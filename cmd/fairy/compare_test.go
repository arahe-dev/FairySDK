package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/arahe-dev/fairy"
)

func mkObs(t *testing.T, rawURL string, layer fairy.Layer, family fairy.IPFamily, status fairy.Status, evidence ...fairy.Evidence) fairy.Observation {
	t.Helper()
	tgt, err := fairy.ParseTarget(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	e := fairy.Experiment{Target: tgt, Layer: layer, IPFamily: family}
	switch layer {
	case fairy.LayerTLS, fairy.LayerHTTP:
		e.Transport = fairy.TCP
	case fairy.LayerQUIC:
		e.Transport = fairy.QUIC
	default:
		e.Transport = fairy.TCP
	}
	e.Normalize()
	return fairy.Observation{
		Experiment: e,
		Layer:      layer,
		Status:     status,
		Duration:   5 * time.Millisecond,
		Evidence:   evidence,
		Error:      map[bool]string{true: "synthetic failure", false: ""}[status != fairy.Pass],
	}
}

func mkReport(t *testing.T, rawURL string, obs []fairy.Observation, findings []fairy.Finding) *fairy.Report {
	t.Helper()
	tgt, err := fairy.ParseTarget(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return &fairy.Report{
		Target:       tgt,
		StartedAt:    time.Now(),
		Duration:     time.Second,
		Observations: obs,
		Findings:     findings,
	}
}

// writeSet writes runs into a directory as metadata envelopes.
func writeSet(t *testing.T, dir string, runs map[string][]*fairy.Report) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for slug, reports := range runs {
		for i, rep := range reports {
			meta := runMetadata{
				SchemaVersion: schemaVersion,
				FairyVersion:  "test",
				RunID:         fmt.Sprintf("%s-%d", slug, i+1),
				NetworkLabel:  filepath.Base(dir),
				Slug:          slug,
				TargetURL:     rep.Target.String(),
				RunIndex:      i + 1,
				Policy:        "fast",
			}
			name := slug + ".json"
			if len(reports) > 1 {
				name = fmt.Sprintf("%s-run%d.json", slug, i+1)
			}
			f, err := os.Create(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := writeReportJSON(f, rep, meta); err != nil {
				t.Fatal(err)
			}
			_ = f.Close()
		}
	}
}

func certEvidence(certType string) fairy.Evidence {
	return fairy.Evidence{Kind: fairy.KindCertificate, Values: map[string]any{"type": certType}}
}

func TestCompareDetectsStatusAndFindingChanges(t *testing.T) {
	vercelA := "https://vercel.com"
	githubA := "https://github.com"
	onlyA := "https://only-in-a.example"

	setA := map[string][]*fairy.Report{
		"vercel.com": {mkReport(t, vercelA, []fairy.Observation{
			mkObs(t, vercelA, fairy.LayerDNS, fairy.FamilyAny, fairy.Pass),
			mkObs(t, vercelA, fairy.LayerTCP, fairy.IPv4, fairy.Pass),
			mkObs(t, vercelA, fairy.LayerTLS, fairy.IPv4, fairy.Fail, certEvidence("unknown_authority")),
		}, []fairy.Finding{{Kind: "tls_specific_failure", Confidence: fairy.Confirmed}})},
		"github.com": {mkReport(t, githubA, []fairy.Observation{
			mkObs(t, githubA, fairy.LayerDNS, fairy.FamilyAny, fairy.Pass),
			mkObs(t, githubA, fairy.LayerTCP, fairy.IPv4, fairy.Pass),
		}, []fairy.Finding{{Kind: "path_healthy", Confidence: fairy.Confirmed}})},
		"only-in-a.example": {mkReport(t, onlyA, []fairy.Observation{
			mkObs(t, onlyA, fairy.LayerDNS, fairy.FamilyAny, fairy.Pass),
		}, nil)},
	}
	setB := map[string][]*fairy.Report{
		"vercel.com": {mkReport(t, vercelA, []fairy.Observation{
			mkObs(t, vercelA, fairy.LayerDNS, fairy.FamilyAny, fairy.Pass),
			mkObs(t, vercelA, fairy.LayerTCP, fairy.IPv4, fairy.Pass),
			mkObs(t, vercelA, fairy.LayerTLS, fairy.IPv4, fairy.Pass),
		}, []fairy.Finding{{Kind: "path_healthy", Confidence: fairy.Confirmed}})},
		"github.com": {mkReport(t, githubA, []fairy.Observation{
			mkObs(t, githubA, fairy.LayerDNS, fairy.FamilyAny, fairy.Fail),
		}, []fairy.Finding{{Kind: "dns_failure", Confidence: fairy.Confirmed}})},
		"only-in-b.example": {mkReport(t, "https://only-in-b.example", []fairy.Observation{
			mkObs(t, "https://only-in-b.example", fairy.LayerDNS, fairy.FamilyAny, fairy.Pass),
		}, nil)},
	}

	dirA, dirB := t.TempDir(), t.TempDir()
	writeSet(t, dirA, setA)
	writeSet(t, dirB, setB)

	a, err := loadReportSet(dirA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadReportSet(dirB)
	if err != nil {
		t.Fatal(err)
	}
	res := compareSets(a, b)

	if len(res.OnlyInA) != 1 || res.OnlyInA[0] != "only-in-a.example" {
		t.Errorf("only_in_a = %v", res.OnlyInA)
	}
	if len(res.OnlyInB) != 1 || res.OnlyInB[0] != "only-in-b.example" {
		t.Errorf("only_in_b = %v", res.OnlyInB)
	}

	var tlsChange, dnsChange *observationChange
	for i := range res.ObservationChanges {
		c := &res.ObservationChanges[i]
		if c.Slug == "vercel.com" && c.Key == "tls/ipv4" {
			tlsChange = c
		}
		if c.Slug == "github.com" && c.Key == "dns" {
			dnsChange = c
		}
	}
	if tlsChange == nil || tlsChange.Kind != "status" || tlsChange.A != "fail" || tlsChange.B != "pass" {
		t.Fatalf("tls change = %+v", tlsChange)
	}
	if tlsChange.AObs != "cert=unknown_authority" {
		t.Errorf("tls detail lost: %q", tlsChange.AObs)
	}
	if dnsChange == nil || dnsChange.A != "pass" || dnsChange.B != "fail" {
		t.Fatalf("dns change = %+v", dnsChange)
	}

	if len(res.FindingChanges) != 2 {
		t.Fatalf("want finding changes for both slugs, got %+v", res.FindingChanges)
	}
	for _, fc := range res.FindingChanges {
		switch fc.Slug {
		case "vercel.com":
			if len(fc.Removed) != 1 || fc.Removed[0] != "tls_specific_failure:confirmed" {
				t.Errorf("vercel removed findings = %v", fc.Removed)
			}
			if len(fc.Added) != 1 || fc.Added[0] != "path_healthy:confirmed" {
				t.Errorf("vercel added findings = %v", fc.Added)
			}
		case "github.com":
			if len(fc.Added) != 1 || fc.Added[0] != "dns_failure:confirmed" {
				t.Errorf("github added findings = %v", fc.Added)
			}
		}
	}
}

func TestCompareFlagsInstabilityWithinSet(t *testing.T) {
	url := "https://flaky.example"
	dirA := t.TempDir()
	writeSet(t, dirA, map[string][]*fairy.Report{
		"flaky.example": {
			mkReport(t, url, []fairy.Observation{
				mkObs(t, url, fairy.LayerQUIC, fairy.IPv4, fairy.Timeout),
			}, nil),
			mkReport(t, url, []fairy.Observation{
				mkObs(t, url, fairy.LayerQUIC, fairy.IPv4, fairy.Pass),
			}, nil),
		},
	})
	// B holds a single run, so only side A can be flagged as unstable.
	dirB := t.TempDir()
	writeSet(t, dirB, map[string][]*fairy.Report{
		"flaky.example": {mkReport(t, url, []fairy.Observation{
			mkObs(t, url, fairy.LayerQUIC, fairy.IPv4, fairy.Pass),
		}, nil)},
	})
	a, err := loadReportSet(dirA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadReportSet(dirB)
	if err != nil {
		t.Fatal(err)
	}
	res := compareSets(a, b)
	if len(res.Unstable) != 1 {
		t.Fatalf("want one instability note, got %+v", res.Unstable)
	}
	if res.Unstable[0].Side != "A" || res.Unstable[0].Key != "quic/ipv4" || len(res.Unstable[0].Statuses) != 2 {
		t.Fatalf("unexpected note: %+v", res.Unstable[0])
	}
}

func TestCompareJSONOutputShape(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	url := "https://shape.example"
	writeSet(t, dirA, map[string][]*fairy.Report{
		"shape.example": {mkReport(t, url, []fairy.Observation{mkObs(t, url, fairy.LayerDNS, fairy.FamilyAny, fairy.Pass)}, nil)},
	})
	writeSet(t, dirB, map[string][]*fairy.Report{
		"shape.example": {mkReport(t, url, []fairy.Observation{mkObs(t, url, fairy.LayerDNS, fairy.FamilyAny, fairy.Fail)}, nil)},
	})

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := run([]string{"compare", dirA, dirB, "--json"})
	_ = w.Close()
	os.Stdout = old
	if code != 0 {
		t.Fatalf("compare exit = %d", code)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{`"schema_version": 1`, `"fairy_version"`, `"observation_changes"`, `"dns"`, `"fail"`} {
		if !contains(out, want) {
			t.Errorf("JSON output missing %q\n%s", want, out)
		}
	}
}

func TestCompareJSONLInput(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	url := "https://jsonl.example"
	writeSet(t, dirA, map[string][]*fairy.Report{
		"jsonl.example": {mkReport(t, url, []fairy.Observation{mkObs(t, url, fairy.LayerTCP, fairy.IPv4, fairy.Pass)}, nil)},
	})
	writeSet(t, dirB, map[string][]*fairy.Report{
		"jsonl.example": {mkReport(t, url, []fairy.Observation{mkObs(t, url, fairy.LayerTCP, fairy.IPv4, fairy.Fail)}, nil)},
	})

	// Re-serialize set B into a JSONL stream: one compact JSON object per
	// line, exactly as `fairy batch --jsonl` writes it.
	bSet, err := loadReportSet(dirB)
	if err != nil {
		t.Fatal(err)
	}
	var lines []byte
	for _, runs := range bSet.Runs {
		for _, run := range runs {
			line, merr := json.Marshal(reportEnvelope{Report: run.Report, Metadata: runMetadata{
				SchemaVersion: schemaVersion,
				FairyVersion:  "test",
				RunID:         "jsonl-run",
				Slug:          run.Slug,
				RunIndex:      run.RunIndex,
			}})
			if merr != nil {
				t.Fatal(merr)
			}
			lines = append(lines, line...)
			lines = append(lines, '\n')
		}
	}
	jsonlPath := filepath.Join(t.TempDir(), "set-b.jsonl")
	if err := os.WriteFile(jsonlPath, lines, 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := loadReportSet(dirA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadReportSet(jsonlPath)
	if err != nil {
		t.Fatal(err)
	}
	res := compareSets(a, b)
	if len(res.ObservationChanges) != 1 || res.ObservationChanges[0].Kind != "status" {
		t.Fatalf("jsonl comparison failed: %+v", res.ObservationChanges)
	}
}

func dirSet(t *testing.T, dir string) map[string]bool {
	t.Helper()
	set, err := loadReportSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for slug := range set.Runs {
		out[slug] = true
	}
	return out
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
