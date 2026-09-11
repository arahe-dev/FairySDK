package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/arahe-dev/fairy"
	"github.com/arahe-dev/fairy/internal/version"
)

// schemaVersion is the version of the machine-readable output shape.
// It changes only when existing fields change meaning or disappear.
const schemaVersion = 1

// runMetadata is attached to every machine-readable report so that runs
// can be attributed and compared without external bookkeeping.
type runMetadata struct {
	SchemaVersion int    `json:"schema_version"`
	FairyVersion  string `json:"fairy_version"`
	RunID         string `json:"run_id"`
	NetworkLabel  string `json:"network_label,omitempty"`
	Slug          string `json:"slug,omitempty"`
	TargetURL     string `json:"target_url"`
	RunIndex      int    `json:"run_index,omitempty"`
	Policy        string `json:"policy"`
	WallMS        int64  `json:"wall_ms"`
}

// reportEnvelope flattens a report and its metadata into one JSON object:
// report fields stay at the top level (target, observations, findings) so
// existing consumers keep working, and metadata is additive.
type reportEnvelope struct {
	*fairy.Report
	Metadata runMetadata `json:"run"`
}

func newRunID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// writeReportJSON writes the envelope for a report.
func writeReportJSON(w io.Writer, report *fairy.Report, meta runMetadata) error {
	meta.SchemaVersion = schemaVersion
	meta.FairyVersion = version.Version
	if meta.RunID == "" {
		meta.RunID = newRunID()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reportEnvelope{Report: report, Metadata: meta})
}

// targetSpec is one entry of a targets file.
type targetSpec struct {
	Slug string
	URL  string
}

// parseTargets reads a targets file: one target per line, as either
// "<url>" or "<slug> <url>". Blank lines and #-comments are ignored.
func parseTargets(r io.Reader) ([]targetSpec, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var out []targetSpec
	seen := map[string]bool{}
	seenURL := map[string]bool{}
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		var slug, target string
		switch len(fields) {
		case 1:
			target = fields[0]
			slug = slugFor(target)
		case 2:
			slug, target = fields[0], fields[1]
		default:
			return nil, fmt.Errorf("line %d: want \"<url>\" or \"<slug> <url>\", got %d fields", i+1, len(fields))
		}
		if _, err := fairy.ParseTarget(target); err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if seen[slug] {
			return nil, fmt.Errorf("line %d: duplicate slug %q", i+1, slug)
		}
		if seenURL[target] {
			return nil, fmt.Errorf("line %d: duplicate target %q (use --runs to repeat a survey)", i+1, target)
		}
		seen[slug] = true
		seenURL[target] = true
		out = append(out, targetSpec{Slug: slug, URL: target})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no targets found")
	}
	return out, nil
}

// slugFor derives a deterministic, filesystem-safe slug from a target
// URL: the host, plus a short path hash when the URL has a path or query
// (so github.com and github.com/a/b differ).
func slugFor(rawURL string) string {
	t, err := fairy.ParseTarget(rawURL)
	host := strings.ToLower(t.Host)
	if err != nil || host == "" {
		host = "target"
	}
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	suffix := ""
	if t.URL != nil {
		extra := t.URL.Path
		if t.URL.RawQuery != "" {
			extra += "?" + t.URL.RawQuery
		}
		if strings.Trim(extra, "/") != "" {
			sum := sha1.Sum([]byte(extra))
			suffix = "-" + hex.EncodeToString(sum[:])[:8]
		}
	}
	if slug == "" {
		slug = "target"
	}
	return slug + suffix
}

// writeTargetsFile is a test/debug helper: serialize specs back out.
func formatTargets(specs []targetSpec) string {
	sorted := append([]targetSpec(nil), specs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Slug < sorted[j].Slug })
	var b strings.Builder
	for _, s := range sorted {
		fmt.Fprintf(&b, "%s %s\n", s.Slug, s.URL)
	}
	return b.String()
}

func writeFileJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
