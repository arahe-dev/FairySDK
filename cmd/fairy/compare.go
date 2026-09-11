package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/arahe-dev/fairy"
	"github.com/arahe-dev/fairy/internal/version"
)

// runCompare diffs two sets of reports (directories, files, or JSONL) and
// reports what changed between them: per-observation status/detail
// changes, hosts present in only one set, finding changes, and
// instability within a set when it holds several runs of a host.
func runCompare(args []string) int {
	fs := flag.NewFlagSet("fairy compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "print the comparison as JSON")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	operands := positionalArgs(args)
	if len(operands) != 2 {
		fmt.Fprintln(os.Stderr, "fairy compare: exactly two report sets required (directories, files or .jsonl)")
		return 2
	}
	setA, err := loadReportSet(operands[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy compare:", err)
		return 1
	}
	setB, err := loadReportSet(operands[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy compare:", err)
		return 1
	}

	result := compareSets(setA, setB)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "fairy compare:", err)
			return 1
		}
		return 0
	}
	renderComparison(os.Stdout, result)
	return 0
}

// loadedRun is one report inside a set.
type loadedRun struct {
	Slug         string
	RunIndex     int
	File         string
	Report       *fairy.Report
	FromMetadata bool
}

// stripLabelPrefix removes a leading "<label>-" from a file-derived slug.
func stripLabelPrefix(slug, label string) string {
	if label == "" || label == "." || label == string(filepath.Separator) {
		return slug
	}
	prefix := label + "-"
	if strings.HasPrefix(slug, prefix) && len(slug) > len(prefix) {
		return slug[len(prefix):]
	}
	return slug
}

// reportSet groups runs by slug.
type reportSet struct {
	Name string
	Runs map[string][]loadedRun
}

var runSuffixRe = regexp.MustCompile(`-run(\d+)$`)

// loadReportSet loads a directory of report JSON files, a single report
// file, or a JSONL stream.
func loadReportSet(path string) (*reportSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	set := &reportSet{Name: filepath.Base(filepath.Clean(path)), Runs: map[string][]loadedRun{}}

	add := func(run loadedRun) {
		set.Runs[run.Slug] = append(set.Runs[run.Slug], run)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		var files []string
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".json") {
				continue
			}
			if strings.HasSuffix(name, ".state.json") || strings.HasSuffix(name, ".meta.json") {
				continue
			}
			files = append(files, filepath.Join(path, name))
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: no report JSON files found", path)
		}
		sort.Strings(files)
		// Reports written by `batch --out reports/<label>` are named
		// <slug>.json, so hosts match across networks. Legacy files that
		// embed the label in the name ("<label>-<slug>-run1.json") get the
		// directory label prefix stripped so they match too.
		label := filepath.Base(filepath.Clean(path))
		for _, f := range files {
			run, err := loadReportFile(f)
			if err != nil {
				return nil, err
			}
			if !run.FromMetadata {
				run.Slug = stripLabelPrefix(run.Slug, label)
			}
			add(run)
		}
	} else if strings.HasSuffix(path, ".jsonl") {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 1<<24)
		lineNo := 0
		for sc.Scan() {
			lineNo++
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			run, err := decodeReport([]byte(line), "")
			if err != nil {
				return nil, fmt.Errorf("%s:%d: %w", filepath.Base(path), lineNo, err)
			}
			run.File = fmt.Sprintf("%s:%d", filepath.Base(path), lineNo)
			add(run)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else {
		run, err := loadReportFile(path)
		if err != nil {
			return nil, err
		}
		add(run)
	}

	for slug := range set.Runs {
		runs := set.Runs[slug]
		sort.SliceStable(runs, func(i, j int) bool { return runs[i].RunIndex < runs[j].RunIndex })
		set.Runs[slug] = runs
	}
	return set, nil
}

func loadReportFile(path string) (loadedRun, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return loadedRun{}, err
	}
	run, err := decodeReport(raw, path)
	if err != nil {
		return loadedRun{}, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	run.File = filepath.Base(path)
	return run, nil
}

// decodedReport mirrors both the plain report and the metadata envelope.
type decodedReport struct {
	fairy.Report
	Metadata *runMetadata `json:"run"`
}

// decodeReport parses a report, with or without the metadata envelope.
// When metadata is absent the slug and run index are derived from the
// file name (if given), otherwise from the target host.
func decodeReport(raw []byte, nameHint string) (loadedRun, error) {
	var d decodedReport
	if err := json.Unmarshal(raw, &d); err != nil {
		return loadedRun{}, err
	}
	run := loadedRun{Report: &d.Report, RunIndex: 1, Slug: slugFor(d.Report.Target.String())}
	if nameHint != "" {
		slug, idx := slugFromFile(nameHint)
		if slug != "" {
			run.Slug = slug
		}
		run.RunIndex = idx
	}
	if d.Metadata != nil {
		run.FromMetadata = true
		if d.Metadata.Slug != "" {
			run.Slug = d.Metadata.Slug
		}
		if d.Metadata.RunIndex > 0 {
			run.RunIndex = d.Metadata.RunIndex
		}
	}
	return run, nil
}

// slugFromFile derives a slug from a report file name ("api.github.com-run2.json").
func slugFromFile(name string) (slug string, run int) {
	base := strings.TrimSuffix(filepath.Base(name), ".json")
	run = 1
	if m := runSuffixRe.FindStringSubmatch(base); m != nil {
		if n, err := strconv.Atoi(m[1]); err == nil {
			run = n
		}
		base = base[:len(base)-len(m[0])]
	}
	return base, run
}

// obsKey identifies one probed point: layer plus address family.
type obsKey struct {
	Layer  string `json:"layer"`
	Family string `json:"family,omitempty"`
}

func (k obsKey) String() string {
	if k.Family == "" {
		return k.Layer
	}
	return k.Layer + "/" + k.Family
}

// obsView is the comparable summary of one observation.
type obsView struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// viewOf summarizes an observation for comparison: status plus the facts
// that most often differ between networks.
func viewOf(o fairy.Observation) obsView {
	v := obsView{Status: string(o.Status)}
	switch o.Layer {
	case fairy.LayerDNS:
		if ev, ok := o.FirstEvidenceOf(fairy.KindDNSAnswer); ok {
			v4, _ := evStrings(ev.Values["v4"])
			v6, _ := evStrings(ev.Values["v6"])
			detail := fmt.Sprintf("v4=%d v6=%d", len(v4), len(v6))
			if label, ok := ev.Values["v6_error"].(string); ok && label != "" {
				detail += " v6_error=" + label
			}
			v.Detail = detail
		} else if ev, ok := o.FirstEvidenceOf(fairy.KindDNSError); ok {
			if rcode, ok := ev.Values["rcode"].(string); ok {
				v.Detail = "rcode=" + rcode
			}
		}
	case fairy.LayerTLS, fairy.LayerQUIC:
		if ev, ok := o.FirstEvidenceOf(fairy.KindCertificate); ok {
			if t, ok := ev.Values["type"].(string); ok && t != "" {
				v.Detail = appendDetail(v.Detail, "cert="+t)
			} else if issuer, ok := ev.Values["issuer"].(string); ok && issuer != "" {
				v.Detail = appendDetail(v.Detail, "issuer="+issuer)
			}
		}
		if ev, ok := o.FirstEvidenceOf(fairy.KindTLSAlert); ok {
			if name, ok := ev.Values["name"].(string); ok {
				v.Detail = appendDetail(v.Detail, "alert="+name)
			}
		}
		if ev, ok := o.FirstEvidenceOf(fairy.KindALPNSelected); ok {
			if p, ok := ev.Values["protocol"].(string); ok && p != "" {
				v.Detail = appendDetail(v.Detail, "alpn="+p)
			}
		}
		if ev, ok := o.FirstEvidenceOf(fairy.KindQUICVersion); ok {
			if ver, ok := ev.Values["version"].(string); ok && ver != "" {
				v.Detail = appendDetail(v.Detail, "quic="+ver)
			}
		}
	case fairy.LayerHTTP:
		if ev, ok := o.FirstEvidenceOf(fairy.KindHTTPStatus); ok {
			code := ""
			if n, ok := evInt(ev.Values["status"]); ok {
				code = strconv.Itoa(n)
			}
			proto, _ := ev.Values["proto"].(string)
			v.Detail = strings.TrimSpace("code=" + code + " " + proto)
		}
	}
	if v.Detail == "" && o.Status != fairy.Pass && o.Error != "" {
		v.Detail = o.Error
	}
	return v
}

func appendDetail(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + " " + add
}

// views reduces a run to comparable observations keyed by layer/family.
func views(run loadedRun) map[obsKey]obsView {
	out := map[obsKey]obsView{}
	for _, o := range run.Report.Observations {
		key := obsKey{Layer: string(o.Layer)}
		if o.Experiment.IPFamily == fairy.IPv4 || o.Experiment.IPFamily == fairy.IPv6 {
			key.Family = string(o.Experiment.IPFamily)
		}
		if _, exists := out[key]; !exists {
			out[key] = viewOf(o)
		}
	}
	return out
}

func findingKeys(run loadedRun) map[string]bool {
	out := map[string]bool{}
	for _, f := range run.Report.Findings {
		out[f.Kind+":"+string(f.Confidence)] = true
	}
	return out
}

// comparison is the machine-readable result of `fairy compare`.
type comparison struct {
	SchemaVersion int    `json:"schema_version"`
	FairyVersion  string `json:"fairy_version"`
	Sets          []struct {
		Name  string `json:"name"`
		Slugs int    `json:"slugs"`
		Runs  int    `json:"runs"`
	} `json:"sets"`
	ObservationChanges []observationChange `json:"observation_changes"`
	OnlyInA            []string            `json:"only_in_a"`
	OnlyInB            []string            `json:"only_in_b"`
	FindingChanges     []findingChange     `json:"finding_changes"`
	Unstable           []unstableNote      `json:"unstable_within_set,omitempty"`
}

type observationChange struct {
	Slug string `json:"slug"`
	Key  string `json:"key"`
	Kind string `json:"kind"` // status | detail | added | removed
	A    string `json:"a,omitempty"`
	B    string `json:"b,omitempty"`
	AObs string `json:"a_observation,omitempty"`
	BObs string `json:"b_observation,omitempty"`
}

type findingChange struct {
	Slug    string   `json:"slug"`
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

type unstableNote struct {
	Side     string   `json:"side"`
	Slug     string   `json:"slug"`
	Key      string   `json:"key"`
	Statuses []string `json:"statuses"`
}

// compareSets diffs the first run of each slug in A against the first run
// of the same slug in B.
func compareSets(a, b *reportSet) comparison {
	res := comparison{SchemaVersion: schemaVersion, FairyVersion: version.Version}
	for _, s := range []*reportSet{a, b} {
		runs := 0
		for _, rs := range s.Runs {
			runs += len(rs)
		}
		res.Sets = append(res.Sets, struct {
			Name  string `json:"name"`
			Slugs int    `json:"slugs"`
			Runs  int    `json:"runs"`
		}{Name: s.Name, Slugs: len(s.Runs), Runs: runs})
	}

	slugs := map[string]bool{}
	for slug := range a.Runs {
		slugs[slug] = true
	}
	for slug := range b.Runs {
		slugs[slug] = true
	}
	ordered := make([]string, 0, len(slugs))
	for slug := range slugs {
		ordered = append(ordered, slug)
	}
	sort.Strings(ordered)

	for _, slug := range ordered {
		ra, inA := a.Runs[slug]
		rb, inB := b.Runs[slug]
		if !inB {
			res.OnlyInA = append(res.OnlyInA, slug)
			continue
		}
		if !inA {
			res.OnlyInB = append(res.OnlyInB, slug)
			continue
		}
		va, vb := views(ra[0]), views(rb[0])

		keys := map[obsKey]bool{}
		for k := range va {
			keys[k] = true
		}
		for k := range vb {
			keys[k] = true
		}
		sortedKeys := make([]obsKey, 0, len(keys))
		for k := range keys {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Slice(sortedKeys, func(i, j int) bool { return sortedKeys[i].String() < sortedKeys[j].String() })

		for _, k := range sortedKeys {
			av, aok := va[k]
			bv, bok := vb[k]
			switch {
			case aok && !bok:
				res.ObservationChanges = append(res.ObservationChanges, observationChange{
					Slug: slug, Key: k.String(), Kind: "removed", A: av.Status, AObs: av.Detail,
				})
			case !aok && bok:
				res.ObservationChanges = append(res.ObservationChanges, observationChange{
					Slug: slug, Key: k.String(), Kind: "added", B: bv.Status, BObs: bv.Detail,
				})
			case av.Status != bv.Status:
				res.ObservationChanges = append(res.ObservationChanges, observationChange{
					Slug: slug, Key: k.String(), Kind: "status",
					A: av.Status, B: bv.Status, AObs: av.Detail, BObs: bv.Detail,
				})
			case av.Detail != bv.Detail:
				res.ObservationChanges = append(res.ObservationChanges, observationChange{
					Slug: slug, Key: k.String(), Kind: "detail",
					A: av.Status, B: bv.Status, AObs: av.Detail, BObs: bv.Detail,
				})
			}
		}

		fa, fb := findingKeys(ra[0]), findingKeys(rb[0])
		var added, removed []string
		for k := range fb {
			if !fa[k] {
				added = append(added, k)
			}
		}
		for k := range fa {
			if !fb[k] {
				removed = append(removed, k)
			}
		}
		if len(added) > 0 || len(removed) > 0 {
			sort.Strings(added)
			sort.Strings(removed)
			res.FindingChanges = append(res.FindingChanges, findingChange{Slug: slug, Added: added, Removed: removed})
		}

		res.Unstable = append(res.Unstable, instability("A", slug, ra)...)
		res.Unstable = append(res.Unstable, instability("B", slug, rb)...)
	}
	if res.OnlyInA == nil {
		res.OnlyInA = []string{}
	}
	if res.OnlyInB == nil {
		res.OnlyInB = []string{}
	}
	if res.ObservationChanges == nil {
		res.ObservationChanges = []observationChange{}
	}
	if res.FindingChanges == nil {
		res.FindingChanges = []findingChange{}
	}
	return res
}

// instability reports keys whose status differed between runs of the same
// set — flaky observations that a single run would hide.
func instability(side, slug string, runs []loadedRun) []unstableNote {
	if len(runs) < 2 {
		return nil
	}
	byKey := map[obsKey]map[string]bool{}
	for _, r := range runs {
		for k, v := range views(r) {
			if byKey[k] == nil {
				byKey[k] = map[string]bool{}
			}
			byKey[k][v.Status] = true
		}
	}
	keys := make([]obsKey, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	var out []unstableNote
	for _, k := range keys {
		if len(byKey[k]) < 2 {
			continue
		}
		statuses := make([]string, 0, len(byKey[k]))
		for s := range byKey[k] {
			statuses = append(statuses, s)
		}
		sort.Strings(statuses)
		out = append(out, unstableNote{Side: side, Slug: slug, Key: k.String(), Statuses: statuses})
	}
	return out
}

func renderComparison(w io.Writer, r comparison) {
	fmt.Fprintf(w, "COMPARE  A=%s  B=%s\n", r.Sets[0].Name, r.Sets[1].Name)
	fmt.Fprintf(w, "sets: A %d hosts/%d runs   B %d hosts/%d runs\n\n",
		r.Sets[0].Slugs, r.Sets[0].Runs, r.Sets[1].Slugs, r.Sets[1].Runs)

	if len(r.ObservationChanges) == 0 {
		fmt.Fprintln(w, "no observation differences")
	} else {
		fmt.Fprintln(w, "OBSERVATION CHANGES")
		fmt.Fprintf(w, "%-28s %-12s %-10s %-28s %-28s\n", "HOST", "KEY", "KIND", "A", "B")
		for _, c := range r.ObservationChanges {
			a := strings.TrimSpace(c.A + " " + c.AObs)
			b := strings.TrimSpace(c.B + " " + c.BObs)
			fmt.Fprintf(w, "%-28s %-12s %-10s %-28s %-28s\n", c.Slug, c.Key, c.Kind, truncate(a, 28), truncate(b, 28))
		}
	}

	if len(r.OnlyInA) > 0 {
		fmt.Fprintf(w, "\nONLY IN A: %s\n", strings.Join(r.OnlyInA, ", "))
	}
	if len(r.OnlyInB) > 0 {
		fmt.Fprintf(w, "\nONLY IN B: %s\n", strings.Join(r.OnlyInB, ", "))
	}

	if len(r.FindingChanges) > 0 {
		fmt.Fprintln(w, "\nFINDING CHANGES")
		for _, fc := range r.FindingChanges {
			fmt.Fprintf(w, "  %-28s", fc.Slug)
			if len(fc.Removed) > 0 {
				fmt.Fprintf(w, " -%s", strings.Join(fc.Removed, " -"))
			}
			if len(fc.Added) > 0 {
				fmt.Fprintf(w, " +%s", strings.Join(fc.Added, " +"))
			}
			fmt.Fprintln(w)
		}
	}

	if len(r.Unstable) > 0 {
		fmt.Fprintln(w, "\nUNSTABLE WITHIN A SET (multiple runs disagreed)")
		for _, u := range r.Unstable {
			fmt.Fprintf(w, "  %s %-28s %-12s %s\n", u.Side, u.Slug, u.Key, strings.Join(u.Statuses, ","))
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// evStrings coerces an evidence value into a []string (handling the
// []any that a JSON round-trip produces).
func evStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// evInt coerces an evidence value into an int.
func evInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}
