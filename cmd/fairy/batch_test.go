package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	content := `
# comment line, ignored

https://example.com
gh-api	https://api.github.com
gh-refs https://github.com/arahe-dev/fairy.git/info/refs?service=git-upload-pack
`
	specs, err := parseTargets(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 3 {
		t.Fatalf("want 3 specs, got %d: %+v", len(specs), specs)
	}
	if specs[0].Slug != "example.com" || specs[0].URL != "https://example.com" {
		t.Fatalf("plain URL slug = %q", specs[0].Slug)
	}
	if specs[1].Slug != "gh-api" {
		t.Fatalf("explicit slug = %q", specs[1].Slug)
	}
	if !strings.Contains(specs[2].URL, "git-upload-pack") {
		t.Fatalf("query string lost: %q", specs[2].URL)
	}

	for _, bad := range []string{
		"not-a-url",
		"a https://example.com\nb https://example.com",
		"https://example.com\nhttps://example.com", // duplicate derived slug
		"a https://example.com\na https://other.example",
		"",
	} {
		if _, err := parseTargets(strings.NewReader(bad)); err == nil {
			t.Errorf("parseTargets(%q) should fail", bad)
		}
	}
}

func TestSlugFor(t *testing.T) {
	cases := map[string]string{
		"https://github.com":       "github.com",
		"https://Example.COM:443/": "example.com",
	}
	for in, want := range cases {
		if got := slugFor(in); got != want {
			t.Errorf("slugFor(%q) = %q, want %q", in, got, want)
		}
	}
	// Paths and queries must produce distinct, stable slugs.
	a := slugFor("https://github.com/arahe-dev/fairy.git/info/refs?service=git-upload-pack")
	b := slugFor("https://github.com/arahe-dev/fairy.git/info/refs?service=git-upload-pack")
	c := slugFor("https://github.com")
	if a != b {
		t.Fatalf("slug not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("distinct paths collided: %q", a)
	}
	if !strings.HasPrefix(a, "github.com-") {
		t.Fatalf("unexpected slug %q", a)
	}
}

func TestBatchWritesReportsAndJSONL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	targets := filepath.Join(dir, "targets.txt")
	body := "local-one " + srv.URL + "/one\nlocal-two " + srv.URL + "/two\n"
	if err := os.WriteFile(targets, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "out")
	jsonl := filepath.Join(dir, "runs.jsonl")

	code := run([]string{
		"batch", targets,
		"--out", outDir,
		"--jsonl", jsonl,
		"--policy", "fast",
		"--max-probes", "2",
		"--timeout", "8s",
		"--runs", "2",
		"--network-label", "unit-test",
	})
	if code != 0 {
		t.Fatalf("batch exit = %d, want 0", code)
	}

	for _, want := range []string{
		"local-one-run1.json", "local-one-run2.json",
		"local-two-run1.json", "local-two-run2.json",
		"local-one-run1.state.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, want)); err != nil {
			t.Errorf("missing output %s: %v", want, err)
		}
	}

	raw, err := os.ReadFile(jsonl)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 JSONL lines, got %d", len(lines))
	}
	for _, line := range lines {
		var env struct {
			SchemaVersion int    `json:"schema_version"`
			RunID         string `json:"run_id"`
			NetworkLabel  string `json:"network_label"`
			Slug          string `json:"slug"`
			Run           struct {
				SchemaVersion int    `json:"schema_version"`
				FairyVersion  string `json:"fairy_version"`
				RunID         string `json:"run_id"`
				NetworkLabel  string `json:"network_label"`
			} `json:"run"`
			Observations []json.RawMessage `json:"observations"`
			Target       struct {
				Host string `json:"host"`
			} `json:"target"`
		}
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("JSONL line is not JSON: %v", err)
		}
		if env.Run.SchemaVersion != schemaVersion || env.Run.FairyVersion == "" || env.Run.RunID == "" {
			t.Errorf("run metadata incomplete: %+v", env.Run)
		}
		if env.Run.NetworkLabel != "unit-test" {
			t.Errorf("network_label = %q", env.Run.NetworkLabel)
		}
		if env.Target.Host == "" || len(env.Observations) == 0 {
			t.Errorf("report payload missing: %+v", env)
		}
	}
}

func TestBatchUsageErrors(t *testing.T) {
	if code := run([]string{"batch"}); code != 2 {
		t.Errorf("missing targets file: exit = %d, want 2", code)
	}
	dir := t.TempDir()
	targets := filepath.Join(dir, "t.txt")
	_ = os.WriteFile(targets, []byte("https://example.com\n"), 0o644)
	if code := run([]string{"batch", targets}); code != 2 {
		t.Errorf("missing --out: exit = %d, want 2", code)
	}
	if code := run([]string{"batch", filepath.Join(dir, "nope.txt"), "--out", filepath.Join(dir, "o")}); code != 1 {
		t.Errorf("missing targets file: exit = %d, want 1", code)
	}
}
