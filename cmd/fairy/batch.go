package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/arahe-dev/fairy"
	"github.com/arahe-dev/fairy/internal/version"
)

// runBatch surveys every target in a targets file, saving one report per
// run and optionally one JSON object per run (JSONL) for machine
// consumption. Concurrency, deterministic file names, run metadata and
// error accounting live here so callers do not need shell loops.
func runBatch(args []string) int {
	fs := flag.NewFlagSet("fairy batch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var ff fairyFlags
	ff.register(fs)
	outDir := fs.String("out", "", "directory to write report JSON (required)")
	jsonl := fs.String("jsonl", "", "write one JSON object per run to this file (\"-\" for stdout)")
	runs := fs.Int("runs", 1, "runs per target (with --runs 1 the file is <slug>.json)")
	jobs := fs.Int("jobs", 1, "targets surveyed in parallel (default 1 keeps UDP/QUIC evidence clean)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	targets := positionalArgs(args)
	if len(targets) < 1 {
		fmt.Fprintln(os.Stderr, "fairy batch: targets file required")
		return 2
	}
	if *outDir == "" {
		fmt.Fprintln(os.Stderr, "fairy batch: --out DIR is required")
		return 2
	}
	if *runs < 1 || *jobs < 1 {
		fmt.Fprintln(os.Stderr, "fairy batch: --runs and --jobs must be >= 1")
		return 2
	}

	targetsFile, err := os.Open(targets[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy batch:", err)
		return 1
	}
	specs, err := parseTargets(targetsFile)
	_ = targetsFile.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy batch:", err)
		return 2
	}

	f, err := ff.newFairy()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy batch:", err)
		return 2
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "fairy batch:", err)
		return 1
	}

	// JSONL stream: "-" means stdout, in which case progress goes to stderr.
	jsonlToStdout := *jsonl == "-"
	var jsonlFile *os.File
	if *jsonl != "" && !jsonlToStdout {
		if jsonlFile, err = os.Create(*jsonl); err != nil {
			fmt.Fprintln(os.Stderr, "fairy batch:", err)
			return 1
		}
		defer jsonlFile.Close()
	}
	var jsonlMu sync.Mutex
	writeJSONL := func(line []byte) {
		jsonlMu.Lock()
		defer jsonlMu.Unlock()
		switch {
		case jsonlToStdout:
			_, _ = os.Stdout.Write(line)
		case jsonlFile != nil:
			_, _ = jsonlFile.Write(line)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	type job struct {
		spec targetSpec
		run  int
	}
	var queue []job
	for _, s := range specs {
		for i := 1; i <= *runs; i++ {
			queue = append(queue, job{spec: s, run: i})
		}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		okCount  int
		failures []string
	)
	sem := make(chan struct{}, *jobs)
	for _, j := range queue {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer wg.Done()
			defer func() { <-sem }()

			meta := runMetadata{
				SchemaVersion: schemaVersion,
				FairyVersion:  version.Version,
				RunID:         newRunID(),
				NetworkLabel:  ff.label,
				Slug:          j.spec.Slug,
				TargetURL:     j.spec.URL,
				RunIndex:      j.run,
				Policy:        ff.policy,
			}
			started := time.Now()
			report, surveyErr := f.Survey(ctx, j.spec.URL)
			meta.WallMS = time.Since(started).Milliseconds()

			if report == nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s run%d: %v", j.spec.Slug, j.run, surveyErr))
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "FAIL %-18s run%d  %v\n", j.spec.Slug, j.run, surveyErr)
				line, _ := json.Marshal(runFailure{Metadata: meta, Error: surveyErr.Error()})
				writeJSONL(append(line, '\n'))
				return
			}

			name := j.spec.Slug + ".json"
			if *runs > 1 {
				name = fmt.Sprintf("%s-run%d.json", j.spec.Slug, j.run)
			}
			reportPath := filepath.Join(*outDir, name)
			statePath := filepath.Join(*outDir, fmt.Sprintf("%s-run%d.state.json", j.spec.Slug, j.run))

			out, cerr := os.Create(reportPath)
			if cerr == nil {
				cerr = writeReportJSON(out, report, meta)
				cerr = orErr(cerr, out.Close())
			}
			if cerr != nil {
				mu.Lock()
				failures = append(failures, fmt.Sprintf("%s run%d: write report: %v", j.spec.Slug, j.run, cerr))
				mu.Unlock()
				return
			}
			if report.State != nil {
				if raw, serr := fairy.SaveState(*report.State); serr == nil {
					_ = os.WriteFile(statePath, raw, 0o644)
				}
			}
			if line, merr := json.Marshal(reportEnvelope{Report: report, Metadata: meta}); merr == nil {
				writeJSONL(append(line, '\n'))
			}

			mu.Lock()
			okCount++
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "ok   %-18s run%d  %dms  %d observations\n",
				j.spec.Slug, j.run, meta.WallMS, len(report.Observations))
		}(j)
	}
	wg.Wait()

	if !jsonlToStdout {
		fmt.Printf("batch complete: %d targets, %d runs, %d ok, %d failed\n", len(specs), len(queue), okCount, len(failures))
		fmt.Printf("reports: %s\n", *outDir)
		if *jsonl != "" {
			fmt.Printf("jsonl: %s\n", *jsonl)
		}
		for _, fl := range failures {
			fmt.Fprintln(os.Stderr, "failed:", fl)
		}
	}
	if len(failures) > 0 {
		return 1
	}
	return 0
}

// runFailure is the JSONL record written when a survey could not run.
type runFailure struct {
	Metadata runMetadata `json:"run"`
	Error    string      `json:"error"`
}

// orErr returns the first non-nil error.
func orErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
