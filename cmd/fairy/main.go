// Command fairy is the FairySDK CLI.
//
//	fairy survey https://example.com
//	fairy survey https://example.com --json --save state.json
//	fairy batch targets.txt --out reports/work --jsonl work.jsonl --policy adaptive
//	fairy compare reports/work reports/hotspot --json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/arahe-dev/fairy"
	"github.com/arahe-dev/fairy/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "survey":
		return runSurvey(args[1:])
	case "batch":
		return runBatch(args[1:])
	case "compare":
		return runCompare(args[1:])
	case "version", "--version", "-v":
		fmt.Println("fairy " + version.Version)
		return 0
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "fairy: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `fairy — controlled network experiments

Usage:
  fairy survey <url> [flags]              one target: observe, infer, report
  fairy batch <targets-file> [flags]      many targets: run, save, stream JSONL
  fairy compare <setA> <setB> [flags]     diff two report sets (one per network)
  fairy version

Exit codes:
  0  the command completed (findings and differences are report data, not errors)
  1  a survey or comparison could not complete
  2  usage error

Survey flags (also accepted by batch):
  --json              print the report as JSON, with run metadata
  --policy NAME       fast | adaptive | factorial | taguchi  (default: fast)
  --timeout DUR       whole-survey time budget per target    (default: 10s)
  --max-probes N      maximum number of experiments          (default: 16)
  --concurrency N     maximum concurrent probes in a survey  (default: 4)
  --insecure          skip TLS certificate verification
  --network-label L   label the network being observed (metadata only)
  --resume FILE       resume a saved SurveyState (target comes from the state)
  --save FILE         save the final SurveyState as JSON

Batch flags:
  --out DIR           directory for one report JSON per target (required)
  --jsonl FILE        one JSON object per run ("-" streams to stdout)
  --runs N            runs per target                        (default: 1)
  --jobs N            targets surveyed in parallel           (default: 1)

Compare flags:
  --json              print the comparison as JSON

Targets file format (one per line):
  https://example.com
  api-example https://api.example.com
`)
}

type surveyFlags struct {
	flagSet *flag.FlagSet
	fairyFlags
	jsonOut bool
	resume  string
	save    string
}

func newSurveyFlags() *surveyFlags {
	sf := &surveyFlags{}
	fs := flag.NewFlagSet("fairy survey", flag.ContinueOnError)
	sf.fairyFlags.register(fs)
	fs.BoolVar(&sf.jsonOut, "json", false, "print the report as JSON")
	fs.StringVar(&sf.resume, "resume", "", "resume from a saved SurveyState JSON file")
	fs.StringVar(&sf.save, "save", "", "save the final SurveyState as JSON")
	sf.flagSet = fs
	fs.SetOutput(os.Stderr)
	return sf
}

func runSurvey(args []string) int {
	sf := newSurveyFlags()
	if err := sf.flagSet.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	operands := positionalArgs(args)
	if len(operands) < 1 && sf.resume == "" {
		fmt.Fprintln(os.Stderr, "fairy survey: target URL required (or --resume FILE)")
		return 2
	}
	target := ""
	if len(operands) > 0 {
		target = operands[0]
	}

	f, err := sf.newFairy()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy survey:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	var report *fairy.Report
	if sf.resume != "" {
		raw, rerr := os.ReadFile(sf.resume)
		if rerr != nil {
			fmt.Fprintln(os.Stderr, "fairy: resume:", rerr)
			return 1
		}
		state, lerr := fairy.LoadState(raw)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "fairy:", lerr)
			return 1
		}
		if target != "" {
			fmt.Fprintln(os.Stderr, "fairy: note: target URL ignored; --resume uses the state's target")
		}
		report, err = f.Resume(ctx, state)
	} else {
		report, err = f.Survey(ctx, target)
	}
	wall := time.Since(started)
	if report == nil {
		fmt.Fprintln(os.Stderr, "fairy:", err)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy:", err)
	}
	if target == "" && report.Target.Host != "" {
		target = report.Target.String()
	}

	if sf.save != "" {
		if report.State == nil {
			fmt.Fprintln(os.Stderr, "fairy: report carries no state to save")
			return 1
		}
		raw, serr := fairy.SaveState(*report.State)
		if serr == nil {
			serr = os.WriteFile(sf.save, raw, 0o644)
		}
		if serr != nil {
			fmt.Fprintln(os.Stderr, "fairy: save:", serr)
			return 1
		}
	}

	meta := runMetadata{
		SchemaVersion: schemaVersion,
		FairyVersion:  version.Version,
		RunID:         newRunID(),
		NetworkLabel:  sf.label,
		Slug:          slugFor(target),
		TargetURL:     target,
		RunIndex:      1,
		Policy:        sf.policy,
		WallMS:        wall.Milliseconds(),
	}
	if sf.jsonOut {
		if werr := writeReportJSON(os.Stdout, report, meta); werr != nil {
			fmt.Fprintln(os.Stderr, "fairy:", werr)
			return 1
		}
		return 0
	}
	if werr := fairy.RenderReport(os.Stdout, report); werr != nil {
		fmt.Fprintln(os.Stderr, "fairy:", werr)
		return 1
	}
	return 0
}
