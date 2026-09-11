// Command fairy is the FairySDK CLI.
//
//	fairy survey https://example.com
//	fairy survey https://example.com --json
//	fairy survey https://example.com --policy adaptive --save state.json
//	fairy survey --resume state.json --save state.json
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arahe-dev/fairy"
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
	case "version", "--version", "-v":
		fmt.Println("fairy 0.1.0")
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
  fairy survey <url> [flags]
  fairy version

Exit codes:
  0  survey completed (findings are report data, not errors)
  1  survey could not complete
  2  usage error

Survey flags:
  --json              print the report as JSON
  --policy NAME       fast | adaptive | factorial | taguchi  (default: fast)
  --timeout DUR       whole-survey time budget              (default: 10s)
  --max-probes N      maximum number of experiments         (default: 16)
  --concurrency N     maximum concurrent probes             (default: 4)
  --insecure          skip TLS certificate verification
  --resume FILE       resume a saved SurveyState (target comes from the state)
  --save FILE         save the final SurveyState as JSON
`)
}

func runSurvey(args []string) int {
	fs := newSurveyFlags()
	// Go's flag package stops parsing at the first positional argument,
	// but users naturally write `fairy survey URL --json`. Split flags
	// from positionals so flags are accepted in any position.
	flagArgs, positional := splitArgs(args, boolFlags)
	if err := fs.flagSet.Parse(flagArgs); err != nil {
		return 2
	}
	if len(positional) < 1 && fs.resume == "" {
		fmt.Fprintln(os.Stderr, "fairy survey: target URL required (or --resume FILE)")
		return 2
	}
	target := ""
	if len(positional) > 0 {
		target = positional[0]
	}
	pol, err := policyByName(fs.policy)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy survey:", err)
		return 2
	}

	f, err := fairy.New(fairy.Config{
		Policy:                pol,
		MaxProbes:             fs.maxProbes,
		Timeout:               fs.timeout,
		MaxConcurrent:         fs.concurrency,
		TLSInsecureSkipVerify: fs.insecure,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "fairy:", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var report *fairy.Report
	if fs.resume != "" {
		raw, err := os.ReadFile(fs.resume)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fairy: resume:", err)
			return 1
		}
		state, err := fairy.LoadState(raw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
			return 1
		}
		if target != "" {
			fmt.Fprintln(os.Stderr, "fairy: note: target URL ignored; --resume uses the state's target")
		}
		report, err = f.Resume(ctx, state)
		if report == nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
			return 1
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
		}
	} else {
		var err error
		report, err = f.Survey(ctx, target)
		if report == nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
			return 1
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
		}
	}

	if fs.save != "" {
		if report.State == nil {
			fmt.Fprintln(os.Stderr, "fairy: report carries no state to save")
			return 1
		}
		raw, err := fairy.SaveState(*report.State)
		if err == nil {
			err = os.WriteFile(fs.save, raw, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "fairy: save:", err)
			return 1
		}
	}

	if fs.json {
		if err := fairy.RenderReportJSON(os.Stdout, report); err != nil {
			fmt.Fprintln(os.Stderr, "fairy:", err)
			return 1
		}
	} else if err := fairy.RenderReport(os.Stdout, report); err != nil {
		fmt.Fprintln(os.Stderr, "fairy:", err)
		return 1
	}
	return 0
}

// boolFlags are survey flags that take no value.
var boolFlags = map[string]bool{"json": true, "insecure": true, "h": true, "help": true}

// splitArgs separates flag tokens (including their values) from
// positional arguments so flags work before and after positionals.
func splitArgs(args []string, noValue map[string]bool) (flagArgs, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		if strings.Contains(a, "=") {
			flagArgs = append(flagArgs, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		flagArgs = append(flagArgs, a)
		if !noValue[name] && i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return flagArgs, positional
}

type surveyFlags struct {
	flagSet     *flag.FlagSet
	json        bool
	policy      string
	timeout     time.Duration
	maxProbes   int
	concurrency int
	insecure    bool
	resume      string
	save        string
}

// policyByName maps a CLI policy name onto the built-in policy.
func policyByName(name string) (fairy.Policy, error) {
	switch name {
	case "fast":
		return fairy.Fast, nil
	case "adaptive":
		return fairy.Adaptive, nil
	case "factorial":
		return fairy.Factorial, nil
	case "taguchi":
		return fairy.Taguchi, nil
	default:
		return nil, fmt.Errorf("unknown policy %q (want fast, adaptive, factorial or taguchi)", name)
	}
}

func newSurveyFlags() *surveyFlags {
	sf := &surveyFlags{}
	fs := flag.NewFlagSet("fairy survey", flag.ContinueOnError)
	fs.BoolVar(&sf.json, "json", false, "print the report as JSON")
	fs.StringVar(&sf.policy, "policy", "fast", "fast | adaptive | factorial | taguchi")
	fs.DurationVar(&sf.timeout, "timeout", 10*time.Second, "whole-survey time budget")
	fs.IntVar(&sf.maxProbes, "max-probes", 16, "maximum number of experiments")
	fs.IntVar(&sf.concurrency, "concurrency", 4, "maximum concurrent probes")
	fs.BoolVar(&sf.insecure, "insecure", false, "skip TLS certificate verification")
	fs.StringVar(&sf.resume, "resume", "", "resume from a saved SurveyState JSON file")
	fs.StringVar(&sf.save, "save", "", "save the final SurveyState as JSON")
	sf.flagSet = fs
	fs.SetOutput(os.Stderr)
	return sf
}
