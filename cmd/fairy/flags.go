package main

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/arahe-dev/fairy"
)

// noValueFlags are flags that take no value; used when splitting flags
// from positional arguments so that flags work before or after them.
var noValueFlags = map[string]bool{
	"json":     true,
	"insecure": true,
	"h":        true,
	"help":     true,
}

// reorderFlags returns just the flag arguments from a command line.
func reorderFlags(args []string) []string {
	flags, _ := splitArgs(args, noValueFlags)
	return flags
}

// positionalArgs returns just the positional arguments from a command line.
func positionalArgs(args []string) []string {
	_, positional := splitArgs(args, noValueFlags)
	return positional
}

// splitArgs separates flag tokens (including their values) from positional
// arguments so flags work before and after positionals.
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

// fairyFlags are the survey-configuration flags shared by `survey` and
// `batch`, so both commands always agree on policy, budgets and TLS
// handling.
type fairyFlags struct {
	policy      string
	timeout     time.Duration
	maxProbes   int
	concurrency int
	insecure    bool
	label       string
}

func (f *fairyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.policy, "policy", "fast", "fast | adaptive | factorial | taguchi")
	fs.DurationVar(&f.timeout, "timeout", 10*time.Second, "whole-survey time budget per target")
	fs.IntVar(&f.maxProbes, "max-probes", 16, "maximum number of experiments per survey")
	fs.IntVar(&f.concurrency, "concurrency", 4, "maximum concurrent probes within one survey")
	fs.BoolVar(&f.insecure, "insecure", false, "skip TLS certificate verification")
	fs.StringVar(&f.label, "network-label", "", "label for the network this run observes (recorded in run metadata)")
}

// newFairy builds the SDK instance described by the flags.
func (f *fairyFlags) newFairy() (*fairy.Fairy, error) {
	pol, err := policyByName(f.policy)
	if err != nil {
		return nil, err
	}
	return fairy.New(fairy.Config{
		Policy:                pol,
		MaxProbes:             f.maxProbes,
		Timeout:               f.timeout,
		MaxConcurrent:         f.concurrency,
		TLSInsecureSkipVerify: f.insecure,
	})
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
