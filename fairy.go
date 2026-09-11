// Package fairy runs controlled network experiments against a target and
// explains where a path fails.
//
// The basic API is one function:
//
//	report, err := fairy.Survey(ctx, "https://example.com")
//
// The advanced form tunes the survey:
//
//	f, err := fairy.New(fairy.Config{
//	    Policy:    fairy.Adaptive,
//	    MaxProbes: 16,
//	    Timeout:   8 * time.Second,
//	})
//	report, err := f.Survey(ctx, "https://example.com")
//
// Fairy produces structured Reports. It knows nothing about VPN routing
// and has no reverse dependency on its consumers.
package fairy

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/arahe-dev/fairy/internal"
	"github.com/arahe-dev/fairy/policy"
)

// Config configures a Fairy instance. Zero values select the defaults:
// the Fast policy, 16 probes, a 10s whole-survey budget and a concurrency
// limit of 4.
type Config struct {
	// Policy selects the experiment-selection policy. Nil means Fast.
	Policy Policy

	// MaxProbes caps the number of experiments per survey.
	MaxProbes int

	// Timeout is the whole-survey time budget.
	Timeout time.Duration

	// MaxConcurrent caps concurrent independent experiments.
	MaxConcurrent int

	// TLSRootCAs overrides the trusted root pool for TLS probes
	// (private CA or test setups).
	TLSRootCAs *x509.CertPool

	// TLSInsecureSkipVerify disables TLS certificate verification for
	// all probes. Diagnostic use only.
	TLSInsecureSkipVerify bool
}

// Fairy runs surveys under a fixed configuration.
type Fairy struct {
	cfg Config
}

// New validates cfg and returns a Fairy. A nil Policy becomes Fast.
func New(cfg Config) (*Fairy, error) {
	if cfg.MaxProbes < 0 {
		return nil, errors.New("fairy: MaxProbes must not be negative")
	}
	if cfg.MaxConcurrent < 0 {
		return nil, errors.New("fairy: MaxConcurrent must not be negative")
	}
	if cfg.Timeout < 0 {
		return nil, errors.New("fairy: Timeout must not be negative")
	}
	if cfg.Policy == nil {
		cfg.Policy = Fast
	}
	return &Fairy{cfg: cfg}, nil
}

// Survey runs a full survey against rawURL and returns the report.
func (f *Fairy) Survey(ctx context.Context, rawURL string) (*Report, error) {
	tgt, err := ParseTarget(rawURL)
	if err != nil {
		return nil, err
	}
	return f.run(ctx, NewSurveyState(tgt))
}

// Resume continues a survey from a persisted SurveyState. Completed
// experiments are immutable and never rerun; the returned Report carries
// the updated state in Report.State for further persistence.
func (f *Fairy) Resume(ctx context.Context, state SurveyState) (*Report, error) {
	if state.Target == nil {
		return nil, errors.New("fairy: resume: survey state has no target")
	}
	st := state // run against a private copy
	return f.run(ctx, &st)
}

func (f *Fairy) run(ctx context.Context, state *SurveyState) (*Report, error) {
	return internal.RunSurvey(ctx, internal.Options{
		MaxProbes:          f.cfg.MaxProbes,
		MaxConcurrent:      f.cfg.MaxConcurrent,
		Timeout:            f.cfg.Timeout,
		RootCAs:            f.cfg.TLSRootCAs,
		InsecureSkipVerify: f.cfg.TLSInsecureSkipVerify,
	}, f.cfg.Policy, state)
}

// Survey runs a survey with default configuration.
func Survey(ctx context.Context, rawURL string) (*Report, error) {
	f, err := New(Config{})
	if err != nil {
		return nil, err
	}
	return f.Survey(ctx, rawURL)
}

// Policy is the experiment-selection policy interface. Policies are pure:
// the same config plus the same SurveyState must propose the same
// experiments. The built-in policies are Fast, Adaptive, Factorial and
// Taguchi; custom policies can implement this interface with only the
// root package imported.
type Policy = policy.Policy

// Built-in policies. They are stateless and safe to share.
var (
	Fast      = policy.NewFast()
	Adaptive  = policy.NewAdaptive()
	Factorial = policy.NewFactorial(policy.FactorialOptions{})
	Taguchi   = policy.NewTaguchi(policy.TaguchiOptions{})
)

// Probe is the internal probe contract: one probe, one layer. Users do
// not register probes in V0; the runner selects the right probe from the
// Experiment fields.
type Probe interface {
	Run(context.Context, Experiment) Observation
}
