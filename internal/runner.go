// Package internal implements the FairySDK survey runner: it drives a
// policy round by round, dispatches experiments to the right probe,
// enforces time budgets and concurrency limits, and never reruns a
// completed experiment.
package internal

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/arahe-dev/fairy/infer"
	"github.com/arahe-dev/fairy/internal/model"
	"github.com/arahe-dev/fairy/policy"
	"github.com/arahe-dev/fairy/probe"
)

// Defaults for the survey runner.
const (
	DefaultMaxProbes     = 16
	DefaultMaxConcurrent = 4
	DefaultTimeout       = 10 * time.Second
	// MaxRounds bounds the propose/execute loop even if a policy keeps
	// proposing new (unrecorded) experiments.
	MaxRounds = 64
)

// Options configure one survey run.
type Options struct {
	MaxProbes          int
	MaxConcurrent      int
	Timeout            time.Duration
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
}

func (o *Options) fill() {
	if o.MaxProbes <= 0 {
		o.MaxProbes = DefaultMaxProbes
	}
	if o.MaxConcurrent <= 0 {
		o.MaxConcurrent = DefaultMaxConcurrent
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
}

// RunSurvey executes a survey to completion against state (mutating it),
// and returns the report. The whole survey is bounded by opts.Timeout;
// each experiment additionally by its layer budget. If the parent
// context is canceled, the partial report is returned together with the
// context error.
func RunSurvey(ctx context.Context, opts Options, pol policy.Policy, state *model.SurveyState) (*model.Report, error) {
	if state == nil {
		return nil, errors.New("fairy: nil survey state")
	}
	if _, ok := state.TargetOf(); !ok {
		return nil, errors.New("fairy: survey state has no target")
	}
	if pol == nil {
		pol = policy.NewFast()
	}
	opts.fill()
	if state.StartedAt.IsZero() {
		state.StartedAt = time.Now()
	}
	startedAt := state.StartedAt

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	probes := newProbeSet(opts)
	budget := opts.MaxProbes - len(state.Observations)
	if budget < 0 {
		budget = 0
	}

	for round := 0; round < MaxRounds; round++ {
		if err := runCtx.Err(); err != nil {
			break
		}
		if budget <= 0 {
			break
		}
		if pol.Done(*state) {
			break
		}
		proposed, err := pol.Propose(runCtx, *state, budget)
		if err != nil {
			return nil, fmt.Errorf("fairy: policy propose: %w", err)
		}
		proposed = dedupe(state, proposed, budget)
		if len(proposed) == 0 {
			break // nothing new to learn; avoid spinning
		}
		observations := runBatch(runCtx, probes, proposed, opts.MaxConcurrent)
		state.Rounds = append(state.Rounds, model.Round{Index: state.Round, Proposed: append([]model.Experiment(nil), proposed...)})
		for _, o := range observations {
			if err := state.AddObservation(o); err != nil {
				return nil, err
			}
		}
		state.Round++
		budget -= len(proposed)
	}

	report := &model.Report{
		Target:       *state.Target,
		StartedAt:    startedAt,
		Duration:     time.Since(startedAt),
		Observations: append([]model.Observation(nil), state.Observations...),
		Findings:     infer.Infer(*state),
		State:        state,
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}

// runBatch runs independent experiments concurrently with a bounded
// number of workers. Probes never "fail": failures are observations.
func runBatch(ctx context.Context, probes *probeSet, exps []model.Experiment, limit int) []model.Observation {
	results := make([]model.Observation, len(exps))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(limit)
	for i := range exps {
		i, e := i, exps[i]
		g.Go(func() error {
			results[i] = runOne(gctx, probes, e)
			return nil
		})
	}
	_ = g.Wait()
	return results
}

// runOne dispatches one experiment to its probe under the layer budget.
func runOne(ctx context.Context, probes *probeSet, e model.Experiment) model.Observation {
	pctx, cancel := context.WithTimeout(ctx, model.Budget(e.Layer))
	defer cancel()
	o := probes.run(pctx, e)
	o.Experiment = e
	o.Layer = e.Layer
	if o.Status == "" {
		o.Status = model.Unknown
	}
	return o
}

// dedupe normalizes proposals and drops experiments already recorded in
// the state or duplicated within the batch, capped at budget. Completed
// experiments are immutable and never rerun.
func dedupe(state *model.SurveyState, exps []model.Experiment, budget int) []model.Experiment {
	if budget <= 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]model.Experiment, 0, len(exps))
	for _, e := range exps {
		e.Normalize()
		if e.ID == "" || state.HasExperiment(e.ID) || seen[e.ID] {
			continue
		}
		seen[e.ID] = true
		out = append(out, e)
		if len(out) >= budget {
			break
		}
	}
	return out
}

// probeSet bundles the concrete probes configured for one survey.
type probeSet struct {
	dns  *probe.DNS
	tcp  *probe.TCP
	tls  *probe.TLS
	http *probe.HTTP
	udp  *probe.UDP
	quic *probe.QUIC
}

func newProbeSet(opts Options) *probeSet {
	return &probeSet{
		dns:  &probe.DNS{},
		tcp:  &probe.TCP{},
		tls:  &probe.TLS{RootCAs: opts.RootCAs, InsecureSkipVerify: opts.InsecureSkipVerify},
		http: &probe.HTTP{RootCAs: opts.RootCAs, InsecureSkipVerify: opts.InsecureSkipVerify},
		udp:  &probe.UDP{},
		quic: &probe.QUIC{RootCAs: opts.RootCAs, InsecureSkipVerify: opts.InsecureSkipVerify},
	}
}

func (ps *probeSet) run(ctx context.Context, e model.Experiment) model.Observation {
	switch e.Layer {
	case model.LayerDNS:
		return ps.dns.Run(ctx, e)
	case model.LayerTCP:
		return ps.tcp.Run(ctx, e)
	case model.LayerTLS:
		return ps.tls.Run(ctx, e)
	case model.LayerHTTP:
		return ps.http.Run(ctx, e)
	case model.LayerUDP:
		return ps.udp.Run(ctx, e)
	case model.LayerQUIC:
		return ps.quic.Run(ctx, e)
	default:
		o := model.NewObservation(e, model.Unknown, 0)
		o.Error = "no probe for layer " + string(e.Layer)
		return o
	}
}
