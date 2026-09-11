package policy

import (
	"context"

	"github.com/arahe-dev/fairy/internal/model"
)

// DefaultFactorialControlURL is the control target used by
// FactorialPolicy when no other control is configured. It is a
// well-known, highly available HTTPS endpoint.
const DefaultFactorialControlURL = "https://www.google.com/generate_204"

// FactorialOptions configure FactorialPolicy.
type FactorialOptions struct {
	// Families to cross. Default: IPv4 and IPv6.
	Families []model.IPFamily
	// Transports to cross. Default: TCP and QUIC.
	Transports []model.Transport
	// ControlURL is the control target crossed against the survey
	// target. Empty disables the control level.
	ControlURL string
	// MaxCandidates bounds the Cartesian product. Default: 64.
	MaxCandidates int
}

// FactorialPolicy is a diagnostic policy: it generates the Cartesian
// product of its factors — family × transport × {target, control} —
// bounded by MaxCandidates. With the defaults that is 2×2×2 = 8 runs.
type FactorialPolicy struct {
	Opts FactorialOptions

	control model.Target
}

// NewFactorial fills defaults and parses the control target.
func NewFactorial(opts FactorialOptions) *FactorialPolicy {
	p := &FactorialPolicy{Opts: opts}
	if len(p.Opts.Families) == 0 {
		p.Opts.Families = []model.IPFamily{model.IPv4, model.IPv6}
	}
	if len(p.Opts.Transports) == 0 {
		p.Opts.Transports = []model.Transport{model.TCP, model.QUIC}
	}
	if p.Opts.MaxCandidates <= 0 {
		p.Opts.MaxCandidates = 64
	}
	if p.Opts.ControlURL == "" {
		p.Opts.ControlURL = DefaultFactorialControlURL
	}
	if p.Opts.ControlURL != "" {
		if t, err := model.ParseTarget(p.Opts.ControlURL); err == nil {
			p.control = t
		}
	}
	return p
}

// Propose returns the not-yet-recorded experiments of the Cartesian
// product, capped at budget.
func (p *FactorialPolicy) Propose(ctx context.Context, state model.SurveyState, budget int) ([]model.Experiment, error) {
	t, err := targetOf(state)
	if err != nil {
		return nil, err
	}
	return dedupeAndCap(state, p.product(t), budget), nil
}

// Done reports whether every candidate of the product is recorded.
func (p *FactorialPolicy) Done(state model.SurveyState) bool {
	t, err := targetOf(state)
	if err != nil {
		return true
	}
	return len(dedupeAndCap(state, p.product(t), p.Opts.MaxCandidates)) == 0
}

// product builds the full Cartesian product deterministically:
// family × transport × {survey target, control target}.
func (p *FactorialPolicy) product(t model.Target) []model.Experiment {
	targets := []model.Target{t}
	if p.control.Host != "" {
		targets = append(targets, p.control)
	}
	var out []model.Experiment
	for _, fam := range p.Opts.Families {
		for _, tr := range p.Opts.Transports {
			for _, tgt := range targets {
				var e model.Experiment
				switch tr {
				case model.TCP:
					e = model.NewTCPExperiment(tgt, fam)
				case model.UDP:
					e = model.NewUDPExperiment(tgt, fam, 0)
				case model.QUIC:
					e = model.NewQUICExperiment(tgt, fam, "")
				default:
					continue
				}
				out = append(out, e)
				if len(out) >= p.Opts.MaxCandidates {
					return out
				}
			}
		}
	}
	return out
}
