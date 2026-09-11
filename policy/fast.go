package policy

import (
	"context"

	"github.com/arahe-dev/fairy/internal/model"
)

// FastPolicy is the default policy: a deterministic dependency tree
//
//	DNS → TCP(/port) → TLS → HTTP, with QUIC/H3 as an independent branch.
//
// Dependent probes run only when their prerequisites pass. A typical
// survey proposes 4–7 experiments.
type FastPolicy struct {
	// PreferIPv6 makes IPv6 the preferred family when both resolve.
	PreferIPv6 bool
}

// NewFast returns a FastPolicy with default preferences.
func NewFast() *FastPolicy { return &FastPolicy{} }

// Propose returns the next deterministic slice of the tree, capped at
// budget. Independent experiments (e.g. TCP and QUIC) are proposed in the
// same round; dependent ones wait for their prerequisites.
func (f *FastPolicy) Propose(ctx context.Context, state model.SurveyState, budget int) ([]model.Experiment, error) {
	return dedupeAndCap(state, f.plan(state), budget), nil
}

// Done reports whether the tree is exhausted: every experiment the tree
// would propose is already recorded.
func (f *FastPolicy) Done(state model.SurveyState) bool {
	if _, err := targetOf(state); err != nil {
		return true
	}
	return len(f.plan(state)) == 0
}

// plan is the pure heart of FastPolicy: given the state, return every
// experiment the tree would run next, in deterministic order.
func (f *FastPolicy) plan(state model.SurveyState) []model.Experiment {
	t, err := targetOf(state)
	if err != nil {
		return nil
	}
	var out []model.Experiment

	// 1. DNS first.
	dns := latest(state, model.LayerDNS, "")
	if dns == nil {
		out = append(out, model.NewDNSExperiment(t, model.ResolverSystem))
		return out
	}
	if dns.Status != model.Pass {
		// Name resolution failed: nothing else in the tree is meaningful.
		return out
	}
	v4, v6 := resolvedFamilies(*dns)
	fams := orderedFamilies(v4, v6, f.PreferIPv6)
	if len(fams) == 0 {
		return out
	}

	// 2. TCP per resolved family (preferred first).
	var tcpPass *model.Observation
	for _, fam := range fams {
		tcp := latest(state, model.LayerTCP, fam)
		if tcp == nil {
			out = append(out, model.NewTCPExperiment(t, fam))
			continue
		}
		if tcp.Status == model.Pass && tcpPass == nil {
			tcpPass = tcp
		}
	}

	// 3. QUIC/H3 as an independent branch (needs DNS only, not TCP).
	if t.IsHTTPS() {
		qfam := fams[0]
		if latest(state, model.LayerQUIC, qfam) == nil {
			out = append(out, model.NewQUICExperiment(t, qfam, ""))
		}
	}

	// 4. TLS after a TCP pass, then HTTP after a TLS pass.
	if tcpPass != nil {
		fam := tcpPass.Experiment.IPFamily
		if t.IsHTTPS() {
			tls := latest(state, model.LayerTLS, fam)
			if tls == nil {
				out = append(out, model.NewTLSExperiment(t, fam, "", ""))
			} else if tls.Status == model.Pass && latest(state, model.LayerHTTP, fam) == nil {
				out = append(out, model.NewHTTPExperiment(t, fam, ""))
			}
		} else {
			// Plain HTTP target: DNS → TCP → HTTP, no TLS.
			if latest(state, model.LayerHTTP, fam) == nil {
				out = append(out, model.NewHTTPExperiment(t, fam, ""))
			}
		}
	}
	return out
}
