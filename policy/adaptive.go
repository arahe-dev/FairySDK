package policy

import (
	"context"

	"github.com/arahe-dev/fairy/internal/model"
)

// AdaptivePolicy runs the FastPolicy tree first, then — while failures
// remain unexplained — proposes follow-up experiments that separate
// plausible hypotheses, scored by:
//
//	score = hypothesesSeparated*10 - estimatedCost - duplicatePenalty
//
// The highest-scoring experiments run next. Selection is deterministic.
type AdaptivePolicy struct {
	Fast FastPolicy
}

// NewAdaptive returns an AdaptivePolicy with default preferences.
func NewAdaptive() *AdaptivePolicy { return &AdaptivePolicy{Fast: FastPolicy{}} }

// Propose first proposes the basic tree; once the tree is exhausted it
// proposes the highest-scoring hypothesis-separating experiments.
func (a *AdaptivePolicy) Propose(ctx context.Context, state model.SurveyState, budget int) ([]model.Experiment, error) {
	base, err := a.Fast.Propose(ctx, state, budget)
	if err != nil {
		return nil, err
	}
	if len(base) > 0 {
		return base, nil
	}
	scored := a.scoreCandidates(state)
	take := 2
	if budget < take {
		take = budget
	}
	out := make([]model.Experiment, 0, take)
	for _, c := range scored {
		if len(out) >= take {
			break
		}
		out = append(out, c.exp)
	}
	return dedupeAndCap(state, out, budget), nil
}

// Done requires the tree to be exhausted and every separating experiment
// the policy would propose to be recorded.
func (a *AdaptivePolicy) Done(state model.SurveyState) bool {
	if _, err := targetOf(state); err != nil {
		return true
	}
	return a.Fast.Done(state) && len(a.candidates(state)) == 0
}

// candidate pairs an experiment with the hypotheses it would separate.
type candidate struct {
	exp  model.Experiment
	hyps []string
}

// Hypothesis identifiers used for candidate scoring.
const (
	hypResolverAnomaly  = "resolver_anomaly"
	hypFamilySpecific   = "family_specific"
	hypSNIFiltering     = "sni_filtering"
	hypALPNInterference = "alpn_interference"
	hypPortSpecific     = "port_specific"
	hypUDPBlocked       = "udp_blocked"
	hypH2Broken         = "h2_broken"
)

// candidates lists the follow-up experiments that could resolve an
// unexplained failure, in a fixed order. Already-recorded experiments are
// excluded, which guarantees termination.
func (a *AdaptivePolicy) candidates(state model.SurveyState) []candidate {
	t, err := targetOf(state)
	if err != nil {
		return nil
	}
	var out []candidate
	add := func(e model.Experiment, hyps ...string) {
		e.Normalize()
		if state.HasExperiment(e.ID) {
			return
		}
		out = append(out, candidate{exp: e, hyps: hyps})
	}

	dns := latest(state, model.LayerDNS, "")
	dnsPass := dns != nil && dns.Status == model.Pass
	if dns == nil {
		return nil
	}
	v4, v6 := resolvedFamilies(*dns)

	// DNS failed: compare the system resolver against a public one.
	if !dnsPass && latest(state, model.LayerDNS, "") != nil &&
		stateHasNoExperimentOf(state, func(e model.Experiment) bool {
			return e.Layer == model.LayerDNS && e.Resolver == model.ResolverPublic
		}) {
		add(model.NewDNSExperiment(t, model.ResolverPublic), hypResolverAnomaly)
		return out // nothing else is meaningful without names
	}
	if !dnsPass {
		return out
	}

	fams := orderedFamilies(v4, v6, a.Fast.PreferIPv6)
	other := func(fam model.IPFamily) model.IPFamily {
		if fam == model.IPv4 {
			return model.IPv6
		}
		return model.IPv4
	}

	// TCP timed out on the preferred family while the other family was
	// announced: try the other family.
	if len(fams) > 1 {
		fam0 := fams[0]
		if tcp := latest(state, model.LayerTCP, fam0); tcp != nil && tcp.Status != model.Pass {
			if latest(state, model.LayerTCP, fams[1]) == nil {
				add(model.NewTCPExperiment(t, fams[1]), hypFamilySpecific)
			}
		}
	}

	// TCP fails on every resolved family: is it port-specific?
	tcpAnyPass := false
	tcpAllFailed := len(fams) > 0
	for _, fam := range fams {
		tcp := latest(state, model.LayerTCP, fam)
		if tcp == nil {
			tcpAllFailed = false
			break
		}
		if tcp.Status == model.Pass {
			tcpAnyPass = true
			tcpAllFailed = false
		}
	}
	if tcpAllFailed {
		add(model.NewTCPExperiment(withPort(t, 80), fams[0]), hypPortSpecific)
		return out
	}

	// TLS failed while TCP passed: compare family, SNI and ALPN.
	if tcpAnyPass && t.IsHTTPS() {
		for _, fam := range fams {
			tcp := latest(state, model.LayerTCP, fam)
			if tcp == nil || tcp.Status != model.Pass {
				continue
			}
			tlsObs := latest(state, model.LayerTLS, fam)
			if tlsObs == nil || tlsObs.Status == model.Pass {
				continue
			}
			if o := latest(state, model.LayerTLS, other(fam)); o == nil && contains(fams, other(fam)) {
				add(model.NewTLSExperiment(t, other(fam), "", ""), hypFamilySpecific)
			}
			add(model.NewTLSExperiment(t, fam, "", model.SNINone), hypSNIFiltering)
			add(model.NewTLSExperiment(t, fam, "http/1.1", ""), hypALPNInterference)
		}
	}

	// QUIC failed while TCP+TLS work: is UDP itself unusable?
	if tcpAnyPass && t.IsHTTPS() {
		if q := latest(state, model.LayerQUIC, fams[0]); q != nil && q.Status != model.Pass {
			add(model.NewUDPExperiment(t, fams[0], 0), hypUDPBlocked)
		}
	}

	// HTTP rejected while TLS works: is it protocol-specific?
	if tcpAnyPass {
		for _, fam := range fams {
			if t.IsHTTPS() {
				tlsObs := latest(state, model.LayerTLS, fam)
				if tlsObs == nil || tlsObs.Status != model.Pass {
					continue
				}
			}
			if h := latest(state, model.LayerHTTP, fam); h != nil && h.Status != model.Pass {
				add(model.NewHTTPExperiment(t, fam, "http/1.1"), hypH2Broken)
			}
		}
	}
	return out
}

// scoreCandidates scores candidates by
//
//	score = hypothesesSeparated*10 - estimatedCost - duplicatePenalty
//
// and returns them ordered deterministically (score desc, then canonical
// form ascending).
func (a *AdaptivePolicy) scoreCandidates(state model.SurveyState) []scoredCandidate {
	scored := make([]scoredCandidate, 0, 8)
	for _, c := range a.candidates(state) {
		duplicatePenalty := 0
		if state.HasExperiment(c.exp.ID) {
			duplicatePenalty = 1000
		}
		score := len(c.hyps)*10 - costOf(c.exp) - duplicatePenalty
		scored = append(scored, scoredCandidate{exp: c.exp, score: score})
	}
	sortScored(scored)
	return scored
}

// stateHasNoExperimentOf reports whether no recorded experiment matches.
func stateHasNoExperimentOf(state model.SurveyState, match func(model.Experiment) bool) bool {
	for i := range state.Observations {
		if match(state.Observations[i].Experiment) {
			return false
		}
	}
	return true
}

func contains(fams []model.IPFamily, f model.IPFamily) bool {
	for _, x := range fams {
		if x == f {
			return true
		}
	}
	return false
}
