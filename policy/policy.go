// Package policy contains experiment-selection policies. A Policy is a
// pure function of SurveyState: the same config plus the same state must
// propose the same experiments, and policies never mutate the state they
// receive. Termination is guaranteed: every policy can only propose a
// finite set of experiments, and proposals already recorded in the state
// are never repeated.
package policy

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"

	"github.com/arahe-dev/fairy/internal/model"
)

// Policy selects the next experiments to run and decides when a survey
// is complete.
type Policy interface {
	// Propose returns up to `budget` experiments to run next. It must be
	// pure: same config + same state -> same experiments.
	Propose(ctx context.Context, state model.SurveyState, budget int) ([]model.Experiment, error)
	// Done reports whether the survey is complete for this policy.
	Done(state model.SurveyState) bool
}

// errNoTarget is returned when a policy is asked to propose against a
// state that carries no target.
var errNoTarget = errors.New("policy: survey state has no target")

// targetOf extracts the survey target from the state.
func targetOf(state model.SurveyState) (model.Target, error) {
	if t, ok := state.TargetOf(); ok {
		return t, nil
	}
	return model.Target{}, errNoTarget
}

// latest returns the most recent observation for a layer (and, when
// family is not empty, that address family). It searches backwards so a
// resumed state with repeated layers still sees the newest result.
func latest(state model.SurveyState, layer model.Layer, family model.IPFamily) *model.Observation {
	for i := len(state.Observations) - 1; i >= 0; i-- {
		o := &state.Observations[i]
		if o.Layer != layer {
			continue
		}
		if family != "" && o.Experiment.IPFamily != family {
			continue
		}
		return o
	}
	return nil
}

// resolvedFamilies reads IPv4/IPv6 presence out of a passing DNS
// observation. Without answer evidence it conservatively assumes IPv4.
func resolvedFamilies(dns model.Observation) (v4, v6 bool) {
	ev, ok := dns.FirstEvidenceOf(model.KindDNSAnswer)
	if !ok {
		return true, false
	}
	if s, ok := model.AsStrings(ev.Values["v4"]); ok {
		v4 = len(s) > 0
	}
	if s, ok := model.AsStrings(ev.Values["v6"]); ok {
		v6 = len(s) > 0
	}
	return v4, v6
}

// orderedFamilies returns the families to dial, preferred first.
func orderedFamilies(v4, v6, prefer6 bool) []model.IPFamily {
	var out []model.IPFamily
	first, second := model.IPv4, model.IPv6
	if prefer6 {
		first, second = model.IPv6, model.IPv4
	}
	if first == model.IPv4 && v4 || first == model.IPv6 && v6 {
		out = append(out, first)
	}
	if second == model.IPv4 && v4 || second == model.IPv6 && v6 {
		out = append(out, second)
	}
	return out
}

// withPort clones a target with a different port.
func withPort(t model.Target, port uint16) model.Target {
	clone := t
	if t.URL != nil {
		u := *t.URL
		u.Host = net.JoinHostPort(t.Host, strconv.FormatUint(uint64(port), 10))
		clone.URL = &u
	}
	clone.Port = port
	return clone
}

// costOf is the estimated cost of an experiment, used by policies that
// trade information gain against cost.
func costOf(e model.Experiment) int {
	switch e.Layer {
	case model.LayerTLS, model.LayerHTTP:
		return 2
	case model.LayerQUIC:
		return 3
	default:
		return 1
	}
}

// dedupeAndCap drops experiments already recorded in the state (or
// duplicated inside the batch), keeps canonical ordering stable, and caps
// the result at budget.
func dedupeAndCap(state model.SurveyState, exps []model.Experiment, budget int) []model.Experiment {
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

// sortCandidates orders candidates by score descending with a stable
// deterministic tie-break on canonical representation.
type scoredCandidate struct {
	exp   model.Experiment
	score int
}

func sortScored(cands []scoredCandidate) {
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].exp.Canonical() < cands[j].exp.Canonical()
	})
}
