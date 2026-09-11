package policy

import (
	"context"

	"github.com/arahe-dev/fairy/internal/model"
)

// l9 is the standard L9(3^4) orthogonal array: 9 runs, 4 three-level
// factors, pairwise orthogonal (every pair of columns covers all 9
// level combinations exactly once).
var l9 = [9][4]int{
	{1, 1, 1, 1},
	{1, 2, 2, 2},
	{1, 3, 3, 3},
	{2, 1, 2, 3},
	{2, 2, 3, 1},
	{2, 3, 1, 2},
	{3, 1, 3, 2},
	{3, 2, 1, 3},
	{3, 3, 2, 1},
}

// TaguchiOptions configure TaguchiPolicy.
type TaguchiOptions struct {
	// MaxCandidates bounds the generated experiment count. Default: 32.
	MaxCandidates int
}

// TaguchiPolicy maps the L9 orthogonal array onto four diagnostic
// factors: address family, transport, SNI variant and payload size.
// It is a diagnostic/development policy — not for ordinary survey flow.
// Only meaningful when multiple independent factors with fixed discrete
// levels are all worth combining.
type TaguchiPolicy struct {
	Opts TaguchiOptions
}

// SNI levels used by TaguchiPolicy: default (target host), no SNI, and
// an unrelated hostname (which a healthy server rejects with a
// certificate mismatch — the interesting datum is whether the path
// treats the three differently).
var taguchiSNILevels = []string{"", model.SNINone, "www.example.com"}

var taguchiPayloadLevels = []int{16, 512, 1400}

// NewTaguchi returns a TaguchiPolicy with defaults.
func NewTaguchi(opts TaguchiOptions) *TaguchiPolicy {
	if opts.MaxCandidates <= 0 {
		opts.MaxCandidates = 32
	}
	return &TaguchiPolicy{Opts: opts}
}

// Propose returns the not-yet-recorded L9 experiments, capped at budget.
func (p *TaguchiPolicy) Propose(ctx context.Context, state model.SurveyState, budget int) ([]model.Experiment, error) {
	t, err := targetOf(state)
	if err != nil {
		return nil, err
	}
	return dedupeAndCap(state, p.rows(t), budget), nil
}

// Done reports whether all L9 rows are recorded.
func (p *TaguchiPolicy) Done(state model.SurveyState) bool {
	t, err := targetOf(state)
	if err != nil {
		return true
	}
	return len(dedupeAndCap(state, p.rows(t), p.Opts.MaxCandidates)) == 0
}

// rows maps each L9 row onto one experiment.
func (p *TaguchiPolicy) rows(t model.Target) []model.Experiment {
	families := []model.IPFamily{model.IPv4, model.IPv6, model.FamilyAny}
	transports := []model.Transport{model.TCP, model.UDP, model.QUIC}

	var out []model.Experiment
	for r := 0; r < len(l9); r++ {
		if len(out) >= p.Opts.MaxCandidates {
			break
		}
		fam := families[l9[r][0]-1]
		tr := transports[l9[r][1]-1]
		sni := taguchiSNILevels[l9[r][2]-1]
		payload := taguchiPayloadLevels[l9[r][3]-1]

		var e model.Experiment
		switch tr {
		case model.TCP:
			e = model.Experiment{Target: t, Layer: model.LayerTCP, IPFamily: fam, Transport: model.TCP, SNI: sni, Payload: payload}
		case model.UDP:
			e = model.Experiment{Target: t, Layer: model.LayerUDP, IPFamily: fam, Transport: model.UDP, SNI: sni, Payload: payload}
		case model.QUIC:
			e = model.Experiment{Target: t, Layer: model.LayerQUIC, IPFamily: fam, Transport: model.QUIC, ALPN: "h3", SNI: sni, Payload: payload}
		default:
			continue
		}
		e.Normalize()
		out = append(out, e)
	}
	return out
}
