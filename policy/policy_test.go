package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

func testTarget(t *testing.T) model.Target {
	t.Helper()
	tgt, err := model.ParseTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

func newState(t *testing.T) *model.SurveyState {
	t.Helper()
	tgt := testTarget(t)
	return &model.SurveyState{SurveyID: "test", Target: &tgt, StartedAt: time.Now()}
}

func passObs(e model.Experiment, evidence ...model.Evidence) model.Observation {
	o := model.NewObservation(e, model.Pass, 10*time.Millisecond)
	o.Evidence = evidence
	return o
}

func failObs(e model.Experiment, evidence ...model.Evidence) model.Observation {
	o := model.NewObservation(e, model.Fail, 10*time.Millisecond)
	o.Evidence = evidence
	o.Error = "failed"
	return o
}

func dnsEvidence(v4, v6 []string) model.Evidence {
	return model.Evidence{Kind: model.KindDNSAnswer, Values: map[string]any{"v4": v4, "v6": v6}}
}

func mustPropose(t *testing.T, p Policy, state *model.SurveyState, budget int) []model.Experiment {
	t.Helper()
	out, err := p.Propose(context.Background(), *state, budget)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFastTreeProgression(t *testing.T) {
	p := NewFast()
	s := newState(t)

	// Round 0: DNS first.
	proposed := mustPropose(t, p, s, 16)
	if len(proposed) != 1 || proposed[0].Layer != model.LayerDNS {
		t.Fatalf("want single DNS experiment, got %+v", proposed)
	}
	_ = s.AddObservation(passObs(proposed[0], dnsEvidence([]string{"93.184.216.34"}, nil)))

	// Round 1: TCP for the resolved family + the independent QUIC branch.
	proposed = mustPropose(t, p, s, 16)
	if len(proposed) != 2 {
		t.Fatalf("want TCP+QUIC, got %+v", proposed)
	}
	if proposed[0].Layer != model.LayerTCP || proposed[0].IPFamily != model.IPv4 {
		t.Fatalf("want TCP/IPv4 first, got %+v", proposed[0])
	}
	if proposed[1].Layer != model.LayerQUIC {
		t.Fatalf("want QUIC second, got %+v", proposed[1])
	}
	_ = s.AddObservation(passObs(proposed[0]))

	// Round 2: TLS after TCP pass; QUIC is still unrecorded and comes
	// along again (independent branch).
	proposed = mustPropose(t, p, s, 16)
	if len(proposed) != 2 {
		t.Fatalf("want TLS + missing QUIC, got %+v", proposed)
	}
	if proposed[1].Layer != model.LayerTLS {
		t.Fatalf("want TLS in the batch, got %+v", proposed)
	}
	for _, e := range proposed {
		_ = s.AddObservation(passObs(e))
	}

	// Round 3: HTTP after TLS pass.
	proposed = mustPropose(t, p, s, 16)
	if len(proposed) != 1 || proposed[0].Layer != model.LayerHTTP {
		t.Fatalf("want HTTP, got %+v", proposed)
	}
	_ = s.AddObservation(passObs(proposed[0]))

	// Tree exhausted.
	if !p.Done(*s) {
		t.Fatal("FastPolicy should be done after the full tree passed")
	}
	if left := mustPropose(t, p, s, 16); len(left) != 0 {
		t.Fatalf("want no further proposals, got %+v", left)
	}
}

func TestFastDNSFailureStopsTree(t *testing.T) {
	p := NewFast()
	s := newState(t)
	proposed := mustPropose(t, p, s, 16)
	o := failObs(proposed[0], model.Evidence{Kind: model.KindDNSError, Values: map[string]any{"rcode": "NXDOMAIN"}})
	_ = s.AddObservation(o)
	if !p.Done(*s) {
		t.Fatal("tree must stop when DNS fails")
	}
	if left := mustPropose(t, p, s, 16); len(left) != 0 {
		t.Fatalf("want no proposals after DNS failure, got %+v", left)
	}
}

func TestFastSkipsProbedFamilies(t *testing.T) {
	p := NewFast()
	s := newState(t)
	dns := model.NewDNSExperiment(*s.Target, model.ResolverSystem)
	_ = s.AddObservation(passObs(dns, dnsEvidence([]string{"1.2.3.4"}, []string{"2001:db8::1"})))

	proposed := mustPropose(t, p, s, 16)
	layers := map[model.Layer]int{}
	for _, e := range proposed {
		layers[e.Layer]++
	}
	if layers[model.LayerTCP] != 2 {
		t.Fatalf("want TCP for both families, got %+v", proposed)
	}
	if layers[model.LayerQUIC] != 1 {
		t.Fatalf("want one QUIC experiment, got %+v", proposed)
	}
}

func TestFastBudgetRespected(t *testing.T) {
	p := NewFast()
	s := newState(t)
	dns := model.NewDNSExperiment(*s.Target, model.ResolverSystem)
	_ = s.AddObservation(passObs(dns, dnsEvidence([]string{"1.2.3.4"}, []string{"2001:db8::1"})))
	proposed := mustPropose(t, p, s, 2)
	if len(proposed) != 2 {
		t.Fatalf("budget not respected: got %d proposals", len(proposed))
	}
}

func TestPolicyDeterminism(t *testing.T) {
	policies := []Policy{NewFast(), NewAdaptive(), NewFactorial(FactorialOptions{ControlURL: "https://control.test"}), NewTaguchi(TaguchiOptions{})}
	for i, p := range policies {
		s := newState(t)
		a := mustPropose(t, p, s, 16)
		b := mustPropose(t, p, s, 16)
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		if !reflect.DeepEqual(ja, jb) {
			t.Errorf("policy %d: proposals not deterministic\n a=%s\n b=%s", i, ja, jb)
		}
	}
}

func TestAdaptiveSeparatesHypothesesAfterTLSFailure(t *testing.T) {
	p := NewAdaptive()
	s := newState(t)
	dns := model.NewDNSExperiment(*s.Target, model.ResolverSystem)
	tgt := *s.Target
	tcp := model.NewTCPExperiment(tgt, model.IPv4)
	tls := model.NewTLSExperiment(tgt, model.IPv4, "", "")
	quic := model.NewQUICExperiment(tgt, model.IPv4, "")
	_ = s.AddObservation(passObs(dns, dnsEvidence([]string{"1.2.3.4"}, nil)))
	_ = s.AddObservation(passObs(tcp))
	_ = s.AddObservation(failObs(tls, model.Evidence{Kind: model.KindTCPReset}))
	_ = s.AddObservation(passObs(quic))

	// The tree is exhausted: HTTP depends on TLS, so it is skipped when
	// TLS failed. The adaptive phase proposes TLS-variant experiments.
	if !p.Fast.Done(*s) {
		t.Fatal("tree should be exhausted (HTTP is gated on the failed TLS)")
	}
	proposed := mustPropose(t, p, s, 16)
	if len(proposed) == 0 || len(proposed) > 2 {
		t.Fatalf("want 1-2 adaptive proposals, got %+v", proposed)
	}
	for _, e := range proposed {
		if e.Layer != model.LayerTLS {
			t.Fatalf("expected TLS-variant experiments, got %+v", e)
		}
		if e.SNI != model.SNINone && e.ALPN != "http/1.1" {
			t.Fatalf("expected SNI/ALPN variants, got %+v", e)
		}
	}
	if p.Done(*s) {
		t.Fatal("adaptive policy must not be done while TLS hypotheses remain untested")
	}
}

func TestAdaptiveTerminates(t *testing.T) {
	p := NewAdaptive()
	s := newState(t)
	// Feed every proposal a passing observation until Done.
	for round := 0; round < 32; round++ {
		if p.Done(*s) {
			return
		}
		proposed := mustPropose(t, p, s, 16)
		if len(proposed) == 0 {
			t.Fatal("not done but nothing proposed")
		}
		for _, e := range proposed {
			_ = s.AddObservation(passObs(e))
		}
	}
	t.Fatal("AdaptivePolicy did not terminate within 32 rounds")
}

func TestFactorialProduct(t *testing.T) {
	p := NewFactorial(FactorialOptions{ControlURL: "https://control.test"})
	s := newState(t)
	proposed := mustPropose(t, p, s, 64)
	if len(proposed) != 8 {
		t.Fatalf("want 8 experiments (2 families x 2 transports x 2 targets), got %d", len(proposed))
	}
	seen := map[string]bool{}
	for _, e := range proposed {
		seen[e.ID] = true
	}
	if len(seen) != 8 {
		t.Fatalf("product produced duplicate IDs: %d unique of 8", len(seen))
	}
	hasControl := false
	for _, e := range proposed {
		if e.Target.Host == "control.test" {
			hasControl = true
		}
	}
	if !hasControl {
		t.Fatal("control target missing from the product")
	}

	// Done only when everything is recorded.
	if p.Done(*s) {
		t.Fatal("not done before running anything")
	}
	for _, e := range proposed {
		_ = s.AddObservation(passObs(e))
	}
	if !p.Done(*s) {
		t.Fatal("done expected after full product")
	}
}

func TestFactorialMaxCandidates(t *testing.T) {
	p := NewFactorial(FactorialOptions{MaxCandidates: 5, ControlURL: ""})
	s := newState(t)
	proposed := mustPropose(t, p, s, 64)
	if len(proposed) != 5 {
		t.Fatalf("MaxCandidates=5 not honored: got %d", len(proposed))
	}
}

func TestTaguchiL9(t *testing.T) {
	p := NewTaguchi(TaguchiOptions{})
	s := newState(t)
	proposed := mustPropose(t, p, s, 32)
	if len(proposed) != 9 {
		t.Fatalf("L9 must yield 9 experiments, got %d", len(proposed))
	}
	seen := map[string]bool{}
	for _, e := range proposed {
		seen[e.ID] = true
	}
	if len(seen) != 9 {
		t.Fatalf("L9 rows collapsed to %d unique experiments", len(seen))
	}

	// Orthogonality of the array: every pair of columns covers all 9
	// level combinations exactly once.
	for c1 := 0; c1 < 4; c1++ {
		for c2 := c1 + 1; c2 < 4; c2++ {
			pairs := map[[2]int]bool{}
			for _, row := range l9 {
				pairs[[2]int{row[c1], row[c2]}] = true
			}
			if len(pairs) != 9 {
				t.Errorf("columns %d/%d are not orthogonal (%d pairs)", c1, c2, len(pairs))
			}
		}
	}

	for _, e := range proposed {
		_ = s.AddObservation(passObs(e))
	}
	if !p.Done(*s) {
		t.Fatal("done expected after all 9 rows")
	}
}

func TestDedupeRejectsRecordedExperiments(t *testing.T) {
	p := NewFast()
	s := newState(t)
	first := mustPropose(t, p, s, 16)
	_ = s.AddObservation(passObs(first[0]))
	second := mustPropose(t, p, s, 16)
	for _, e := range second {
		if e.ID == first[0].ID {
			t.Fatalf("recorded experiment %s proposed again", e.ID)
		}
	}
}
