package model

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestExperimentIDDeterministic(t *testing.T) {
	tgt, err := ParseTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	a := NewTCPExperiment(tgt, IPv4)
	b := NewTCPExperiment(tgt, IPv4)
	if a.ID == "" || len(a.ID) != 12 {
		t.Fatalf("want 12-char ID, got %q", a.ID)
	}
	if a.ID != b.ID {
		t.Fatalf("same inputs produced different IDs: %s vs %s", a.ID, b.ID)
	}
	c := NewTCPExperiment(tgt, IPv6)
	if a.ID == c.ID {
		t.Fatal("different inputs produced the same ID")
	}
	// Explicit ALPN and SNI change the ID.
	tlsA := NewTLSExperiment(tgt, IPv4, "", "")
	tlsB := NewTLSExperiment(tgt, IPv4, "http/1.1", "")
	tlsC := NewTLSExperiment(tgt, IPv4, "", SNINone)
	ids := map[string]bool{tlsA.ID: true, tlsB.ID: true, tlsC.ID: true}
	if len(ids) != 3 {
		t.Fatalf("ALPN/SNI variants must have distinct IDs: %v", ids)
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		raw      string
		wantHost string
		wantPort uint16
		wantErr  bool
	}{
		{"https://example.com", "example.com", 443, false},
		{"https://example.com:8443/x", "example.com", 8443, false},
		{"http://example.com", "example.com", 80, false},
		{"http://[::1]:8080/", "::1", 8080, false},
		{"ftp://example.com", "", 0, true},
		{"https://", "", 0, true},
		{"", "", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q): want error, got %+v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tc.raw, err)
			continue
		}
		if got.Host != tc.wantHost || got.Port != tc.wantPort {
			t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d", tc.raw, got.Host, got.Port, tc.wantHost, tc.wantPort)
		}
		if got.URL == nil {
			t.Errorf("ParseTarget(%q): URL is nil", tc.raw)
		}
	}
}

func TestNormalize(t *testing.T) {
	tgt, _ := ParseTarget("https://example.com")
	var e Experiment
	e.Target = tgt
	e.Layer = LayerDNS
	e.Normalize()
	if e.IPFamily != FamilyAny || e.Transport != UDP || e.Resolver != ResolverSystem {
		t.Fatalf("DNS defaults not applied: %+v", e)
	}
	if e.ID == "" {
		t.Fatal("Normalize did not fill the ID")
	}

	tcp := Experiment{Target: tgt, Layer: LayerTCP}
	tcp.Normalize()
	if tcp.IPFamily != IPv4 || tcp.Transport != TCP {
		t.Fatalf("TCP defaults not applied: %+v", tcp)
	}
}

func TestStateAddObservationRejectsDuplicates(t *testing.T) {
	tgt, _ := ParseTarget("https://example.com")
	e := NewTCPExperiment(tgt, IPv4)
	s := &SurveyState{SurveyID: "s1", Target: &tgt}
	o := NewObservation(e, Pass, 10*time.Millisecond)
	if err := s.AddObservation(o); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := s.AddObservation(o); !errors.Is(err, ErrDuplicateExperiment) {
		t.Fatalf("want ErrDuplicateExperiment, got %v", err)
	}
	if !s.HasExperiment(e.ID) {
		t.Fatal("HasExperiment = false after add")
	}
}

func TestStateJSONRoundTrip(t *testing.T) {
	tgt, _ := ParseTarget("https://example.com")
	dns := NewDNSExperiment(tgt, ResolverSystem)
	s := &SurveyState{SurveyID: "abc", Target: &tgt, StartedAt: time.Now().Truncate(time.Second)}
	o := NewObservation(dns, Pass, 5*time.Millisecond)
	o.AddEvidence(KindDNSAnswer, map[string]any{"v4": []string{"1.2.3.4"}, "v6": []string{}, "latency_ms": int64(5)})
	_ = s.AddObservation(o)
	s.Rounds = append(s.Rounds, Round{Index: 0, Proposed: []Experiment{dns}})

	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var back SurveyState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.SurveyID != "abc" || len(back.Observations) != 1 || len(back.Rounds) != 1 {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if back.Target == nil || back.Target.Host != "example.com" {
		t.Fatalf("round trip lost target: %+v", back.Target)
	}
	v4, _ := AsStrings(back.Observations[0].Evidence[0].Values["v4"])
	if len(v4) != 1 || v4[0] != "1.2.3.4" {
		t.Fatalf("round trip lost evidence: %+v", back.Observations[0].Evidence[0])
	}
}

func TestBudget(t *testing.T) {
	if Budget(LayerDNS) != 2*time.Second || Budget(LayerQUIC) != 3*time.Second {
		t.Fatal("unexpected layer budgets")
	}
}
