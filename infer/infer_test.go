package infer

import (
	"reflect"
	"testing"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

func tgt(t *testing.T) model.Target {
	t.Helper()
	out, err := model.ParseTarget("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type obsSpec struct {
	layer    model.Layer
	family   model.IPFamily
	status   model.Status
	evidence []model.Evidence
}

func buildState(t *testing.T, specs ...obsSpec) model.SurveyState {
	t.Helper()
	target := tgt(t)
	s := model.SurveyState{SurveyID: "t", Target: &target, StartedAt: time.Now()}
	for _, sp := range specs {
		var e model.Experiment
		switch sp.layer {
		case model.LayerDNS:
			e = model.NewDNSExperiment(target, model.ResolverSystem)
		case model.LayerTCP:
			e = model.NewTCPExperiment(target, sp.family)
		case model.LayerTLS:
			e = model.NewTLSExperiment(target, sp.family, "", "")
		case model.LayerHTTP:
			e = model.NewHTTPExperiment(target, sp.family, "")
		case model.LayerUDP:
			e = model.NewUDPExperiment(target, sp.family, 0)
		case model.LayerQUIC:
			e = model.NewQUICExperiment(target, sp.family, "")
		}
		o := model.NewObservation(e, sp.status, 10*time.Millisecond)
		o.Evidence = sp.evidence
		if sp.status != model.Pass {
			o.Error = "synthetic failure"
		}
		_ = s.AddObservation(o)
	}
	return s
}

func kinds(findings []model.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Kind)
	}
	return out
}

func expectFindings(t *testing.T, state model.SurveyState, want []string) {
	t.Helper()
	got := kinds(Infer(state))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}
}

func TestHealthyPath(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerHTTP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerQUIC, model.IPv4, model.Pass, nil},
	)
	expectFindings(t, s, []string{KindPathHealthy})
	f := Infer(s)[0]
	if f.Confidence != model.Confirmed || len(f.Evidence) == 0 {
		t.Fatalf("path_healthy must be confirmed with evidence: %+v", f)
	}
}

func TestDNSFailureShortCircuits(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Fail, []model.Evidence{{Kind: model.KindDNSError, Values: map[string]any{"rcode": "NXDOMAIN"}}}},
	)
	expectFindings(t, s, []string{KindDNSFailure})
	if got := Infer(s)[0].Confidence; got != model.Confirmed {
		t.Fatalf("NXDOMAIN must be confirmed, got %s", got)
	}
}

func TestDNSTimeoutIsLikely(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Timeout, []model.Evidence{{Kind: model.KindTimeout}}},
	)
	expectFindings(t, s, []string{KindDNSFailure})
	if got := Infer(s)[0].Confidence; got != model.Likely {
		t.Fatalf("DNS timeout must be likely, got %s", got)
	}
}

func TestTCPRefusedConfirmed(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindTCPRefused}}},
	)
	expectFindings(t, s, []string{KindTCPUnreachable})
	if got := Infer(s)[0].Confidence; got != model.Confirmed {
		t.Fatalf("refused must be confirmed, got %s", got)
	}
}

func TestTCPTimeoutLikely(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Timeout, []model.Evidence{{Kind: model.KindTimeout}}},
	)
	expectFindings(t, s, []string{KindTCPUnreachable})
	if got := Infer(s)[0].Confidence; got != model.Likely {
		t.Fatalf("timeout must be likely, got %s", got)
	}
}

func TestIPv6PathFailure(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv6, model.Timeout, []model.Evidence{{Kind: model.KindTimeout}}},
	)
	expectFindings(t, s, []string{KindIPv6PathFailure})
}

func TestTLSSpecificFailureWithResetSuggestsProxy(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindTCPReset}}},
	)
	expectFindings(t, s, []string{KindTLSSpecificFailure, KindPossibleProxyInterference})
	if got := Infer(s)[0].Confidence; got != model.Likely {
		t.Fatalf("reset without alert must be likely, got %s", got)
	}
	if got := Infer(s)[1].Confidence; got != model.Possible {
		t.Fatalf("proxy interference must be possible, got %s", got)
	}
}

func TestTLSAlertConfirmed(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindTLSAlert, Values: map[string]any{"alert": 40, "name": "handshake_failure"}}}},
	)
	expectFindings(t, s, []string{KindTLSSpecificFailure})
	if got := Infer(s)[0].Confidence; got != model.Confirmed {
		t.Fatalf("alert must be confirmed, got %s", got)
	}
}

func TestQUICUnavailableLikelyWhenTCPWorks(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerQUIC, model.IPv4, model.Timeout, []model.Evidence{{Kind: model.KindTimeout}}},
	)
	expectFindings(t, s, []string{KindQUICUnavailable})
	if got := Infer(s)[0].Confidence; got != model.Likely {
		t.Fatalf("quic unavailable with working TCP must be likely, got %s", got)
	}
}

func TestQUICRefusedConfirmed(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerQUIC, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindUDPRefused}}},
	)
	expectFindings(t, s, []string{KindQUICUnavailable})
	if got := Infer(s)[0].Confidence; got != model.Confirmed {
		t.Fatalf("udp refusal must be confirmed, got %s", got)
	}
}

func TestUDPUnavailableConfidence(t *testing.T) {
	refused := buildState(t,
		obsSpec{model.LayerUDP, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindUDPRefused}}},
	)
	expectFindings(t, refused, []string{KindUDPUnavailable})
	if got := Infer(refused)[0].Confidence; got != model.Confirmed {
		t.Fatalf("refused must be confirmed, got %s", got)
	}

	silent := buildState(t,
		obsSpec{model.LayerUDP, model.IPv4, model.Timeout, []model.Evidence{{Kind: model.KindTimeout}}},
	)
	expectFindings(t, silent, []string{KindUDPUnavailable})
	if got := Infer(silent)[0].Confidence; got != model.Possible {
		t.Fatalf("silence must stay possible (never 'blocked'), got %s", got)
	}
}

func TestHTTPApplicationRejection(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerHTTP, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindHTTPStatus, Values: map[string]any{"status": 503}}}},
	)
	expectFindings(t, s, []string{KindHTTPApplicationRejection})
	if got := Infer(s)[0].Confidence; got != model.Confirmed {
		t.Fatalf("observed 5xx must be confirmed, got %s", got)
	}
}

func TestEmptyStateYieldsNothing(t *testing.T) {
	s := buildState(t)
	if got := Infer(s); got != nil {
		t.Fatalf("empty state must produce no findings, got %v", got)
	}
}

func TestEvidenceLinesReferenceExperiments(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindTCPRefused}}},
	)
	f := Infer(s)[0]
	for _, e := range f.Evidence {
		if len(e) < 12 {
			t.Fatalf("evidence line too short: %q", e)
		}
	}
}

// "No data of the requested type" (filtered AAAA, etc.) means the name
// exists — that must not read as a confirmed NXDOMAIN.
func TestDNSNoDataIsLikely(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Fail, []model.Evidence{{Kind: model.KindDNSError, Values: map[string]any{"rcode": "NOERROR", "note": "no data"}}}},
	)
	expectFindings(t, s, []string{KindDNSFailure})
	if got := Infer(s)[0].Confidence; got != model.Likely {
		t.Fatalf("nodata must stay likely, got %s", got)
	}
}

// A certificate signed by an unknown authority on a path where TCP
// works is the interception signature: tls_specific_failure stays
// confirmed, and possible_proxy_interference must be reported.
func TestTLSUnknownAuthoritySuggestsProxy(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTLS, model.IPv4, model.Fail, []model.Evidence{{Kind: model.KindCertificate, Values: map[string]any{"type": "unknown_authority", "error": "x509: certificate signed by unknown authority"}}}},
	)
	got := kinds(Infer(s))
	if !reflect.DeepEqual(got, []string{KindTLSSpecificFailure, KindPossibleProxyInterference}) {
		t.Fatalf("findings = %v, want [tls_specific_failure possible_proxy_interference]", got)
	}
	if c := Infer(s)[1].Confidence; c != model.Possible {
		t.Fatalf("interference must stay possible, got %s", c)
	}
}

// Skipped observations mean "never probed" (prerequisite missing) and
// must not become layer-failure findings.
func TestSkippedObservationsAreNotFailures(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv6, model.Skipped, []model.Evidence{{Kind: model.KindDNSError, Values: map[string]any{"error": "resolution failed"}}}},
		obsSpec{model.LayerQUIC, model.IPv6, model.Skipped, []model.Evidence{{Kind: model.KindDNSError, Values: map[string]any{"error": "resolution failed"}}}},
	)
	if got := Infer(s); got != nil {
		t.Fatalf("skipped layers must produce no findings, got %v", got)
	}
}

// IPv6 unreachable where IPv4 works is the ipv6_path_failure signature —
// including the "network is unreachable" flavor (Fail, not Unknown).
func TestIPv6UnreachableFiresPathFailure(t *testing.T) {
	s := buildState(t,
		obsSpec{model.LayerDNS, "", model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv4, model.Pass, nil},
		obsSpec{model.LayerTCP, model.IPv6, model.Fail, []model.Evidence{{Kind: model.KindNetworkUnreachable}}},
	)
	expectFindings(t, s, []string{KindIPv6PathFailure})
}

// Regression: an adaptive follow-up variant that passes must not mask the
// failing canonical experiment of the same layer. Found by comparing
// adaptive-policy runs with `fairy compare` on a real network.
func TestVariantPassDoesNotMaskCanonicalFailure(t *testing.T) {
	target := tgt(t)
	canonical := model.NewTLSExperiment(target, model.IPv4, "", "")
	variant := model.NewTLSExperiment(target, model.IPv4, "", model.SNINone)
	if canonical.ID == variant.ID {
		t.Fatal("test needs distinct experiments")
	}
	s := model.SurveyState{SurveyID: "t", Target: &target}
	tcp := model.NewTCPExperiment(target, model.IPv4)
	_ = s.AddObservation(passObsFor(tcp))
	_ = s.AddObservation(failObsFor(canonical, model.Evidence{Kind: model.KindCertificate, Values: map[string]any{"type": "unknown_authority"}}))
	// The SNI-less variant is recorded later and passed.
	_ = s.AddObservation(passObsFor(variant))

	got := kinds(Infer(s))
	if !reflect.DeepEqual(got, []string{KindTLSSpecificFailure, KindPossibleProxyInterference}) {
		t.Fatalf("findings = %v, want canonical TLS failure to survive variant passes", got)
	}
}

func passObsFor(e model.Experiment) model.Observation {
	return model.NewObservation(e, model.Pass, 5*time.Millisecond)
}

func failObsFor(e model.Experiment, evidence ...model.Evidence) model.Observation {
	o := model.NewObservation(e, model.Fail, 5*time.Millisecond)
	o.Evidence = evidence
	o.Error = "synthetic failure"
	return o
}
