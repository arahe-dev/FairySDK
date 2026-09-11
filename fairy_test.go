package fairy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// localTLSServer starts an HTTPS server for host "localhost" on
// 127.0.0.1 with a certificate the returned pool trusts.
func localTLSServer(t *testing.T) (baseURL string, rootCAs tlsRootPool, close func()) {
	t.Helper()
	cert, pool := testCertPair(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fairy-e2e")
		_, _ = w.Write([]byte("hello fairy"))
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	return "https://localhost:" + portOf(ln.Addr().String()), pool, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func portOf(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}

func TestSurveyEndToEndLocalhost(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	f, err := New(Config{Timeout: 20 * time.Second, TLSRootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	report, err := f.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatalf("survey: %v", err)
	}
	if report == nil || len(report.Observations) == 0 {
		t.Fatal("empty report")
	}

	passed := map[Layer]bool{}
	hasQUIC := false
	for _, o := range report.Observations {
		switch o.Layer {
		case LayerDNS, LayerTCP, LayerTLS, LayerHTTP:
			if o.Status == Pass {
				passed[o.Layer] = true
			}
		case LayerQUIC:
			hasQUIC = true
		}
	}
	for _, l := range []Layer{LayerDNS, LayerTCP, LayerTLS, LayerHTTP} {
		if !passed[l] {
			t.Errorf("layer %s did not pass: %+v", l, report.Observations)
		}
	}
	if !hasQUIC {
		t.Error("no QUIC observation (FastPolicy must probe the QUIC branch)")
	}
	foundQUICFinding := false
	for _, f := range report.Findings {
		if f.Kind == KindQUICUnavailable {
			foundQUICFinding = true
			if len(f.Evidence) == 0 {
				t.Error("finding without evidence")
			}
		}
	}
	if !foundQUICFinding {
		t.Errorf("expected a quic_unavailable finding, got %+v", report.Findings)
	}
}

func TestSurveyExperimentIDsDeterministic(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	cfg := Config{Timeout: 20 * time.Second, TLSRootCAs: pool}
	f1, _ := New(cfg)
	f2, _ := New(cfg)

	r1, err := f1.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := f2.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatal(err)
	}
	ids1 := map[string]bool{}
	for _, o := range r1.Observations {
		ids1[o.Experiment.ID] = true
	}
	ids2 := map[string]bool{}
	for _, o := range r2.Observations {
		ids2[o.Experiment.ID] = true
	}
	if len(ids1) != len(ids2) {
		t.Fatalf("different experiment counts across identical surveys: %d vs %d", len(ids1), len(ids2))
	}
	for id := range ids1 {
		if !ids2[id] {
			t.Fatalf("experiment %s missing from the second survey", id)
		}
	}
}

func TestResumeFromSavedState(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	// Phase 1: a budget of one probe records DNS only.
	f1, err := New(Config{MaxProbes: 1, Timeout: 20 * time.Second, TLSRootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	report1, err := f1.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if len(report1.Observations) != 1 {
		t.Fatalf("want exactly one observation, got %d", len(report1.Observations))
	}
	if report1.State == nil {
		t.Fatal("report carries no state")
	}
	raw, err := SaveState(*report1.State)
	if err != nil {
		t.Fatal(err)
	}
	state, err := LoadState(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Phase 2: resume completes the survey without rerunning DNS.
	f2, err := New(Config{Timeout: 20 * time.Second, TLSRootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	report2, err := f2.Resume(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(report2.Observations) <= 1 {
		t.Fatalf("resume made no progress: %d observations", len(report2.Observations))
	}
	seen := map[string]bool{}
	for _, o := range report2.Observations {
		if seen[o.Experiment.ID] {
			t.Fatalf("duplicate experiment %s after resume", o.Experiment.ID)
		}
		seen[o.Experiment.ID] = true
	}
	if !seen[report1.Observations[0].Experiment.ID] {
		t.Fatal("resumed survey lost the original observation")
	}
	passed := map[Layer]bool{}
	for _, o := range report2.Observations {
		if o.Status == Pass {
			passed[o.Layer] = true
		}
	}
	for _, l := range []Layer{LayerTCP, LayerTLS, LayerHTTP} {
		if !passed[l] {
			t.Errorf("resumed survey did not complete layer %s", l)
		}
	}
}

func TestDuplicateExperimentRejection(t *testing.T) {
	tgt, err := ParseTarget("https://localhost")
	if err != nil {
		t.Fatal(err)
	}
	state := NewSurveyState(tgt)
	e := Experiment{Target: tgt, Layer: LayerTCP, IPFamily: IPv4, Transport: TCP}
	e.Normalize()
	o := Observation{Experiment: e, Layer: LayerTCP, Status: Pass}
	if err := state.AddObservation(o); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := state.AddObservation(o); !errors.Is(err, ErrDuplicateExperiment) {
		t.Fatalf("want ErrDuplicateExperiment, got %v", err)
	}
}

func TestCanceledContextReturnsPartialReport(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	f, err := New(Config{Timeout: 20 * time.Second, TLSRootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := f.Survey(ctx, baseURL)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if report == nil {
		t.Fatal("cancellation should still return the (partial) report")
	}
}

func TestSurveyCompletesWithLowConcurrency(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	f, err := New(Config{MaxConcurrent: 1, Timeout: 30 * time.Second, TLSRootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	report, err := f.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatalf("survey with concurrency 1: %v", err)
	}
	if len(report.Observations) < 4 {
		t.Fatalf("too few observations: %d", len(report.Observations))
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New(Config{MaxProbes: -1}); err == nil {
		t.Error("negative MaxProbes must be rejected")
	}
	if _, err := New(Config{Timeout: -time.Second}); err == nil {
		t.Error("negative Timeout must be rejected")
	}
	if _, err := New(Config{MaxConcurrent: -2}); err == nil {
		t.Error("negative MaxConcurrent must be rejected")
	}
	f, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if f.cfg.Policy != Fast {
		t.Fatal("nil policy must default to Fast")
	}
}

func TestRenderReportConsole(t *testing.T) {
	baseURL, pool, closeSrv := localTLSServer(t)
	defer closeSrv()

	f, _ := New(Config{Timeout: 20 * time.Second, TLSRootCAs: pool})
	report, err := f.Survey(context.Background(), baseURL)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := RenderReport(&b, report); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"FAIRY SURVEY", "Target:", "DNS", "PASS", "Finding:"} {
		if !strings.Contains(out, want) {
			t.Errorf("console output missing %q\n%s", want, out)
		}
	}
}
