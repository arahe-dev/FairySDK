package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

func TestHTTP200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fairy-test")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	o := (&HTTP{}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	ev, ok := o.FirstEvidenceOf(model.KindHTTPStatus)
	if !ok {
		t.Fatal("missing http_status evidence")
	}
	if code, _ := model.AsInt(ev.Values["status"]); code != 200 {
		t.Fatalf("status = %v, want 200", ev.Values["status"])
	}
	if ev.Values["proto"] != "HTTP/1.1" {
		t.Fatalf("proto = %v", ev.Values["proto"])
	}
	if ev.Values["server"] != "fairy-test" {
		t.Fatalf("server header not captured: %v", ev.Values)
	}
}

func TestHTTPRedirectNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/there", http.StatusFound)
	}))
	defer srv.Close()

	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	o := (&HTTP{}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	ev, _ := o.FirstEvidenceOf(model.KindHTTPStatus)
	if code, _ := model.AsInt(ev.Values["status"]); code != 302 {
		t.Fatalf("status = %v, want 302", ev.Values["status"])
	}
	if ev.Values["location"] != "/there" {
		t.Fatalf("location = %v", ev.Values["location"])
	}
}

func TestHTTPApplicationRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	o := (&HTTP{}).Run(context.Background(), e)
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	ev, _ := o.FirstEvidenceOf(model.KindHTTPStatus)
	if code, _ := model.AsInt(ev.Values["status"]); code != 503 {
		t.Fatalf("status = %v, want 503", ev.Values["status"])
	}
}

func TestHTTPTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	ctx, cancel := shortCtx(t, 200*time.Millisecond)
	defer cancel()
	o := (&HTTP{}).Run(ctx, e)
	if o.Status != model.Timeout {
		t.Fatalf("status = %s, want timeout", o.Status)
	}
}

func TestHTTPOverTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("secure"))
	}))
	defer srv.Close()

	pool := TrustPool(srv)
	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	o := (&HTTP{RootCAs: pool}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
}

func TestHTTPWrongCertFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	tgt := expTarget(t, srv.URL)
	e := model.NewHTTPExperiment(tgt, model.IPv4, "")
	o := (&HTTP{}).Run(context.Background(), e) // no root pool: untrusted
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	if _, ok := o.FirstEvidenceOf(model.KindCertificate); !ok {
		t.Fatalf("missing certificate evidence: %+v", o.Evidence)
	}
}
