package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/arahe-dev/fairy/internal/model"
)

// quicServer starts a local HTTP/3 server on 127.0.0.1:0 and returns its
// address plus a root pool trusting its certificate.
func quicServer(t *testing.T, handler http.Handler) (string, *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t, []string{"localhost"}, net.IPv4(127, 0, 0, 1))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler: handler,
	}
	go func() { _ = srv.Serve(pc) }()
	t.Cleanup(func() { _ = srv.Close() })
	return pc.LocalAddr().String(), pool
}

func TestQUICHTTP3Success(t *testing.T) {
	addr, pool := quicServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fairy-h3")
		_, _ = w.Write([]byte("quic"))
	}))
	tgt := expTarget(t, "https://localhost:"+portOf(addr))
	e := model.NewQUICExperiment(tgt, model.IPv4, "")
	o := (&QUIC{RootCAs: pool}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s), evidence: %+v", o.Status, o.Error, o.Evidence)
	}
	if _, ok := o.FirstEvidenceOf(model.KindQUICVersion); !ok {
		t.Fatalf("missing quic_version evidence: %+v", o.Evidence)
	}
	ev, ok := o.FirstEvidenceOf(model.KindHTTPStatus)
	if !ok {
		t.Fatalf("missing http_status evidence: %+v", o.Evidence)
	}
	if code, _ := model.AsInt(ev.Values["status"]); code != 200 {
		t.Fatalf("h3 status = %v, want 200", ev.Values["status"])
	}
	if h3, _ := ev.Values["h3"].(bool); !h3 {
		t.Fatalf("h3 flag missing: %v", ev.Values)
	}
	if alpn, ok := o.FirstEvidenceOf(model.KindALPNSelected); ok {
		if alpn.Values["protocol"] != "h3" {
			t.Fatalf("alpn = %v, want h3", alpn.Values["protocol"])
		}
	}
}

func TestQUICTimeoutOnSilentPort(t *testing.T) {
	// A bound UDP socket that never responds: the QUIC handshake hangs.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	tgt := expTarget(t, "https://localhost:"+portOf(pc.LocalAddr().String()))
	e := model.NewQUICExperiment(tgt, model.IPv4, "")
	ctx, cancel := shortCtx(t, 500*time.Millisecond)
	defer cancel()
	o := (&QUIC{}).Run(ctx, e)
	if o.Status != model.Timeout && o.Status != model.Fail {
		t.Fatalf("status = %s (%s), want timeout or fail", o.Status, o.Error)
	}
}

func TestQUICBadCertFails(t *testing.T) {
	addr, _ := quicServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tgt := expTarget(t, "https://localhost:"+portOf(addr))
	e := model.NewQUICExperiment(tgt, model.IPv4, "")
	o := (&QUIC{}).Run(context.Background(), e) // no root pool
	if o.Status != model.Fail {
		t.Fatalf("status = %s (%s), want fail", o.Status, o.Error)
	}
	// The chain may present as certificate verification evidence or as
	// the corresponding TLS alert (bad_certificate); both are honest.
	_, hasCert := o.FirstEvidenceOf(model.KindCertificate)
	alertEv, hasAlert := o.FirstEvidenceOf(model.KindTLSAlert)
	if !hasCert && !(hasAlert && alertEv.Values["alert"] == 42) {
		t.Fatalf("missing certificate/tls_alert evidence: %+v", o.Evidence)
	}
}
