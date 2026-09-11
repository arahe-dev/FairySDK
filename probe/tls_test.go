package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// tlsServer starts a TLS server on 127.0.0.1:0 that handshakes and then
// closes the connection. Returns addr and the cert's root pool.
func tlsServer(t *testing.T, nextProtos []string) (string, *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t, []string{"localhost"}, net.IPv4(127, 0, 0, 1))
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   nextProtos,
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := c.(*tls.Conn)
			_ = tc.Handshake()
			_ = tc.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), pool
}

func TestTLSSuccess(t *testing.T) {
	addr, pool := tlsServer(t, []string{"h2", "http/1.1"})
	tgt := expTarget(t, "https://localhost:"+portOf(addr))
	e := model.NewTLSExperiment(tgt, model.IPv4, "", "")
	o := (&TLS{RootCAs: pool}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	for _, kind := range []string{model.KindCertificate, model.KindTLSVersion, model.KindCipherSuite, model.KindALPNSelected} {
		if _, ok := o.FirstEvidenceOf(kind); !ok {
			t.Errorf("missing %s evidence: %+v", kind, o.Evidence)
		}
	}
	ev, _ := o.FirstEvidenceOf(model.KindALPNSelected)
	if ev.Values["protocol"] != "h2" {
		t.Fatalf("alpn = %v, want h2", ev.Values["protocol"])
	}
	certEv, _ := o.FirstEvidenceOf(model.KindCertificate)
	if names, _ := model.AsStrings(certEv.Values["dns_names"]); len(names) == 0 || names[0] != "localhost" {
		t.Fatalf("cert dns_names = %v", certEv.Values["dns_names"])
	}
}

func TestTLSWrongHostname(t *testing.T) {
	addr, pool := tlsServer(t, []string{"h2", "http/1.1"})
	tgt := expTarget(t, "https://localhost:"+portOf(addr))
	e := model.NewTLSExperiment(tgt, model.IPv4, "", "wrong.example.com")
	o := (&TLS{RootCAs: pool}).Run(context.Background(), e)
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	ev, ok := o.FirstEvidenceOf(model.KindCertificate)
	if !ok {
		t.Fatalf("missing certificate evidence: %+v", o.Evidence)
	}
	if ev.Values["type"] != "hostname_mismatch" {
		t.Fatalf("type = %v, want hostname_mismatch", ev.Values["type"])
	}
}

func TestTLSTimeout(t *testing.T) {
	// A raw TCP listener that accepts but never speaks TLS: the
	// handshake hangs until the budget expires.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				time.Sleep(5 * time.Second)
				_ = c.Close()
			}(c)
		}
	}()

	tgt := expTarget(t, "https://localhost:"+portOf(ln.Addr().String()))
	e := model.NewTLSExperiment(tgt, model.IPv4, "", "")
	ctx, cancel := shortCtx(t, 300*time.Millisecond)
	defer cancel()
	o := (&TLS{}).Run(ctx, e)
	if o.Status != model.Timeout {
		t.Fatalf("status = %s, want timeout", o.Status)
	}
	if _, ok := o.FirstEvidenceOf(model.KindTimeout); !ok {
		t.Fatalf("missing timeout evidence: %+v", o.Evidence)
	}
}

func portOf(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}
