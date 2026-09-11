package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arahe-dev/fairy/internal/model"
)

// dnsServer starts a local UDP DNS server on 127.0.0.1:0 and returns its
// "host:port" address.
func dnsServer(t *testing.T, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func dnsSuccessHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.IPv6loopback,
			})
		}
		_ = w.WriteMsg(m)
	})
}

func TestDNSSuccessViaPublicResolver(t *testing.T) {
	addr := dnsServer(t, dnsSuccessHandler())
	tgt := expTarget(t, "https://srv.test.invalid") // server replies regardless of name
	e := model.NewDNSExperiment(tgt, model.ResolverPublic)
	p := &DNS{PublicServer: addr}
	o := p.Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s), evidence: %+v", o.Status, o.Error, o.Evidence)
	}
	ev, ok := o.FirstEvidenceOf(model.KindDNSAnswer)
	if !ok {
		t.Fatal("missing dns_answer evidence")
	}
	v4, _ := model.AsStrings(ev.Values["v4"])
	if len(v4) != 1 || v4[0] != "127.0.0.1" {
		t.Fatalf("v4 = %v, want [127.0.0.1]", v4)
	}
	v6, _ := model.AsStrings(ev.Values["v6"])
	if len(v6) != 1 {
		t.Fatalf("v6 = %v, want [::1]", v6)
	}
}

func TestDNSNXDOMAIN(t *testing.T) {
	addr := dnsServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		_ = w.WriteMsg(m)
	}))
	tgt := expTarget(t, "https://missing.test.invalid")
	e := model.NewDNSExperiment(tgt, model.ResolverPublic)
	o := (&DNS{PublicServer: addr}).Run(context.Background(), e)
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	ev, ok := o.FirstEvidenceOf(model.KindDNSError)
	if !ok || ev.Values["rcode"] != "NXDOMAIN" {
		t.Fatalf("evidence = %+v", o.Evidence)
	}
}

func TestDNSSERVFAIL(t *testing.T) {
	addr := dnsServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}))
	tgt := expTarget(t, "https://broken.test.invalid")
	e := model.NewDNSExperiment(tgt, model.ResolverPublic)
	o := (&DNS{PublicServer: addr}).Run(context.Background(), e)
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	if ev, ok := o.FirstEvidenceOf(model.KindDNSError); !ok || ev.Values["rcode"] != "SERVFAIL" {
		t.Fatalf("evidence = %+v", o.Evidence)
	}
}

func TestDNSTimeout(t *testing.T) {
	// A server that receives queries but never answers.
	addr := dnsServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {}))
	tgt := expTarget(t, "https://silent.test.invalid")
	e := model.NewDNSExperiment(tgt, model.ResolverPublic)
	ctx, cancel := shortCtx(t, 300*time.Millisecond)
	defer cancel()
	o := (&DNS{PublicServer: addr}).Run(ctx, e)
	if o.Status != model.Timeout {
		t.Fatalf("status = %s, want timeout", o.Status)
	}
	if _, ok := o.FirstEvidenceOf(model.KindTimeout); !ok {
		t.Fatalf("missing timeout evidence: %+v", o.Evidence)
	}
}

func TestDNSSystemResolverLocalhost(t *testing.T) {
	tgt := expTarget(t, "https://localhost")
	e := model.NewDNSExperiment(tgt, model.ResolverSystem)
	o := (&DNS{}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	ev, _ := o.FirstEvidenceOf(model.KindDNSAnswer)
	v4, _ := model.AsStrings(ev.Values["v4"])
	if len(v4) == 0 {
		t.Fatalf("localhost should resolve to an IPv4 loopback: %+v", ev.Values)
	}
	if !strings.HasPrefix(v4[0], "127.") {
		t.Fatalf("unexpected v4 %q", v4[0])
	}
}

func TestDNSFamilyFilter(t *testing.T) {
	addr := dnsServer(t, dnsSuccessHandler())
	tgt := expTarget(t, "https://v6only.test.invalid")
	e := model.NewDNSExperiment(tgt, model.ResolverPublic)
	e.IPFamily = model.IPv6
	o := (&DNS{PublicServer: addr}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	ev, _ := o.FirstEvidenceOf(model.KindDNSAnswer)
	if v4, _ := model.AsStrings(ev.Values["v4"]); len(v4) != 0 {
		t.Fatalf("ipv6 experiment must not return v4 answers: %+v", ev.Values)
	}
	if v6, _ := model.AsStrings(ev.Values["v6"]); len(v6) == 0 {
		t.Fatalf("missing v6 answers: %+v", ev.Values)
	}
	_ = errors.Is // keep errors import if assertions evolve
}
