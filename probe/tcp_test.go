package probe

import (
	"context"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/arahe-dev/fairy/internal/model"
)

func TestTCPConnect(t *testing.T) {
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
			_ = c.Close()
		}
	}()

	tgt := expTarget(t, "https://127.0.0.1:"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	ev, ok := o.FirstEvidenceOf(model.KindTCPConnect)
	if !ok {
		t.Fatal("missing tcp_connect evidence")
	}
	if ev.Values["remote_addr"] == "" {
		t.Fatalf("missing remote_addr: %+v", ev.Values)
	}
}

func TestTCPRefused(t *testing.T) {
	port := closedTCPPort(t)
	tgt := expTarget(t, "https://127.0.0.1:"+strconv.Itoa(port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)
	if o.Status != model.Fail {
		t.Fatalf("status = %s (%s), want fail", o.Status, o.Error)
	}
	if _, ok := o.FirstEvidenceOf(model.KindTCPRefused); !ok {
		t.Fatalf("missing tcp_refused evidence: %+v", o.Evidence)
	}
}

func TestTCPCanceled(t *testing.T) {
	port := closedTCPPort(t)
	tgt := expTarget(t, "https://127.0.0.1:"+strconv.Itoa(port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	o := (&TCP{}).Run(ctx, e)
	if o.Status != model.Timeout {
		t.Fatalf("status = %s, want timeout (cancellation is not a path failure)", o.Status)
	}
}

func TestTCPDurationRecorded(t *testing.T) {
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
			_ = c.Close()
		}
	}()
	tgt := expTarget(t, "https://127.0.0.1:"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)
	if o.Duration <= 0 && o.Duration != 0 {
		t.Fatalf("implausible duration %v", o.Duration)
	}
	if o.Duration > time.Second {
		t.Fatalf("connect took %v, too slow for loopback", o.Duration)
	}
}

// Regression: the kernel stating "network is unreachable" is definitive
// evidence (Status Fail with network_unreachable), never Unknown. This
// is what an IPv6-capable DNS answer on a v4-only path produces.
func TestTCPNetworkUnreachableIsFail(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}
	o := model.NewObservation(model.Experiment{Layer: model.LayerTCP}, model.Unknown, 0)
	fillConnError(context.Background(), &o, err, time.Now())
	if o.Status != model.Fail {
		t.Fatalf("status = %s, want fail", o.Status)
	}
	if _, ok := o.FirstEvidenceOf(model.KindNetworkUnreachable); !ok {
		t.Fatalf("missing network_unreachable evidence: %+v", o.Evidence)
	}
}

// multiAddrResolver serves a fixed set of A records for any name, so the
// multi-address behaviour can be tested against real sockets.
func multiAddrResolver(t *testing.T, ips ...net.IP) {
	t.Helper()
	fakeResolverAt(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			for _, ip := range ips {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   ip,
				})
			}
		}
		_ = w.WriteMsg(m)
	}))
}

// Regression for the objects.githubusercontent.com case: one address of
// several is dead while the others work. The hostname must PASS, and the
// failing address must be recorded — not silently dropped because it was
// not first in DNS order.
func TestTCPMultiAddressPartialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	// 127.0.0.1 has the listener; 127.0.0.2 is loopback with nothing on it.
	multiAddrResolver(t, net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2))

	tgt := expTarget(t, "https://multi.test.invalid:"+strconv.Itoa(port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)

	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s), want pass: one address works", o.Status, o.Error)
	}
	if len(o.Addresses) != 2 {
		t.Fatalf("want 2 recorded addresses, got %+v", o.Addresses)
	}
	if !o.PartialAddressFailure() {
		t.Fatalf("partial address failure not detected: %+v", o.Addresses)
	}
	if passed, failed := o.AddressTally(); passed != 1 || failed != 1 {
		t.Fatalf("tally = %d passed / %d failed, want 1/1", passed, failed)
	}
	if o.Addresses[0].IP != "127.0.0.1" || o.Addresses[0].Status != model.Pass {
		t.Fatalf("address order not deterministic: %+v", o.Addresses)
	}
	if o.Addresses[1].IP != "127.0.0.2" || o.Addresses[1].Status != model.Fail {
		t.Fatalf("dead address not classified: %+v", o.Addresses[1])
	}
}

// When every address fails the hostname fails, with the specific failure
// evidence preserved.
func TestTCPAllAddressesFail(t *testing.T) {
	multiAddrResolver(t, net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2))
	port := closedTCPPort(t)
	tgt := expTarget(t, "https://all-dead.test.invalid:"+strconv.Itoa(port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)

	if o.Status != model.Fail {
		t.Fatalf("status = %s (%s), want fail", o.Status, o.Error)
	}
	if _, ok := o.FirstEvidenceOf(model.KindTCPRefused); !ok {
		t.Fatalf("missing tcp_refused evidence: %+v", o.Evidence)
	}
	if len(o.Addresses) != 2 {
		t.Fatalf("want both addresses recorded, got %+v", o.Addresses)
	}
	if o.PartialAddressFailure() {
		t.Fatal("partial failure must not be reported when nothing passed")
	}
}

// A single-address hostname keeps the simple behaviour: one attempt, one
// outcome, no partial failure.
func TestTCPSingleAddressUnaffected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	multiAddrResolver(t, net.IPv4(127, 0, 0, 1))
	tgt := expTarget(t, "https://single.test.invalid:"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	e := model.NewTCPExperiment(tgt, model.IPv4)
	o := (&TCP{}).Run(context.Background(), e)
	if o.Status != model.Pass || len(o.Addresses) != 1 || o.PartialAddressFailure() {
		t.Fatalf("single address behaviour changed: status=%s addresses=%+v", o.Status, o.Addresses)
	}
}
