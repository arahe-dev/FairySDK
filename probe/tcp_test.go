package probe

import (
	"context"
	"strconv"
	"syscall"
	"net"
	"testing"
	"time"

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
