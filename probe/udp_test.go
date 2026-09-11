package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// udpEcho echoes every datagram back to its sender.
func udpEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func TestUDPEcho(t *testing.T) {
	addr := udpEcho(t)
	port := portOf(addr)
	tgt := expTarget(t, "https://127.0.0.1:"+port)
	e := model.NewUDPExperiment(tgt, model.IPv4, 16)
	o := (&UDP{}).Run(context.Background(), e)
	if o.Status != model.Pass {
		t.Fatalf("status = %s (%s)", o.Status, o.Error)
	}
	if _, ok := o.FirstEvidenceOf(model.KindUDPResponse); !ok {
		t.Fatalf("missing udp_response evidence: %+v", o.Evidence)
	}
}

func TestUDPSilenceIsTimeout(t *testing.T) {
	// A bound socket that never answers. Silence is not "blocked":
	// the honest verdict is Timeout, and inference treats it as
	// insufficient evidence.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	tgt := expTarget(t, "https://127.0.0.1:"+portOf(pc.LocalAddr().String()))
	e := model.NewUDPExperiment(tgt, model.IPv4, 16)
	ctx, cancel := shortCtx(t, 300*time.Millisecond)
	defer cancel()
	o := (&UDP{}).Run(ctx, e)
	if o.Status != model.Timeout {
		t.Fatalf("status = %s (%s), want timeout", o.Status, o.Error)
	}
}

func TestUDPRefusedOnClosedPort(t *testing.T) {
	// Bind a UDP socket, learn its port, close it: ICMP port
	// unreachable should surface as a refusal (platform dependent —
	// some stacks only report it as silence, which is Timeout).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portOf(pc.LocalAddr().String())
	_ = pc.Close()

	tgt := expTarget(t, "https://127.0.0.1:"+port)
	e := model.NewUDPExperiment(tgt, model.IPv4, 16)
	ctx, cancel := shortCtx(t, 700*time.Millisecond)
	defer cancel()
	o := (&UDP{}).Run(ctx, e)
	if o.Status != model.Fail && o.Status != model.Timeout {
		t.Fatalf("status = %s (%s), want fail or timeout", o.Status, o.Error)
	}
}
