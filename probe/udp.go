package probe

import (
	"context"
	"net"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// UDP performs a basic UDP reachability experiment. UDP has no universal
// response contract: silence is NOT evidence of blocking, so a silent
// endpoint yields Status Timeout with timeout evidence, and genuinely
// ambiguous errors yield Status Unknown. The inference layer treats UDP
// silence conservatively.
type UDP struct{}

// Run performs one UDP experiment: send a payload, wait briefly for any
// response.
func (p *UDP) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	ip, err := resolveFirst(ctx, e)
	if err != nil {
		o.Status = model.Skipped
		o.Error = "dns resolution failed: " + err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"error": err.Error()})
		o.Duration = time.Since(start)
		return o
	}
	raddr := &net.UDPAddr{IP: net.ParseIP(ip), Port: int(e.Target.Port)}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fillConnError(ctx, &o, err, start)
		return o
	}
	defer conn.Close()

	size := e.Payload
	if size <= 0 {
		size = 16
	}
	if size > 1400 {
		size = 1400
	}
	payload := make([]byte, size)

	deadline := time.Now().Add(remaining(ctx, model.Budget(model.LayerUDP)))
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		fillConnError(ctx, &o, err, start)
		return o
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	o.Duration = time.Since(start)
	if err != nil {
		switch {
		case isRefused(err) || isReset(err):
			// An ICMP port-unreachable surfaced on the connected socket.
			o.Status = model.Fail
			o.Error = "udp port unreachable"
			o.AddEvidence(model.KindUDPRefused, map[string]any{"port": int(e.Target.Port)})
		case isUnreachable(err):
			o.Status = model.Fail
			o.Error = "network unreachable (no route)"
			o.AddEvidence(model.KindNetworkUnreachable, nil)
		case isTimeout(err) || isCanceled(err):
			o.Status = model.Timeout
			o.Error = "no udp response"
			o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerUDP), "note": "no response"})
		default:
			o.Status = model.Unknown
			o.Error = err.Error()
		}
		return o
	}
	o.Status = model.Pass
	o.AddEvidence(model.KindUDPResponse, map[string]any{
		"bytes":      n,
		"remote":     raddr.String(),
		"latency_ms": ms(o.Duration),
	})
	return o
}
