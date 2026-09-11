package probe

import (
	"context"
	"errors"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// TCP probes a single TCP connect to the target port. The host is
// resolved first and the explicit IP is dialed, so family control works
// and routing stays separable from hostname-dependent behavior.
type TCP struct{}

// Run performs one TCP connect experiment.
func (p *TCP) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)
	conn, err := dialIP(ctx, e, "tcp")
	o.Duration = time.Since(start)
	if err != nil {
		fillConnError(ctx, &o, err, start)
		return o
	}
	defer conn.Close()
	o.Status = model.Pass
	o.AddEvidence(model.KindTCPConnect, map[string]any{
		"local_addr":  conn.LocalAddr().String(),
		"remote_addr": conn.RemoteAddr().String(),
		"latency_ms":  ms(o.Duration),
	})
	return o
}

// fillConnError classifies a connection-level error into status and
// structured evidence. Timeouts become Timeout; refusals and resets
// become Fail with their own evidence kinds.
func fillConnError(ctx context.Context, o *model.Observation, err error, start time.Time) {
	o.Duration = time.Since(start)
	var pe *prereqError
	if errors.As(err, &pe) {
		o.Status = model.Skipped
		o.Error = "dns resolution failed: " + pe.err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"error": pe.err.Error()})
		return
	}
	switch {
	case isRefused(err):
		o.Status = model.Fail
		o.Error = "connection refused"
		o.AddEvidence(model.KindTCPRefused, nil)
	case isReset(err):
		o.Status = model.Fail
		o.Error = "connection reset"
		o.AddEvidence(model.KindTCPReset, nil)
	case isTimeout(err):
		o.Status = model.Timeout
		o.Error = "timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(o.Layer)})
	case isCanceled(err):
		o.Status = model.Timeout
		o.Error = "canceled"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(o.Layer), "note": "context canceled"})
	default:
		o.Status = model.Unknown
		o.Error = err.Error()
	}
}
