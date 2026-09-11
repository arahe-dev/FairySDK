package probe

import (
	"context"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// TCP probes a TCP connect to the target port. The host is resolved
// first, then every resolved address of the requested family is dialed —
// the hostname passes if any address connects, and the outcome of each
// address is recorded, because one bad address out of several is a real
// defect that a first-address verdict would hide.
type TCP struct{}

// Run performs one TCP connect experiment.
func (p *TCP) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)
	conn, outcomes, err := connectAll(ctx, e, "tcp")
	o.Duration = time.Since(start)
	if err != nil {
		fillPrereq(&o, err)
		return o
	}
	o.Addresses = outcomes

	if conn != nil {
		defer conn.Close()
		o.Status = model.Pass
		o.AddEvidence(model.KindTCPConnect, map[string]any{
			"local_addr":  conn.LocalAddr().String(),
			"remote_addr": conn.RemoteAddr().String(),
			"latency_ms":  ms(o.Duration),
			"addresses":   len(outcomes),
		})
		return o
	}

	status, kind, text := aggregateStatus(outcomes)
	o.Status = status
	o.Error = text
	addFailureEvidence(&o, kind)
	return o
}
