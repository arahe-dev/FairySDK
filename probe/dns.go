package probe

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/arahe-dev/fairy/internal/model"
)

// DNS probes name resolution. The system resolver path uses
// net.Resolver; ResolverPublic mode uses an explicit UDP resolver
// (miekg/dns) for comparisons. DoH/DoT are out of scope for V0.
type DNS struct {
	// PublicServer overrides the resolver used for ResolverPublic mode
	// ("host:port"). Empty means model.DefaultPublicResolver.
	PublicServer string
}

// Run performs one DNS experiment and records structured evidence:
// resolved addresses, rcode, latency, IPv4/IPv6 presence, NXDOMAIN,
// SERVFAIL and timeouts.
func (p *DNS) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)
	if e.Resolver == model.ResolverPublic {
		p.runPublic(ctx, e, &o, start)
	} else {
		p.runSystem(ctx, e, &o, start)
	}
	o.Duration = time.Since(start)
	return o
}

func (p *DNS) runSystem(ctx context.Context, e model.Experiment, o *model.Observation, start time.Time) {
	family := "ip4"
	switch e.IPFamily {
	case model.IPv6:
		family = "ip6"
	case model.FamilyAny:
		family = "ip"
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, family, e.Target.Host)
	if err != nil {
		fillDNSError(o, err, start)
		return
	}
	var v4, v6 []string
	for _, a := range addrs {
		un := a.Unmap()
		if un.Is4() {
			v4 = append(v4, un.String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	if len(v4)+len(v6) == 0 {
		o.Status = model.Fail
		o.Error = "no addresses returned"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "NOERROR", "note": "no answers"})
		return
	}
	o.Status = model.Pass
	o.AddEvidence(model.KindDNSAnswer, map[string]any{
		"v4":         v4,
		"v6":         v6,
		"rcode":      "NOERROR",
		"resolver":   "system",
		"latency_ms": ms(time.Since(start)),
	})
}

func (p *DNS) runPublic(ctx context.Context, e model.Experiment, o *model.Observation, start time.Time) {
	server := p.PublicServer
	if server == "" {
		server = model.DefaultPublicResolver
	}
	client := &dns.Client{Net: "udp", Timeout: remaining(ctx, model.Budget(model.LayerDNS))}

	wantA, wantAAAA := true, true
	switch e.IPFamily {
	case model.IPv4:
		wantAAAA = false
	case model.IPv6:
		wantA = false
	}

	var v4, v6 []string
	rcode := "NOERROR"
	var lastErr error
	for _, q := range []struct {
		qtype uint16
		want  bool
		store *[]string
	}{
		{dns.TypeA, wantA, &v4},
		{dns.TypeAAAA, wantAAAA, &v6},
	} {
		if !q.want {
			continue
		}
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(e.Target.Host), q.qtype)
		msg.RecursionDesired = true
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		rcode = dns.RcodeToString[resp.Rcode]
		if resp.Rcode != dns.RcodeSuccess {
			fillDNSRcode(o, rcode)
			return
		}
		for _, rr := range resp.Answer {
			switch rec := rr.(type) {
			case *dns.A:
				*q.store = append(*q.store, rec.A.String())
			case *dns.AAAA:
				*q.store = append(*q.store, rec.AAAA.String())
			}
		}
	}
	if lastErr != nil {
		fillDNSError(o, lastErr, start)
		return
	}
	if len(v4)+len(v6) == 0 {
		o.Status = model.Fail
		o.Error = "no addresses returned"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": rcode, "note": "no answers", "server": server})
		return
	}
	o.Status = model.Pass
	o.AddEvidence(model.KindDNSAnswer, map[string]any{
		"v4":         v4,
		"v6":         v6,
		"rcode":      rcode,
		"resolver":   "public",
		"server":     server,
		"latency_ms": ms(time.Since(start)),
	})
}

// fillDNSError converts a resolver error into status + evidence.
func fillDNSError(o *model.Observation, err error, start time.Time) {
	var dnsErr *net.DNSError
	if isTimeout(err) || (errors.As(err, &dnsErr) && dnsErr.IsTimeout) {
		o.Status = model.Timeout
		o.Error = "dns lookup timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerDNS)})
		return
	}
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			o.Status = model.Fail
			o.Error = "name not found (NXDOMAIN)"
			o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "NXDOMAIN"})
		case dnsErr.IsTemporary:
			o.Status = model.Fail
			o.Error = "resolver temporary failure (SERVFAIL)"
			o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "SERVFAIL"})
		default:
			o.Status = model.Fail
			o.Error = err.Error()
			o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "ERROR", "error": err.Error()})
		}
		return
	}
	o.Status = model.Unknown
	o.Error = err.Error()
	o.AddEvidence(model.KindDNSError, map[string]any{"error": err.Error()})
}

// fillDNSRcode records a non-NOERROR rcode from an explicit resolver.
func fillDNSRcode(o *model.Observation, rcode string) {
	o.Status = model.Fail
	switch rcode {
	case "NXDOMAIN":
		o.Error = "name not found (NXDOMAIN)"
	case "SERVFAIL":
		o.Error = "resolver temporary failure (SERVFAIL)"
	default:
		o.Error = "dns " + rcode
	}
	o.AddEvidence(model.KindDNSError, map[string]any{"rcode": rcode})
}
