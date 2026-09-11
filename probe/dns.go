package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
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

// runSystem resolves via the OS resolver. Address families are queried
// separately so that a broken or filtered AAAA path never corrupts the
// verdict for A records (and vice versa): some networks answer A
// normally while returning "no data" or even NXDOMAIN for AAAA, which a
// single merged lookup collapses into a misleading "name not found".
func (p *DNS) runSystem(ctx context.Context, e model.Experiment, o *model.Observation, start time.Time) {
	if e.IPFamily != model.FamilyAny {
		family := "ip4"
		if e.IPFamily == model.IPv6 {
			family = "ip6"
		}
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, family, e.Target.Host)
		if err != nil {
			fillDNSError(o, err, start)
			return
		}
		fam := model.IPv4
		if e.IPFamily == model.IPv6 {
			fam = model.IPv6
		}
		fillSystemAnswer(o, familyAddrs(addrs, fam), nil, nil, start)
		return
	}

	// Family "any": query both families independently.
	v4, err4 := net.DefaultResolver.LookupNetIP(ctx, "ip4", e.Target.Host)
	v6, err6 := net.DefaultResolver.LookupNetIP(ctx, "ip6", e.Target.Host)

	v4s, v6s := familyAddrs(v4, model.IPv4), familyAddrs(v6, model.IPv6)
	var v4Label, v6Label any
	if err4 != nil {
		v4Label = mapDNSError(err4)
	}
	if err6 != nil {
		v6Label = mapDNSError(err6)
	}

	if len(v4s)+len(v6s) == 0 {
		// Both requested families failed: classify the pair honestly.
		o.Status = model.Fail
		rcode, note := combineFamilyErrors(err4, err6)
		o.Error = note
		o.AddEvidence(model.KindDNSError, map[string]any{
			"rcode":    rcode,
			"note":     note,
			"v4_error": v4Label,
			"v6_error": v6Label,
		})
		return
	}
	fillSystemAnswer(o, v4s, v6s, map[string]any{"v4_error": v4Label, "v6_error": v6Label}, start)
}

// familyAddrs converts resolver addresses into strings for one family.
// IPv4 literals and some platform resolvers surface IPv4 addresses in
// 4-in-6 form (::ffff:a.b.c.d), so every address is unmapped first.
func familyAddrs(addrs []netip.Addr, family model.IPFamily) []string {
	var out []string
	for _, a := range addrs {
		a = a.Unmap()
		if family == model.IPv6 {
			if a.Is6() {
				out = append(out, a.String())
			}
			continue
		}
		if a.Is4() {
			out = append(out, a.String())
		}
	}
	return out
}

// fillSystemAnswer records a successful system-resolver answer.
func fillSystemAnswer(o *model.Observation, v4, v6 []string, extra map[string]any, start time.Time) {
	if len(v4)+len(v6) == 0 {
		o.Status = model.Fail
		o.Error = "no addresses returned"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "NOERROR", "note": "no answers"})
		return
	}
	o.Status = model.Pass
	vals := map[string]any{
		"v4":         v4,
		"v6":         v6,
		"rcode":      "NOERROR",
		"resolver":   "system",
		"latency_ms": ms(time.Since(start)),
	}
	for k, v := range extra {
		if v != nil {
			vals[k] = v
		}
	}
	o.AddEvidence(model.KindDNSAnswer, vals)
}

// combineFamilyErrors turns the per-family failure pair into an honest
// rcode + note. NXDOMAIN is only claimed when BOTH families were told
// the name does not exist; a "no data" answer means the name exists but
// has no records of the requested type (typical AAAA filtering).
func combineFamilyErrors(err4, err6 error) (rcode, note string) {
	l4, l6 := "ok", "ok"
	if err4 != nil {
		l4 = mapDNSError(err4)
	}
	if err6 != nil {
		l6 = mapDNSError(err6)
	}
	isNotFound := func(l string) bool { return l == "not_found" }
	isNoData := func(l string) bool { return l == "no_data" || l == "ok" }

	switch {
	case l4 == "timeout" || l6 == "timeout":
		return "TIMEOUT", "resolver query timed out"
	case l4 == "temporary" || l6 == "temporary":
		return "SERVFAIL", "resolver temporary failure (SERVFAIL)"
	case isNotFound(l4) && isNotFound(l6):
		return "NXDOMAIN", "name not found (NXDOMAIN)"
	case isNoData(l4) && isNoData(l6):
		// At least one family was told the name exists but has no
		// records of the requested type.
		return "NOERROR", "no usable addresses: resolver returned no data for the requested families (v4: " + l4 + ", v6: " + l6 + ")"
	default:
		return "ERROR", "resolver returned no usable addresses (v4: " + l4 + ", v6: " + l6 + ")"
	}
}

// mapDNSError labels a resolver error with a stable, honest category.
// Windows distinguishes "name not found" (WSAHOST_NOT_FOUND, reported
// as IsNotFound) from "name valid but no records of the requested type"
// (WSANO_DATA, IsNotFound=false); the pure Go resolver conflates both,
// so on other platforms "no_data" is detected only via the error text
// or inferred when the other family resolved the same name.
func mapDNSError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsTimeout:
			return "timeout"
		case dnsErr.IsTemporary:
			return "temporary"
		case dnsErr.IsNotFound:
			return "not_found"
		case strings.Contains(dnsErr.Err, "no data of the requested type"):
			return "no_data"
		default:
			return "error"
		}
	}
	return "error"
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
	if isTimeout(err) {
		o.Status = model.Timeout
		o.Error = "dns lookup timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerDNS)})
		return
	}
	switch mapDNSError(err) {
	case "not_found":
		o.Status = model.Fail
		o.Error = "name not found (NXDOMAIN)"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "NXDOMAIN"})
	case "no_data":
		o.Status = model.Fail
		o.Error = "no records of the requested type"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "NOERROR", "note": "resolver returned no data for the requested type"})
	case "temporary":
		o.Status = model.Fail
		o.Error = "resolver temporary failure (SERVFAIL)"
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "SERVFAIL"})
	default:
		o.Status = model.Fail
		o.Error = err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"rcode": "ERROR", "error": err.Error()})
	}
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
