// Package infer turns observations into findings. Inference is separate
// from probes and strictly evidence-first: a finding always names its
// confidence and the observations that support it, and it never claims
// more than the evidence shows — "TCP timed out" becomes
// tcp_unreachable, never "firewall blocked this".
package infer

import (
	"fmt"
	"strings"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// Finding kinds produced by Infer.
const (
	KindDNSFailure              = "dns_failure"
	KindIPv6PathFailure         = "ipv6_path_failure"
	KindTCPUnreachable          = "tcp_unreachable"
	KindTLSSpecificFailure      = "tls_specific_failure"
	KindUDPUnavailable          = "udp_unavailable"
	KindQUICUnavailable         = "quic_unavailable"
	KindHTTPApplicationRejection = "http_application_rejection"
	KindPossibleProxyInterference = "possible_proxy_interference"
	KindPathHealthy             = "path_healthy"
)

// Describe returns a short human-readable sentence for a finding kind.
func Describe(kind string) string {
	switch kind {
	case KindDNSFailure:
		return "Name resolution failed"
	case KindIPv6PathFailure:
		return "IPv6 path fails while IPv4 works"
	case KindTCPUnreachable:
		return "TCP connection to the target fails"
	case KindTLSSpecificFailure:
		return "TLS handshake fails after TCP succeeds"
	case KindUDPUnavailable:
		return "UDP transport unanswered or unavailable"
	case KindQUICUnavailable:
		return "QUIC unavailable on this path"
	case KindHTTPApplicationRejection:
		return "The HTTP application rejects the request"
	case KindPossibleProxyInterference:
		return "Inconsistent path results suggest possible proxy interference"
	case KindPathHealthy:
		return "All probed layers passed"
	default:
		return kind
	}
}

// Infer derives findings from a survey state. It is pure: the same state
// always produces the same findings.
func Infer(state model.SurveyState) []model.Finding {
	if len(state.Observations) == 0 {
		return nil
	}
	var out []model.Finding
	add := func(kind string, conf model.Confidence, obs ...*model.Observation) {
		f := model.Finding{Kind: kind, Confidence: conf, Evidence: []string{}}
		for _, o := range obs {
			if o != nil {
				f.Evidence = append(f.Evidence, evidenceLine(*o))
			}
		}
		out = append(out, f)
	}

	dns := pick(state, model.LayerDNS, "")

	// DNS failure short-circuits the rest: nothing downstream is meaningful.
	if dns != nil && dns.Status != model.Pass {
		conf := model.Likely
		if rcode := dnsRcode(dns); rcode == "NXDOMAIN" || rcode == "SERVFAIL" {
			conf = model.Confirmed
		}
		add(KindDNSFailure, conf, dns)
		return out
	}

	tcp4 := pick(state, model.LayerTCP, model.IPv4)
	tcp6 := pick(state, model.LayerTCP, model.IPv6)
	tcpPass4 := tcp4 != nil && tcp4.Status == model.Pass
	tcpPass6 := tcp6 != nil && tcp6.Status == model.Pass
	tcpPassAny := tcpPass4 || tcpPass6

	// All attempted TCP connects failed.
	if tcpAllFailed(state) {
		conf := model.Likely
		for _, o := range layerObs(state, model.LayerTCP) {
			if _, ok := o.FirstEvidenceOf(model.KindTCPRefused); ok {
				conf = model.Confirmed
			}
		}
		add(KindTCPUnreachable, conf, tcp4, tcp6)
		return out
	}

	// IPv6 fails where IPv4 works: TCP, TLS and QUIC pairs.
	if familyPairFails(state, tcp4, tcp6) {
		add(KindIPv6PathFailure, model.Likely, tcp6, tcp4)
	} else {
		tls4 := pick(state, model.LayerTLS, model.IPv4)
		tls6 := pick(state, model.LayerTLS, model.IPv6)
		if familyPairFails(state, tls4, tls6) {
			add(KindIPv6PathFailure, model.Likely, tls6, tls4)
		} else {
			q4 := pick(state, model.LayerQUIC, model.IPv4)
			q6 := pick(state, model.LayerQUIC, model.IPv6)
			if familyPairFails(state, q4, q6) {
				add(KindIPv6PathFailure, model.Likely, q6, q4)
			}
		}
	}

	// TLS-specific failure: TCP passed but TLS failed on the same family.
	for _, fam := range []model.IPFamily{model.IPv4, model.IPv6} {
		tcp := pick(state, model.LayerTCP, fam)
		tls := pick(state, model.LayerTLS, fam)
		if tcp == nil || tcp.Status != model.Pass || tls == nil || tls.Status == model.Pass || tls.Status == model.Skipped {
			continue
		}
		conf := model.Likely
		if _, ok := tls.FirstEvidenceOf(model.KindTLSAlert); ok {
			conf = model.Confirmed
		}
		if _, ok := tls.FirstEvidenceOf(model.KindCertificate); ok {
			conf = model.Confirmed
		}
		add(KindTLSSpecificFailure, conf, tcp, tls)
		// A mid-handshake reset with no TLS alert, or a certificate
		// signed by an authority the system does not know, are the two
		// classic interception signatures — still only "possible":
		// both have innocent explanations (broken server, expired
		// misconfigured certificate).
		if _, ok := tls.FirstEvidenceOf(model.KindTCPReset); ok {
			add(KindPossibleProxyInterference, model.Possible, tcp, tls)
		}
		if ev, ok := tls.FirstEvidenceOf(model.KindCertificate); ok {
			if ev.Values["type"] == "unknown_authority" {
				add(KindPossibleProxyInterference, model.Possible, tcp, tls)
			}
		}
	}

	// UDP transport. Skipped observations mean "never probed" (a
	// prerequisite was missing), which is not evidence of failure.
	if udp := pick(state, model.LayerUDP, ""); udp != nil && udp.Status != model.Pass && udp.Status != model.Skipped {
		conf := model.Possible
		if udp.Status == model.Fail {
			conf = model.Confirmed
		}
		add(KindUDPUnavailable, conf, udp)
	}

	// QUIC unavailable.
	if quic := pick(state, model.LayerQUIC, ""); quic != nil && quic.Status != model.Pass && quic.Status != model.Skipped {
		conf := model.Possible
		if tcpPassAny {
			conf = model.Likely
		}
		if _, ok := quic.FirstEvidenceOf(model.KindUDPRefused); ok {
			conf = model.Confirmed
		}
		add(KindQUICUnavailable, conf, quic)
	}

	// HTTP application rejection: only when the server answered with a
	// 4xx/5xx (transport timeouts are not application rejections).
	for _, fam := range []model.IPFamily{model.IPv4, model.IPv6} {
		http := pick(state, model.LayerHTTP, fam)
		if http == nil || http.Status != model.Fail {
			continue
		}
		if ev, ok := http.FirstEvidenceOf(model.KindHTTPStatus); ok {
			if code, ok := model.AsInt(ev.Values["status"]); ok && code >= 400 {
				add(KindHTTPApplicationRejection, model.Confirmed, http)
			}
		}
	}

	// A healthy path when everything probed passed.
	if dns != nil && dns.Status == model.Pass && tcpPassAny && len(out) == 0 && passCount(state) >= 3 {
		var supporting []*model.Observation
		for i := range state.Observations {
			if state.Observations[i].Status == model.Pass {
				supporting = append(supporting, &state.Observations[i])
			}
		}
		add(KindPathHealthy, model.Confirmed, supporting...)
	}
	return out
}

// dnsRcode extracts the rcode label from DNS error evidence, if present.
func dnsRcode(o *model.Observation) string {
	ev, ok := o.FirstEvidenceOf(model.KindDNSError)
	if !ok {
		return ""
	}
	rc, _ := ev.Values["rcode"].(string)
	return rc
}

// pick returns the preferred observation for a layer and (optionally)
// address family. The canonical (default-variant) experiment wins over
// later follow-up variants: an adaptive SNI/ALPN variant that happens to
// pass must not erase the verdict of the default experiment, and a
// variant that fails must not be reported as the layer's normal result.
// Without a canonical observation the most recent one is used.
func pick(state model.SurveyState, layer model.Layer, family model.IPFamily) *model.Observation {
	var fallback *model.Observation
	for i := len(state.Observations) - 1; i >= 0; i-- {
		o := &state.Observations[i]
		if o.Layer != layer {
			continue
		}
		if family != "" && o.Experiment.IPFamily != family {
			continue
		}
		if isCanonicalExperiment(o.Experiment) {
			return o
		}
		if fallback == nil {
			fallback = o
		}
	}
	return fallback
}

// isCanonicalExperiment reports whether an experiment is the default
// variant for its layer, i.e. the one an ordinary tree survey runs:
// system resolver for DNS, no SNI/ALPN overrides for TCP/TLS/HTTP, and
// the standard h3 ALPN for QUIC.
func isCanonicalExperiment(e model.Experiment) bool {
	if e.SNI != "" {
		return false
	}
	switch e.Layer {
	case model.LayerDNS:
		return e.Resolver == model.ResolverSystem || e.Resolver == ""
	case model.LayerTLS, model.LayerHTTP, model.LayerTCP:
		return e.ALPN == ""
	case model.LayerQUIC:
		return e.ALPN == "" || e.ALPN == "h3"
	default:
		return e.ALPN == ""
	}
}

func layerObs(state model.SurveyState, layer model.Layer) []model.Observation {
	var out []model.Observation
	for _, o := range state.Observations {
		if o.Layer == layer {
			out = append(out, o)
		}
	}
	return out
}

// tcpAllFailed reports whether at least one TCP connect was attempted and
// none passed (Skipped observations are not attempts).
func tcpAllFailed(state model.SurveyState) bool {
	obs := layerObs(state, model.LayerTCP)
	attempted := false
	for _, o := range obs {
		if o.Status == model.Skipped || o.Status == model.Unknown {
			continue
		}
		attempted = true
		if o.Status == model.Pass {
			return false
		}
	}
	return attempted
}

// familyPairFails reports whether an IPv6 experiment failed while its
// IPv4 twin passed.
func familyPairFails(state model.SurveyState, v4, v6 *model.Observation) bool {
	return v4 != nil && v4.Status == model.Pass &&
		v6 != nil && (v6.Status == model.Fail || v6.Status == model.Timeout)
}

func passCount(state model.SurveyState) int {
	n := 0
	for _, o := range state.Observations {
		if o.Status == model.Pass {
			n++
		}
	}
	return n
}

// evidenceLine renders one observation as a stable human-readable
// evidence string referencing the experiment ID.
func evidenceLine(o model.Observation) string {
	label := string(o.Experiment.Layer)
	if o.Experiment.Target.Port != 0 && o.Experiment.Layer != model.LayerDNS && o.Experiment.Layer != model.LayerTLS {
		label = fmt.Sprintf("%s/%d", label, o.Experiment.Target.Port)
	}
	if o.Experiment.IPFamily == model.IPv6 {
		label += " v6"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", label, strings.ToUpper(string(o.Status)))
	if d := o.Duration.Truncate(time.Millisecond); d > 0 {
		fmt.Fprintf(&b, " %s", d)
	}
	if o.Error != "" {
		fmt.Fprintf(&b, " (%s)", o.Error)
	}
	fmt.Fprintf(&b, " [%s]", o.Experiment.ID)
	return b.String()
}
