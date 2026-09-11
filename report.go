package fairy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/arahe-dev/fairy/infer"
	"github.com/arahe-dev/fairy/internal/model"
)

// Report is the final output of a survey.
type Report = model.Report

// Finding is an inference drawn from one or more observations, with a
// confidence level and the evidence that supports it.
type Finding = model.Finding

// Confidence expresses how strongly evidence supports a finding.
type Confidence = model.Confidence

const (
	Confirmed            Confidence = model.Confirmed
	Likely               Confidence = model.Likely
	Possible             Confidence = model.Possible
	InsufficientEvidence Confidence = model.InsufficientEvidence
)

// Finding kinds reported by the inference layer.
const (
	KindDNSFailure                = infer.KindDNSFailure
	KindIPv6PathFailure           = infer.KindIPv6PathFailure
	KindTCPUnreachable            = infer.KindTCPUnreachable
	KindTLSSpecificFailure        = infer.KindTLSSpecificFailure
	KindUDPUnavailable            = infer.KindUDPUnavailable
	KindQUICUnavailable           = infer.KindQUICUnavailable
	KindHTTPApplicationRejection  = infer.KindHTTPApplicationRejection
	KindPossibleProxyInterference = infer.KindPossibleProxyInterference
	KindPartialAddressFailure     = infer.KindPartialAddressFailure
	KindPathHealthy               = infer.KindPathHealthy
)

// RenderReport writes the human-readable console form of a report.
func RenderReport(w io.Writer, r *Report) error {
	if r == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("FAIRY SURVEY\n\n")
	b.WriteString("Target: " + displayURL(r.Target) + "\n\n")
	for _, o := range r.Observations {
		marker := ""
		if o.PartialAddressFailure() {
			passed, failed := o.AddressTally()
			marker = fmt.Sprintf("  [%d/%d addresses failed]", failed, passed+failed)
		}
		fmt.Fprintf(&b, "%-14s %-9s %s%s\n", obsLabel(o), statusText(o.Status), outcomeText(o), marker)
	}
	b.WriteString("\n")
	for _, f := range r.Findings {
		b.WriteString("Finding:\n")
		fmt.Fprintf(&b, "  %s\n", infer.Describe(f.Kind))
		fmt.Fprintf(&b, "  Confidence: %s\n", f.Confidence)
		if len(f.Evidence) > 0 {
			b.WriteString("  Evidence:\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(&b, "    - %s\n", e)
			}
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// RenderReportJSON writes the JSON form of a report.
func RenderReportJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// obsLabel renders the line label for an observation, e.g. "TCP/443" or
// "HTTP/2".
func obsLabel(o Observation) string {
	e := o.Experiment
	label := ""
	switch e.Layer {
	case LayerDNS:
		return "DNS"
	case LayerTCP:
		label = fmt.Sprintf("TCP/%d", e.Target.Port)
	case LayerTLS:
		switch {
		case e.SNI == SNINone:
			label = "TLS(no-sni)"
		case e.SNI != "":
			label = "TLS(sni)"
		default:
			label = "TLS"
		}
	case LayerHTTP:
		if proto, ok := protoOf(o); ok && strings.Contains(proto, "2") {
			label = "HTTP/2"
		} else {
			label = "HTTP"
		}
	case LayerUDP:
		label = fmt.Sprintf("UDP/%d", e.Target.Port)
	case LayerQUIC:
		label = "QUIC"
	default:
		label = strings.ToUpper(string(e.Layer))
	}
	if e.IPFamily == IPv6 {
		label += " (v6)"
	}
	return label
}

// displayURL renders the target for humans, hiding the implicit default
// port that ParseTarget adds for canonical experiment IDs.
func displayURL(t Target) string {
	if t.URL == nil {
		return t.String()
	}
	u := *t.URL
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		host := u.Hostname()
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
	}
	return u.String()
}

// protoOf extracts the negotiated protocol from HTTP evidence.
func protoOf(o Observation) (string, bool) {
	if ev, ok := o.FirstEvidenceOf(KindHTTPStatus); ok {
		if p, ok := ev.Values["proto"].(string); ok && p != "" {
			return p, true
		}
	}
	if ev, ok := o.FirstEvidenceOf(KindALPNSelected); ok {
		if p, ok := ev.Values["protocol"].(string); ok && p != "" {
			return p, true
		}
	}
	return "", false
}

func statusText(s Status) string {
	switch s {
	case Pass:
		return "PASS"
	case Fail:
		return "FAIL"
	case Timeout:
		return "TIMEOUT"
	case Skipped:
		return "SKIPPED"
	default:
		return "UNKNOWN"
	}
}

// outcomeText renders the third column: the duration on success, the
// error category on failure.
func outcomeText(o Observation) string {
	if o.Status == Pass || o.Status == Skipped {
		if o.Duration > 0 {
			return durationText(o.Duration)
		}
		return "-"
	}
	if o.Error != "" {
		return o.Error
	}
	if o.Duration > 0 {
		return durationText(o.Duration)
	}
	return "-"
}

func durationText(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
