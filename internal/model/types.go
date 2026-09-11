// Package model defines the shared experiment model for FairySDK.
//
// These types live in an internal leaf package so that the probe, policy
// and inference packages can share them without creating import cycles.
// The public fairy package re-exports every type under its own namespace,
// so external users only ever import the root package.
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Layer identifies the protocol layer an experiment probes.
type Layer string

const (
	LayerDNS  Layer = "dns"
	LayerTCP  Layer = "tcp"
	LayerTLS  Layer = "tls"
	LayerHTTP Layer = "http"
	LayerUDP  Layer = "udp"
	LayerQUIC Layer = "quic"
)

// Status is the outcome of a single experiment.
type Status string

const (
	Pass    Status = "pass"
	Fail    Status = "fail"
	Timeout Status = "timeout"
	Skipped Status = "skipped"
	Unknown Status = "unknown"
)

// IPFamily selects the address family an experiment uses.
type IPFamily string

const (
	IPv4      IPFamily = "ipv4"
	IPv6      IPFamily = "ipv6"
	FamilyAny IPFamily = "any" // DNS only: query both A and AAAA records.
)

// Transport is the wire transport an experiment uses.
type Transport string

const (
	TCP  Transport = "tcp"
	UDP  Transport = "udp"
	QUIC Transport = "quic"
)

// ResolverMode selects how a DNS experiment resolves names.
type ResolverMode string

const (
	ResolverSystem ResolverMode = "system" // OS resolver via net.Resolver.
	ResolverPublic ResolverMode = "public" // Explicit public resolver via miekg/dns.
)

// DefaultPublicResolver is the server used for ResolverPublic mode.
const DefaultPublicResolver = "8.8.8.8:53"

// SNINone is the sentinel SNI value meaning "send no ServerName".
// The empty SNI value means "default: use the target host".
const SNINone = "none"

// Target is the subject of a survey.
type Target struct {
	URL  *url.URL `json:"url"`
	Host string   `json:"host"`
	Port uint16   `json:"port"`
}

// MarshalJSON renders the target compactly: the URL as a string.
func (t Target) MarshalJSON() ([]byte, error) {
	u := ""
	if t.URL != nil {
		u = t.URL.String()
	}
	return json.Marshal(struct {
		URL  string `json:"url"`
		Host string `json:"host"`
		Port uint16 `json:"port"`
	}{URL: u, Host: t.Host, Port: t.Port})
}

// UnmarshalJSON parses a target previously written by MarshalJSON.
func (t *Target) UnmarshalJSON(b []byte) error {
	var raw struct {
		URL  string `json:"url"`
		Host string `json:"host"`
		Port uint16 `json:"port"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	t.Host = raw.Host
	t.Port = raw.Port
	if raw.URL != "" {
		u, err := url.Parse(raw.URL)
		if err != nil {
			return err
		}
		t.URL = u
	}
	return nil
}

// String renders the target URL, falling back to host:port.
func (t Target) String() string {
	if t.URL != nil && t.URL.String() != "" {
		return t.URL.String()
	}
	if t.Host != "" {
		return netJoin(t.Host, t.Port)
	}
	return ""
}

// IsHTTPS reports whether the target scheme implies TLS.
func (t Target) IsHTTPS() bool {
	return t.URL == nil || t.URL.Scheme == "" || t.URL.Scheme == "https"
}

// ParseTarget parses a raw URL into a Target, filling scheme defaults:
// port 443 for https, 80 for http. Only http and https are accepted.
func ParseTarget(raw string) (Target, error) {
	if strings.TrimSpace(raw) == "" {
		return Target{}, errors.New("fairy: empty target URL")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Target{}, fmt.Errorf("fairy: parse target: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Target{}, fmt.Errorf("fairy: unsupported scheme %q (want http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Target{}, errors.New("fairy: target URL has no host")
	}
	port := uint16(0)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return Target{}, fmt.Errorf("fairy: invalid port %q", p)
		}
		port = uint16(n)
	} else if u.Scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	// Keep a normalized URL (fills in the default port explicitly).
	if u.Port() == "" {
		u.Host = netJoin(host, port)
	}
	return Target{URL: u, Host: host, Port: port}, nil
}

func netJoin(host string, port uint16) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(int(port))
	}
	return host + ":" + strconv.Itoa(int(port))
}

// Evidence is one structured fact extracted from a probe result. Raw
// errors are never the diagnostic model; they are converted into Evidence.
type Evidence struct {
	Kind   string         `json:"kind"`
	Values map[string]any `json:"values,omitempty"`
}

// Evidence kinds produced by probes.
const (
	KindDNSAnswer            = "dns_answer"
	KindDNSError             = "dns_error"
	KindTCPConnect           = "tcp_connect"
	KindTCPRefused           = "tcp_refused"
	KindTCPReset             = "tcp_reset"
	KindNetworkUnreachable   = "network_unreachable"
	KindTLSAlert             = "tls_alert"
	KindTLSVersion           = "tls_version"
	KindCipherSuite          = "cipher_suite"
	KindCertificate          = "certificate"
	KindALPNSelected         = "alpn_selected"
	KindHTTPStatus           = "http_status"
	KindUDPResponse          = "udp_response"
	KindUDPRefused           = "udp_refused"
	KindQUICHandshakeFailure = "quic_handshake_failure"
	KindQUICVersion          = "quic_version"
	KindH3RequestError       = "http3_request_error"
	KindTimeout              = "timeout"
)

// Observation is the complete record of one experiment at one layer.
type Observation struct {
	Experiment Experiment    `json:"experiment"`
	Layer      Layer         `json:"layer"`
	Status     Status        `json:"status"`
	Duration   time.Duration `json:"duration"`
	Evidence   []Evidence    `json:"evidence,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// NewObservation starts an observation for an experiment.
func NewObservation(e Experiment, status Status, d time.Duration) Observation {
	return Observation{Experiment: e, Layer: e.Layer, Status: status, Duration: d}
}

// AddEvidence appends a structured fact to the observation.
func (o *Observation) AddEvidence(kind string, values map[string]any) {
	o.Evidence = append(o.Evidence, Evidence{Kind: kind, Values: values})
}

// EvidenceOf returns all evidence entries with the given kind.
func (o Observation) EvidenceOf(kind string) []Evidence {
	var out []Evidence
	for _, ev := range o.Evidence {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// FirstEvidenceOf returns the first evidence entry with the given kind.
func (o Observation) FirstEvidenceOf(kind string) (Evidence, bool) {
	for _, ev := range o.Evidence {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return Evidence{}, false
}

// Round records one policy proposal round: the experiments the policy
// proposed and that the runner executed (in proposal order).
type Round struct {
	Index    int          `json:"index"`
	Proposed []Experiment `json:"proposed"`
}

// SurveyState is the full, JSON-serializable state of one survey. Every
// completed observation is immutable; the same experiment ID is never
// recorded twice.
type SurveyState struct {
	SurveyID     string        `json:"survey_id"`
	Target       *Target       `json:"target,omitempty"`
	StartedAt    time.Time     `json:"started_at,omitempty"`
	Round        int           `json:"round"`
	Observations []Observation `json:"observations"`
	Rounds       []Round       `json:"rounds"`
}

// ErrDuplicateExperiment is returned when an already-recorded experiment
// is added to the state again.
var ErrDuplicateExperiment = errors.New("fairy: experiment already recorded")

// HasExperiment reports whether an experiment with this ID is recorded.
func (s *SurveyState) HasExperiment(id string) bool {
	if id == "" {
		return false
	}
	for i := range s.Observations {
		if s.Observations[i].Experiment.ID == id {
			return true
		}
	}
	return false
}

// AddObservation records a completed observation. Completed experiments
// are immutable: adding the same experiment ID twice is an error.
func (s *SurveyState) AddObservation(o Observation) error {
	if s.HasExperiment(o.Experiment.ID) {
		return fmt.Errorf("%w: %s", ErrDuplicateExperiment, o.Experiment.ID)
	}
	s.Observations = append(s.Observations, o)
	return nil
}

// TargetOf returns the survey target, if known.
func (s *SurveyState) TargetOf() (Target, bool) {
	if s == nil || s.Target == nil {
		return Target{}, false
	}
	return *s.Target, true
}

// Confidence expresses how strongly evidence supports a finding.
type Confidence string

const (
	Confirmed            Confidence = "confirmed"
	Likely               Confidence = "likely"
	Possible             Confidence = "possible"
	InsufficientEvidence Confidence = "insufficient_evidence"
)

// Finding is an inference drawn from observations. Evidence first,
// interpretation second.
type Finding struct {
	Kind       string     `json:"kind"`
	Confidence Confidence `json:"confidence"`
	Evidence   []string   `json:"evidence"`
}

// Report is the final output of a survey.
type Report struct {
	Target       Target        `json:"target"`
	StartedAt    time.Time     `json:"started_at"`
	Duration     time.Duration `json:"duration"`
	Observations []Observation `json:"observations"`
	Findings     []Finding     `json:"findings"`

	// State is the survey state that produced this report. It is not
	// serialized with the report; persist it separately for resume.
	State *SurveyState `json:"-"`
}

// Budget returns the default per-experiment time budget for a layer.
func Budget(l Layer) time.Duration {
	switch l {
	case LayerDNS, LayerTCP, LayerUDP:
		return 2 * time.Second
	case LayerTLS, LayerHTTP, LayerQUIC:
		return 3 * time.Second
	default:
		return 2 * time.Second
	}
}

// AsInt coerces an evidence value (int, int64, or float64 after a JSON
// round-trip) into an int.
func AsInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// AsStrings coerces an evidence value ([]string or []any after a JSON
// round-trip) into a []string.
func AsStrings(v any) ([]string, bool) {
	switch s := v.(type) {
	case []string:
		return s, true
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out, true
	default:
		return nil, false
	}
}
