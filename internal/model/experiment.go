package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Experiment is one fully specified controlled experiment: a complete
// probe input. Categorical values are enums, never floats, so that
// experiments are comparable and IDs are stable.
type Experiment struct {
	ID        string       `json:"id"`
	Target    Target       `json:"target"`
	Layer     Layer        `json:"layer"`
	IPFamily  IPFamily     `json:"ip_family,omitempty"`
	Transport Transport    `json:"transport,omitempty"`
	Resolver  ResolverMode `json:"resolver,omitempty"`
	ALPN      string       `json:"alpn,omitempty"`
	// SNI: "" means default (the target host); "none" means send no
	// ServerName; any other value is an explicit SNI hostname.
	SNI     string `json:"sni,omitempty"`
	Payload int    `json:"payload,omitempty"`
}

// ExperimentID derives the deterministic experiment ID: canonical
// serialization -> SHA-256 -> first 12 hex chars. Same inputs therefore
// always produce the same ID, which gives deduplication and
// restartability for free.
func ExperimentID(e Experiment) string {
	sum := sha256.Sum256([]byte(e.Canonical()))
	return hex.EncodeToString(sum[:])[:12]
}

// Canonical renders the experiment into a stable string used for ID
// derivation. The version prefix guards against accidental collisions
// if the model ever grows fields.
func (e Experiment) Canonical() string {
	return strings.Join([]string{
		"v1",
		string(e.Layer),
		e.Target.String(),
		e.Target.Host,
		strconv.Itoa(int(e.Target.Port)),
		string(e.IPFamily),
		string(e.Transport),
		string(e.Resolver),
		e.ALPN,
		e.SNI,
		strconv.Itoa(e.Payload),
	}, "|")
}

// String renders a short human-readable experiment label.
func (e Experiment) String() string {
	return fmt.Sprintf("%s/%s/%s", e.Layer, e.IPFamily, e.Transport)
}

// Normalize fills derived defaults (family, transport, resolver) and the
// deterministic ID. It is idempotent.
func (e *Experiment) Normalize() {
	if e.Target.Host == "" && e.Target.URL != nil {
		e.Target.Host = e.Target.URL.Hostname()
	}
	if e.IPFamily == "" {
		if e.Layer == LayerDNS {
			e.IPFamily = FamilyAny
		} else {
			e.IPFamily = IPv4
		}
	}
	if e.Transport == "" {
		switch e.Layer {
		case LayerDNS:
			e.Transport = UDP
		case LayerTCP, LayerTLS, LayerHTTP:
			e.Transport = TCP
		case LayerUDP:
			e.Transport = UDP
		case LayerQUIC:
			e.Transport = QUIC
		}
	}
	if e.Resolver == "" && e.Layer == LayerDNS {
		e.Resolver = ResolverSystem
	}
	if e.Payload == 0 && e.Layer == LayerUDP {
		e.Payload = 16
	}
	if e.ID == "" {
		e.ID = ExperimentID(*e)
	}
}

// NewDNSExperiment builds the canonical DNS experiment for a target.
func NewDNSExperiment(t Target, r ResolverMode) Experiment {
	if r == "" {
		r = ResolverSystem
	}
	e := Experiment{Target: t, Layer: LayerDNS, IPFamily: FamilyAny, Transport: UDP, Resolver: r}
	e.Normalize()
	return e
}

// NewTCPExperiment builds the canonical TCP connect experiment.
func NewTCPExperiment(t Target, f IPFamily) Experiment {
	e := Experiment{Target: t, Layer: LayerTCP, IPFamily: f, Transport: TCP}
	e.Normalize()
	return e
}

// NewTLSExperiment builds the canonical TLS handshake experiment.
// alpn "" means offer both h2 and http/1.1. sni "" means the target host.
func NewTLSExperiment(t Target, f IPFamily, alpn, sni string) Experiment {
	e := Experiment{Target: t, Layer: LayerTLS, IPFamily: f, Transport: TCP, ALPN: alpn, SNI: sni}
	e.Normalize()
	return e
}

// NewHTTPExperiment builds the canonical HTTP request experiment.
func NewHTTPExperiment(t Target, f IPFamily, alpn string) Experiment {
	e := Experiment{Target: t, Layer: LayerHTTP, IPFamily: f, Transport: TCP, ALPN: alpn}
	e.Normalize()
	return e
}

// NewUDPExperiment builds the canonical UDP reachability experiment.
func NewUDPExperiment(t Target, f IPFamily, payload int) Experiment {
	e := Experiment{Target: t, Layer: LayerUDP, IPFamily: f, Transport: UDP, Payload: payload}
	e.Normalize()
	return e
}

// NewQUICExperiment builds the canonical QUIC/HTTP-3 experiment.
func NewQUICExperiment(t Target, f IPFamily, sni string) Experiment {
	e := Experiment{Target: t, Layer: LayerQUIC, IPFamily: f, Transport: QUIC, ALPN: "h3", SNI: sni}
	e.Normalize()
	return e
}
