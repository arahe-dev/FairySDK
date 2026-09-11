package fairy

import (
	"github.com/arahe-dev/fairy/internal/model"
)

// Layer identifies the protocol layer an experiment probes.
type Layer = model.Layer

const (
	LayerDNS  Layer = model.LayerDNS
	LayerTCP  Layer = model.LayerTCP
	LayerTLS  Layer = model.LayerTLS
	LayerHTTP Layer = model.LayerHTTP
	LayerUDP  Layer = model.LayerUDP
	LayerQUIC Layer = model.LayerQUIC
)

// Status is the outcome of a single experiment.
type Status = model.Status

const (
	Pass    Status = model.Pass
	Fail    Status = model.Fail
	Timeout Status = model.Timeout
	Skipped Status = model.Skipped
	Unknown Status = model.Unknown
)

// IPFamily selects the address family an experiment uses.
type IPFamily = model.IPFamily

const (
	IPv4      IPFamily = model.IPv4
	IPv6      IPFamily = model.IPv6
	FamilyAny IPFamily = model.FamilyAny // DNS only: both A and AAAA.
)

// Transport is the wire transport an experiment uses.
type Transport = model.Transport

const (
	TCP  Transport = model.TCP
	UDP  Transport = model.UDP
	QUIC Transport = model.QUIC
)

// ResolverMode selects how a DNS experiment resolves names.
type ResolverMode = model.ResolverMode

const (
	ResolverSystem ResolverMode = model.ResolverSystem
	ResolverPublic ResolverMode = model.ResolverPublic
)

// SNINone is the sentinel SNI value meaning "send no ServerName"; an
// empty SNI means "default: the target host".
const SNINone = model.SNINone

// Experiment is one fully specified controlled experiment: a complete
// probe input with a deterministic ID.
type Experiment = model.Experiment

// ExperimentID derives the deterministic experiment ID (canonical
// serialization -> SHA-256 -> first 12 hex chars). Same inputs always
// produce the same ID.
func ExperimentID(e Experiment) string {
	return model.ExperimentID(e)
}

// Round records one policy proposal round.
type Round = model.Round

// Observation is the complete record of one experiment at one layer.
// Raw errors are never the diagnostic model: they become Evidence.
type Observation = model.Observation
