package fairy

import (
	"github.com/arahe-dev/fairy/internal/model"
)

// Evidence is one structured fact extracted from a probe result.
type Evidence = model.Evidence

// Evidence kinds produced by probes.
const (
	KindDNSAnswer            = model.KindDNSAnswer
	KindDNSError             = model.KindDNSError
	KindTCPConnect           = model.KindTCPConnect
	KindTCPRefused           = model.KindTCPRefused
	KindTCPReset             = model.KindTCPReset
	KindTLSAlert             = model.KindTLSAlert
	KindTLSVersion           = model.KindTLSVersion
	KindCipherSuite          = model.KindCipherSuite
	KindCertificate          = model.KindCertificate
	KindALPNSelected         = model.KindALPNSelected
	KindHTTPStatus           = model.KindHTTPStatus
	KindUDPResponse          = model.KindUDPResponse
	KindUDPRefused           = model.KindUDPRefused
	KindQUICHandshakeFailure = model.KindQUICHandshakeFailure
	KindQUICVersion          = model.KindQUICVersion
	KindH3RequestError       = model.KindH3RequestError
	KindTimeout              = model.KindTimeout
)
