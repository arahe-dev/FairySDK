package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strconv"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// TLS performs a TLS handshake over a fresh TCP connection. It dials the
// explicit IP and sets ServerName separately, so routing problems and
// hostname-dependent TLS behavior stay distinguishable.
type TLS struct {
	// RootCAs overrides the trusted root pool (tests, private CAs).
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
}

// Run performs one TLS handshake experiment.
func (p *TLS) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)
	rawConn, err := dialIP(ctx, e, "tcp")
	if err != nil {
		fillConnError(ctx, &o, err, start)
		return o
	}
	defer rawConn.Close()

	sni := sniFor(e)
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpnProtos(e.ALPN),
		RootCAs:            p.RootCAs,
		InsecureSkipVerify: p.InsecureSkipVerify || sni == "",
		MinVersion:         tls.VersionTLS12,
	}
	tconn := tls.Client(rawConn, cfg)
	hsErr := tconn.HandshakeContext(ctx)
	o.Duration = time.Since(start)
	if hsErr != nil {
		fillTLSError(&o, hsErr)
		return o
	}
	defer tconn.Close()

	cs := tconn.ConnectionState()
	o.Status = model.Pass
	o.AddEvidence(model.KindTLSVersion, map[string]any{
		"name":        tls.VersionName(cs.Version),
		"handshake_ms": ms(o.Duration),
	})
	o.AddEvidence(model.KindCipherSuite, map[string]any{
		"name": tls.CipherSuiteName(cs.CipherSuite),
	})
	if len(cs.PeerCertificates) > 0 {
		o.AddEvidence(model.KindCertificate, certificateValues(cs.PeerCertificates[0]))
	}
	if cs.NegotiatedProtocol != "" {
		o.AddEvidence(model.KindALPNSelected, map[string]any{"protocol": cs.NegotiatedProtocol})
	}
	return o
}

// sniFor resolves the SNI for an experiment: empty means the target
// host, "none" means send no ServerName.
func sniFor(e model.Experiment) string {
	switch e.SNI {
	case "":
		return e.Target.Host
	case model.SNINone:
		return ""
	default:
		return e.SNI
	}
}

// certificateValues extracts structured certificate facts.
func certificateValues(cert *x509.Certificate) map[string]any {
	vals := map[string]any{
		"subject":    cert.Subject.CommonName,
		"issuer":     cert.Issuer.CommonName,
		"dns_names":  cert.DNSNames,
		"not_after":  cert.NotAfter.UTC().Format(time.RFC3339),
		"not_before": cert.NotBefore.UTC().Format(time.RFC3339),
	}
	if cert.IPAddresses != nil {
		var ips []string
		for _, ip := range cert.IPAddresses {
			ips = append(ips, ip.String())
		}
		vals["ip_addresses"] = ips
	}
	return vals
}

// fillTLSError classifies a handshake failure. TLS alerts and certificate
// problems are Fail with their own evidence; deadlines are Timeout.
func fillTLSError(o *model.Observation, err error) {
	var ae tls.AlertError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &ae):
		o.Status = model.Fail
		o.Error = "tls alert " + strconv.Itoa(int(ae)) + " (" + alertName(uint8(ae)) + ")"
		o.AddEvidence(model.KindTLSAlert, map[string]any{"alert": int(ae), "name": alertName(uint8(ae))})
	case errors.As(err, &cve):
		o.Status = model.Fail
		o.Error = "certificate verification failed: " + cve.Error()
		vals := map[string]any{"error": cve.Error()}
		if class := certErrorClass(cve.Err); class != "" {
			vals["type"] = class
		}
		o.AddEvidence(model.KindCertificate, vals)
	case isReset(err):
		o.Status = model.Fail
		o.Error = "connection reset during handshake"
		o.AddEvidence(model.KindTCPReset, nil)
	case isRefused(err):
		o.Status = model.Fail
		o.Error = "connection refused"
		o.AddEvidence(model.KindTCPRefused, nil)
	case isTimeout(err):
		o.Status = model.Timeout
		o.Error = "tls handshake timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerTLS)})
	case isCanceled(err):
		o.Status = model.Timeout
		o.Error = "canceled"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerTLS), "note": "context canceled"})
	default:
		o.Status = model.Unknown
		o.Error = err.Error()
	}
}

// alertNames maps common TLS alert codes to stable names.
var alertNames = map[uint8]string{
	0:   "close_notify",
	10:  "unexpected_message",
	20:  "bad_record_mac",
	40:  "handshake_failure",
	42:  "bad_certificate",
	43:  "unsupported_certificate",
	44:  "certificate_revoked",
	45:  "certificate_expired",
	46:  "certificate_unknown",
	47:  "illegal_parameter",
	48:  "unknown_ca",
	50:  "internal_error",
	51:  "user_canceled",
	70:  "protocol_version",
	71:  "insufficient_security",
	86:  "inappropriate_fallback",
	109: "missing_extension",
	112: "unrecognized_name",
	113: "bad_certificate_status_response",
	116: "certificate_required",
	120: "no_application_protocol",
}

func alertName(code uint8) string {
	if name, ok := alertNames[code]; ok {
		return name
	}
	return "alert_" + strconv.Itoa(int(code))
}
