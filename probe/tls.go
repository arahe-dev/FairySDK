package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strconv"
	"sync"
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

// Run performs one TLS handshake experiment. Any resolved address that
// completes a handshake makes the hostname pass; the outcome of each
// attempted address is recorded.
//
// The handshake is attempted per address, not merely per connection: an
// address can accept TCP and then stall or be intercepted during the
// handshake, so connection-level failover alone would still land on the
// bad address and report a healthy hostname as broken.
func (p *TLS) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	sni := sniFor(e)
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpnProtos(e.ALPN),
		RootCAs:            p.RootCAs,
		InsecureSkipVerify: p.InsecureSkipVerify || sni == "",
		MinVersion:         tls.VersionTLS12,
	}

	tconn, outcomes, repErr, err := attemptTLS(ctx, e, cfg)
	o.Duration = time.Since(start)
	if err != nil {
		fillPrereq(&o, err)
		return o
	}
	o.Addresses = outcomes
	if tconn == nil {
		// Nothing completed a handshake: report the representative
		// failure with full evidence (alert code, certificate class).
		if repErr != nil {
			fillTLSError(&o, repErr)
		} else {
			status, kind, text := aggregateStatus(outcomes)
			o.Status = status
			o.Error = text
			addFailureEvidence(&o, kind)
		}
		return o
	}
	defer tconn.Close()

	cs := tconn.ConnectionState()
	o.Status = model.Pass
	o.AddEvidence(model.KindTLSVersion, map[string]any{
		"name":         tls.VersionName(cs.Version),
		"handshake_ms": ms(o.Duration),
		"addresses":    len(outcomes),
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

// attemptTLS connects to and handshakes with every resolved address at
// once, waiting for all of them. It returns the first connection that
// completed a handshake in resolver order, the outcome of every address,
// a representative raw error when none succeeded, and a prerequisite
// error when resolution itself failed.
func attemptTLS(ctx context.Context, e model.Experiment, cfg *tls.Config) (*tls.Conn, []model.AddressOutcome, error, error) {
	addrs, err := resolveAll(ctx, e)
	if err != nil {
		return nil, nil, nil, &prereqError{err}
	}

	type tlsAttempt struct {
		ip   string
		conn *tls.Conn
		err  error
		d    time.Duration
	}
	results := make(chan tlsAttempt, len(addrs))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, addrAttemptLimit)
	var wg sync.WaitGroup
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			rawConn, derr := dialOne(runCtx, ip, e.Target.Port, "tcp")
			if derr != nil {
				results <- tlsAttempt{ip: ip, err: derr, d: time.Since(start)}
				return
			}
			conn := tls.Client(rawConn, cfg)
			if herr := conn.HandshakeContext(runCtx); herr != nil {
				_ = rawConn.Close()
				results <- tlsAttempt{ip: ip, err: herr, d: time.Since(start)}
				return
			}
			results <- tlsAttempt{ip: ip, conn: conn, d: time.Since(start)}
		}(ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	byIP := make(map[string]tlsAttempt, len(addrs))
	for a := range results {
		byIP[a.ip] = a
	}

	var (
		winner   *tls.Conn
		outcomes []model.AddressOutcome
		repErr   error
	)
	for _, ip := range addrs { // resolver order keeps reports deterministic
		a, ok := byIP[ip]
		if !ok {
			continue
		}
		out := model.AddressOutcome{IP: ip, Status: model.Pass, Duration: a.d}
		switch {
		case a.err != nil:
			out.Status, out.Kind, out.Error = classifyTLSError(a.err)
			if repErr == nil {
				repErr = a.err
			}
		case winner == nil:
			winner = a.conn
		default:
			_ = a.conn.Close()
		}
		outcomes = append(outcomes, out)
	}
	return winner, outcomes, repErr, nil
}

// classifyTLSError maps a handshake failure onto status plus an evidence
// kind.
func classifyTLSError(err error) (model.Status, string, string) {
	var ae tls.AlertError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &ae):
		return model.Fail, model.KindTLSAlert,
			"tls alert " + strconv.Itoa(int(ae)) + " (" + alertName(uint8(ae)) + ")"
	case errors.As(err, &cve):
		return model.Fail, model.KindCertificate, "certificate verification failed: " + cve.Error()
	case isRefused(err):
		return model.Fail, model.KindTCPRefused, "connection refused"
	case isUnreachable(err):
		return model.Fail, model.KindNetworkUnreachable, "network unreachable"
	case isReset(err):
		return model.Fail, model.KindTCPReset, "connection reset during handshake"
	case isTimeout(err):
		return model.Timeout, model.KindTimeout, "tls handshake timed out"
	case isCanceled(err):
		return model.Timeout, model.KindTimeout, "canceled"
	default:
		return model.Unknown, "", err.Error()
	}
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
	case isUnreachable(err):
		o.Status = model.Fail
		o.Error = "network unreachable"
		o.AddEvidence(model.KindNetworkUnreachable, nil)
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
