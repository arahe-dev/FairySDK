package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/arahe-dev/fairy/internal/model"
)

// maxH3BodyRead bounds how much of an HTTP/3 response body is drained.
const maxH3BodyRead = 32 << 10

// QUIC performs a staged QUIC/HTTP-3 experiment:
//
//  1. QUIC handshake to the target port (UDP connectivity + TLS 1.3 over
//     QUIC), capturing version, ALPN and handshake evidence.
//  2. One HTTP/3 GET when the handshake succeeded.
//
// quic-go is used; QUIC is never implemented by hand.
type QUIC struct {
	// RootCAs overrides the trusted root pool (tests, private CAs).
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
}

// Run performs one QUIC/HTTP-3 experiment. Every resolved address is
// attempted; the hostname passes if any QUIC handshake completes, and the
// HTTP/3 stage runs on the connection that actually succeeded.
func (p *QUIC) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	addrs, err := resolveAll(ctx, e)
	if err != nil {
		o.Status = model.Skipped
		o.Error = "dns resolution failed: " + err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"error": err.Error()})
		o.Duration = time.Since(start)
		return o
	}

	sni := sniFor(e)
	tlsCfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpnProtos(e.ALPN),
		RootCAs:            p.RootCAs,
		InsecureSkipVerify: p.InsecureSkipVerify || sni == "",
		MinVersion:         tls.VersionTLS12,
	}
	budget := remaining(ctx, model.Budget(model.LayerQUIC))
	qcfg := &quic.Config{
		HandshakeIdleTimeout: budget,
		MaxIdleTimeout:       budget,
	}

	conn, outcomes := attemptQUIC(ctx, addrs, e.Target.Port, tlsCfg, qcfg)
	o.Duration = time.Since(start)
	o.Addresses = outcomes
	if conn == nil {
		status, kind, text := aggregateStatus(outcomes)
		o.Status = status
		o.Error = text
		addFailureEvidence(&o, kind)
		return o
	}
	defer conn.CloseWithError(0, "fairy: done")

	cs := conn.ConnectionState()
	o.AddEvidence(model.KindQUICVersion, map[string]any{
		"version":      fmt.Sprintf("%v", cs.Version),
		"handshake_ms": ms(o.Duration),
		"addresses":    len(outcomes),
	})
	if cs.TLS.NegotiatedProtocol != "" {
		o.AddEvidence(model.KindALPNSelected, map[string]any{"protocol": cs.TLS.NegotiatedProtocol})
	}
	if len(cs.TLS.PeerCertificates) > 0 {
		o.AddEvidence(model.KindCertificate, certificateValues(cs.TLS.PeerCertificates[0]))
	}

	// Stage 2: HTTP/3 request on the connection that verified.
	p.h3Request(ctx, e, conn, tlsCfg, qcfg, &o)
	o.Status = model.Pass
	o.Duration = time.Since(start)
	return o
}

// attemptQUIC dials every resolved address at once and waits for all of
// them, returning the first connection that completed a handshake (in
// resolver order) plus the outcome of every attempt. Each attempt owns its
// own UDP socket, since quic-go binds one connection per packet
// connection.
func attemptQUIC(ctx context.Context, addrs []string, port uint16, tlsCfg *tls.Config, qcfg *quic.Config) (quic.Connection, []model.AddressOutcome) {
	type quicAttempt struct {
		ip   string
		conn quic.Connection
		err  error
		d    time.Duration
	}
	results := make(chan quicAttempt, len(addrs))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			start := time.Now()
			udpConn, err := net.ListenUDP("udp", nil)
			var conn quic.Connection
			if err == nil {
				raddr := &net.UDPAddr{IP: net.ParseIP(ip), Port: int(port)}
				conn, err = quic.Dial(runCtx, udpConn, raddr, tlsCfg, qcfg)
				if err != nil {
					_ = udpConn.Close()
				}
			}
			results <- quicAttempt{ip: ip, conn: conn, err: err, d: time.Since(start)}
		}(ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var (
		winner   quic.Connection
		outcomes []model.AddressOutcome
	)
	for a := range results {
		out := model.AddressOutcome{IP: a.ip, Status: model.Pass, Duration: a.d}
		if a.err != nil {
			out.Status, out.Kind, out.Error = classifyQUICError(a.err)
		}
		outcomes = append(outcomes, out)
		if a.err != nil {
			continue
		}
		if winner == nil {
			winner = a.conn
		} else {
			_ = a.conn.CloseWithError(0, "fairy: duplicate")
		}
	}
	sortOutcomes(outcomes, addrs)
	return winner, outcomes
}

// classifyQUICError maps a QUIC dial failure onto status plus an evidence
// kind.
func classifyQUICError(err error) (model.Status, string, string) {
	var vn *quic.VersionNegotiationError
	var sr *quic.StatelessResetError
	var it *quic.IdleTimeoutError
	var ht *quic.HandshakeTimeoutError
	var ae tls.AlertError
	var cve *tls.CertificateVerificationError
	switch {
	case isRefused(err) || isReset(err):
		return model.Fail, model.KindUDPRefused, "udp port unreachable"
	case isUnreachable(err) || strings.Contains(err.Error(), "unreachable"):
		// quic-go wraps route errors in a local INTERNAL_ERROR, hiding
		// the errno from errors.As; the message is still definitive.
		return model.Fail, model.KindNetworkUnreachable, "network unreachable (no route)"
	case errors.As(err, &vn):
		return model.Fail, model.KindQUICHandshakeFailure, "quic version negotiation failed"
	case errors.As(err, &sr):
		return model.Fail, model.KindQUICHandshakeFailure, "quic stateless reset"
	case errors.As(err, &cve):
		return model.Fail, model.KindCertificate, "certificate verification failed: " + cve.Error()
	case errors.As(err, &ae):
		return model.Fail, model.KindTLSAlert, "tls alert during quic handshake: " + err.Error()
	case errors.As(err, &ht), errors.As(err, &it), isTimeout(err):
		return model.Timeout, model.KindTimeout, "quic handshake timed out"
	case isCanceled(err):
		return model.Timeout, model.KindTimeout, "canceled"
	default:
		return model.Unknown, "", err.Error()
	}
}

// h3Request performs the HTTP/3 request stage over the QUIC connection
// that already completed a handshake — no second handshake, and no chance
// of the request landing on a different address than the verified one.
func (p *QUIC) h3Request(ctx context.Context, e model.Experiment, conn quic.Connection, tlsCfg *tls.Config, qcfg *quic.Config, o *model.Observation) {
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      qcfg,
	}
	cc := tr.NewClientConn(conn)
	defer func() { _ = cc.CloseWithError(0, "fairy: done") }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Target.URL.String(), nil)
	if err != nil {
		o.AddEvidence(model.KindH3RequestError, map[string]any{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		o.AddEvidence(model.KindH3RequestError, map[string]any{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxH3BodyRead))
	vals := map[string]any{
		"status": resp.StatusCode,
		"proto":  resp.Proto,
		"h3":     true,
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		vals["server"] = srv
	}
	o.AddEvidence(model.KindHTTPStatus, vals)
}

// fillQUICError classifies a QUIC dial failure for single-attempt callers.
func fillQUICError(o *model.Observation, err error) {
	status, kind, text := classifyQUICError(err)
	o.Status = status
	o.Error = text
	addFailureEvidence(o, kind)
}
