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

// Run performs one QUIC/HTTP-3 experiment.
func (p *QUIC) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	ip, err := resolveFirst(ctx, e)
	if err != nil {
		o.Status = model.Skipped
		o.Error = "dns resolution failed: " + err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"error": err.Error()})
		o.Duration = time.Since(start)
		return o
	}
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", e.Target.Port))

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

	conn, err := quic.DialAddr(ctx, addr, tlsCfg, qcfg)
	o.Duration = time.Since(start)
	if err != nil {
		fillQUICError(&o, err)
		return o
	}
	defer conn.CloseWithError(0, "fairy: done")

	cs := conn.ConnectionState()
	o.AddEvidence(model.KindQUICVersion, map[string]any{
		"version":     fmt.Sprintf("%v", cs.Version),
		"handshake_ms": ms(o.Duration),
	})
	if cs.TLS.NegotiatedProtocol != "" {
		o.AddEvidence(model.KindALPNSelected, map[string]any{"protocol": cs.TLS.NegotiatedProtocol})
	}
	if len(cs.TLS.PeerCertificates) > 0 {
		o.AddEvidence(model.KindCertificate, certificateValues(cs.TLS.PeerCertificates[0]))
	}

	// Stage 2: HTTP/3 request when the handshake succeeded.
	p.h3Request(ctx, e, tlsCfg, qcfg, &o)
	o.Status = model.Pass
	o.Duration = time.Since(start)
	return o
}

func (p *QUIC) h3Request(ctx context.Context, e model.Experiment, tlsCfg *tls.Config, qcfg *quic.Config, o *model.Observation) {
	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      qcfg,
	}
	defer func() { _ = tr.Close() }()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Target.URL.String(), nil)
	if err != nil {
		o.AddEvidence(model.KindH3RequestError, map[string]any{"error": err.Error()})
		return
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := tr.RoundTrip(req)
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

// fillQUICError classifies a QUIC dial failure.
func fillQUICError(o *model.Observation, err error) {
	var vn *quic.VersionNegotiationError
	var sr *quic.StatelessResetError
	var it *quic.IdleTimeoutError
	var ht *quic.HandshakeTimeoutError
	var ae tls.AlertError
	var cve *tls.CertificateVerificationError
	switch {
	case isRefused(err) || isReset(err):
		o.Status = model.Fail
		o.Error = "udp port unreachable"
		o.AddEvidence(model.KindUDPRefused, nil)
	case errors.As(err, &vn):
		o.Status = model.Fail
		o.Error = "quic version negotiation failed"
		o.AddEvidence(model.KindQUICHandshakeFailure, map[string]any{"reason": "version_negotiation_failed"})
	case errors.As(err, &sr):
		o.Status = model.Fail
		o.Error = "quic stateless reset"
		o.AddEvidence(model.KindQUICHandshakeFailure, map[string]any{"reason": "stateless_reset"})
	case errors.As(err, &cve):
		o.Status = model.Fail
		o.Error = "certificate verification failed: " + cve.Error()
		vals := map[string]any{"error": cve.Error()}
		if class := certErrorClass(cve.Err); class != "" {
			vals["type"] = class
		}
		o.AddEvidence(model.KindCertificate, vals)
	case errors.As(err, &ae):
		o.Status = model.Fail
		o.Error = "tls alert during quic handshake: " + err.Error()
		o.AddEvidence(model.KindTLSAlert, map[string]any{"alert": int(ae), "name": alertName(uint8(ae))})
	case errors.As(err, &ht), errors.As(err, &it), isTimeout(err):
		o.Status = model.Timeout
		o.Error = "quic handshake timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerQUIC)})
	case isCanceled(err):
		o.Status = model.Timeout
		o.Error = "canceled"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerQUIC), "note": "context canceled"})
	default:
		o.Status = model.Unknown
		o.Error = err.Error()
	}
}
