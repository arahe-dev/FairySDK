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

	"github.com/arahe-dev/fairy/internal/model"
)

// UserAgent is sent by HTTP probes.
const UserAgent = "fairy/0.1 (+https://github.com/arahe-dev/fairy)"

// maxHTTPBodyRead bounds how much of a response body is drained to time
// the full transfer.
const maxHTTPBodyRead = 64 << 10 // 64 KiB

// HTTP performs one GET request through a dedicated http.Transport. The
// global http.DefaultClient is never used. Automatic redirects are
// disabled: a 3xx is recorded as data, not followed.
type HTTP struct {
	// RootCAs overrides the trusted root pool (tests, private CAs).
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
}

// Run performs one HTTP experiment and records status, protocol, redirect
// location, selected headers, TTFB and total duration.
func (p *HTTP) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	dialer := &net.Dialer{Timeout: remaining(ctx, model.Budget(model.LayerHTTP))}
	sni := sniFor(e)
	transport := &http.Transport{
		Proxy: nil, // direct connection; environment proxies would corrupt experiment data
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			ip, err := resolveFirst(ctx, e)
			if err != nil {
				return nil, &prereqError{err}
			}
			_, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		},
		TLSClientConfig: &tls.Config{
			ServerName:         sni,
			NextProtos:         alpnProtos(e.ALPN),
			RootCAs:            p.RootCAs,
			InsecureSkipVerify: p.InsecureSkipVerify || sni == "",
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.Target.URL.String(), nil)
	if err != nil {
		o.Status = model.Unknown
		o.Error = err.Error()
		o.Duration = time.Since(start)
		return o
	}
	req.Header.Set("User-Agent", UserAgent)

	t0 := time.Now()
	resp, err := client.Do(req)
	ttfb := time.Since(t0)
	if err != nil {
		fillHTTPError(&o, err, time.Since(start))
		return o
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBodyRead))
	o.Duration = time.Since(start)

	vals := map[string]any{
		"status":     resp.StatusCode,
		"proto":      resp.Proto,
		"ttfb_ms":    ms(ttfb),
		"total_ms":   ms(o.Duration),
		"body_bytes": bodyBytes,
	}
	if srv := resp.Header.Get("Server"); srv != "" {
		vals["server"] = srv
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		vals["content_type"] = ct
	}
	if via := resp.Header.Get("Via"); via != "" {
		vals["via"] = via
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		vals["location"] = resp.Header.Get("Location")
	}
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		vals["alpn"] = resp.TLS.NegotiatedProtocol
		o.AddEvidence(model.KindALPNSelected, map[string]any{"protocol": resp.TLS.NegotiatedProtocol})
	}
	o.AddEvidence(model.KindHTTPStatus, vals)
	if resp.StatusCode >= 400 {
		o.Status = model.Fail
		o.Error = fmt.Sprintf("http %d", resp.StatusCode)
	} else {
		o.Status = model.Pass
	}
	return o
}

// fillHTTPError classifies a client.Do failure.
func fillHTTPError(o *model.Observation, err error, d time.Duration) {
	o.Duration = d
	var pe *prereqError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &pe):
		o.Status = model.Skipped
		o.Error = "dns resolution failed: " + pe.err.Error()
		o.AddEvidence(model.KindDNSError, map[string]any{"error": pe.err.Error()})
	case errors.As(err, &cve):
		o.Status = model.Fail
		o.Error = "certificate verification failed: " + cve.Error()
		o.AddEvidence(model.KindCertificate, map[string]any{"error": cve.Error()})
	case isReset(err):
		o.Status = model.Fail
		o.Error = "connection reset"
		o.AddEvidence(model.KindTCPReset, nil)
	case isRefused(err):
		o.Status = model.Fail
		o.Error = "connection refused"
		o.AddEvidence(model.KindTCPRefused, nil)
	case isTimeout(err):
		o.Status = model.Timeout
		o.Error = "timed out"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerHTTP)})
	case isCanceled(err):
		o.Status = model.Timeout
		o.Error = "canceled"
		o.AddEvidence(model.KindTimeout, map[string]any{"stage": string(model.LayerHTTP), "note": "context canceled"})
	default:
		o.Status = model.Unknown
		o.Error = err.Error()
	}
}
