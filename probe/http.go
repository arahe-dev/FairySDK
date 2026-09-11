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
	"sync"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
	"github.com/arahe-dev/fairy/internal/version"
)

// UserAgent is sent by HTTP probes.
const UserAgent = version.UserAgent

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

// addrTracker records which addresses the dialer used so that per-address
// outcomes survive the transport's own connection management.
type addrTracker struct {
	mu       sync.Mutex
	pinned   string
	outcomes []model.AddressOutcome
	seen     map[string]bool
}

func newAddrTracker() *addrTracker {
	return &addrTracker{seen: map[string]bool{}}
}

// pin forces subsequent dials to one address (per-attempt failover).
func (t *addrTracker) pin(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.pinned = ip
}

// pinnedIP returns the currently pinned address, if any.
func (t *addrTracker) pinnedIP() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pinned
}

// record stores one address outcome, keeping the first record per address.
func (t *addrTracker) record(o model.AddressOutcome) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if o.IP == "" || t.seen[o.IP] {
		return
	}
	t.seen[o.IP] = true
	t.outcomes = append(t.outcomes, o)
}

// list returns the recorded outcomes in the order they were observed.
func (t *addrTracker) list() []model.AddressOutcome {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]model.AddressOutcome(nil), t.outcomes...)
}

// Run performs one HTTP experiment and records status, protocol, redirect
// location, selected headers, TTFB and total duration.
//
// Each resolved address is tried in turn, with every attempt given a slice
// of the remaining budget, so a single stalled address cannot consume the
// whole layer budget and hide the addresses that work.
func (p *HTTP) Run(ctx context.Context, e model.Experiment) model.Observation {
	start := time.Now()
	o := model.NewObservation(e, model.Unknown, 0)

	tracker := newAddrTracker()
	sni := sniFor(e)
	transport := &http.Transport{
		Proxy: nil, // direct connection; environment proxies would corrupt experiment data
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ip := tracker.pinnedIP(); ip != "" {
				return dialOne(ctx, ip, e.Target.Port, "tcp")
			}
			conn, outcomes, err := connectFirst(ctx, e, "tcp")
			for _, oc := range outcomes {
				tracker.record(oc)
			}
			return conn, err
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

	addrs, aerr := resolveAll(ctx, e)
	if aerr != nil {
		o.Duration = time.Since(start)
		fillPrereq(&o, &prereqError{aerr})
		return o
	}
	perAttempt := remaining(ctx, model.Budget(model.LayerHTTP)) / time.Duration(len(addrs))
	if perAttempt < 100*time.Millisecond {
		perAttempt = 100 * time.Millisecond
	}

	var lastErr error
	for _, ip := range addrs {
		tracker.pin(ip)
		attemptCtx, cancel := context.WithTimeout(ctx, perAttempt)
		t0 := time.Now()
		resp, derr := client.Do(req.WithContext(attemptCtx))
		ttfb := time.Since(t0)

		if derr == nil {
			bodyBytes, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPBodyRead))
			_ = resp.Body.Close()
			o.Duration = time.Since(start)
			cancel()
			tracker.record(model.AddressOutcome{IP: ip, Status: model.Pass, Duration: ttfb})
			o.Addresses = tracker.list()
			p.fillResponseEvidence(&o, resp, ttfb, bodyBytes)
			return o
		}

		cancel()
		lastErr = derr
		status, kind, text := classifyHTTPError(derr)
		tracker.record(model.AddressOutcome{IP: ip, Status: status, Duration: ttfb, Kind: kind, Error: text})

		var pe *prereqError
		if errors.As(derr, &pe) {
			break // resolution failed: no other address will help
		}
	}

	fillHTTPError(&o, lastErr, time.Since(start))
	o.Addresses = tracker.list()
	return o
}

// fillResponseEvidence records everything an HTTP response tells us.
func (p *HTTP) fillResponseEvidence(o *model.Observation, resp *http.Response, ttfb time.Duration, bodyBytes int64) {
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
}

// classifyHTTPError maps a request failure onto status plus an evidence
// kind (used for per-address outcomes).
func classifyHTTPError(err error) (model.Status, string, string) {
	var pe *prereqError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &pe):
		msg := pe.err.Error()
		return model.Skipped, model.KindDNSError, msg
	case errors.As(err, &cve):
		return model.Fail, model.KindCertificate, "certificate verification failed: " + cve.Error()
	case isReset(err):
		return model.Fail, model.KindTCPReset, "connection reset"
	case isRefused(err):
		return model.Fail, model.KindTCPRefused, "connection refused"
	case isUnreachable(err):
		return model.Fail, model.KindNetworkUnreachable, "network unreachable"
	case isTimeout(err):
		return model.Timeout, model.KindTimeout, "timed out"
	case isCanceled(err):
		return model.Timeout, model.KindTimeout, "canceled"
	default:
		return model.Unknown, "", err.Error()
	}
}

// fillHTTPError classifies a client.Do failure.
func fillHTTPError(o *model.Observation, err error, d time.Duration) {
	o.Duration = d
	if err == nil {
		o.Status = model.Unknown
		o.Error = "request failed without error"
		return
	}
	var pe *prereqError
	var cve *tls.CertificateVerificationError
	switch {
	case errors.As(err, &pe):
		fillPrereq(o, err)
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
		o.Error = "connection reset"
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
