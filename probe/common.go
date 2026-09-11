// Package probe contains the FairySDK probe implementations: DNS, TCP,
// TLS, HTTP, UDP and QUIC. Each probe reports exactly one Layer, converts
// raw errors into structured Evidence, classifies timeouts as Status
// Timeout and insufficient data as Status Unknown. Probes are stateless.
package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// addrAttemptLimit bounds how many addresses of one name are dialed at
// the same time.
const addrAttemptLimit = 4

// lookupFamily maps an experiment's address family onto a resolver network.
func lookupFamily(e model.Experiment) string {
	switch e.IPFamily {
	case model.IPv6:
		return "ip6"
	case model.FamilyAny:
		return "ip"
	default:
		return "ip4"
	}
}

// resolveAll returns every address the experiment host resolves to in the
// requested family. For FamilyAny, IPv4 addresses come first so results
// stay deterministic on dual-stack hosts. Duplicates are removed and
// resolver order is preserved.
func resolveAll(ctx context.Context, e model.Experiment) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, lookupFamily(e), e.Target.Host)
	if err != nil {
		return nil, err
	}
	var v4, v6 []string
	seen := map[string]bool{}
	for _, a := range addrs {
		var s string
		if un := a.Unmap(); un.Is4() {
			s = un.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			v4 = append(v4, s)
			continue
		}
		s = a.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		v6 = append(v6, s)
	}
	out := append(v4, v6...)
	if len(out) == 0 {
		return nil, errors.New("no addresses returned")
	}
	return out, nil
}

// resolveFirst returns the first resolved address. It is used by probes
// that cannot fan out across addresses (UDP reachability).
func resolveFirst(ctx context.Context, e model.Experiment) (string, error) {
	addrs, err := resolveAll(ctx, e)
	if err != nil {
		return "", err
	}
	return addrs[0], nil
}

// dialOne connects to one explicit address, so routing behavior and
// hostname-dependent behavior (TLS SNI) stay separable.
func dialOne(ctx context.Context, ip string, port uint16, network string) (net.Conn, error) {
	d := net.Dialer{}
	return d.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(int(port))))
}

// dialAttempt is one in-flight address attempt.
type dialAttempt struct {
	ip   string
	conn net.Conn
	err  error
	d    time.Duration
}

// outcomeFromAttempt converts an attempt into its recorded outcome.
func outcomeFromAttempt(a dialAttempt) model.AddressOutcome {
	out := model.AddressOutcome{IP: a.ip, Status: model.Pass, Duration: a.d}
	if a.err != nil {
		out.Status, out.Kind, out.Error = classifyDialError(a.err)
	}
	return out
}

// sortOutcomes orders outcomes by the resolver's address order so reports
// stay deterministic regardless of completion order.
func sortOutcomes(outcomes []model.AddressOutcome, addrs []string) {
	order := make(map[string]int, len(addrs))
	for i, ip := range addrs {
		order[ip] = i
	}
	sort.SliceStable(outcomes, func(i, j int) bool {
		return order[outcomes[i].IP] < order[outcomes[j].IP]
	})
}

// connectAll dials every resolved address at once and waits for all of
// them, so the probe can report which addresses work and which do not.
// It returns the first successful connection in resolver order (or nil
// when none connected) plus the outcome of every attempt.
//
// Waiting for every attempt costs time only when something is actually
// wrong — a blackholed address — which is exactly when the extra
// evidence matters.
func connectAll(ctx context.Context, e model.Experiment, network string) (net.Conn, []model.AddressOutcome, error) {
	addrs, err := resolveAll(ctx, e)
	if err != nil {
		return nil, nil, &prereqError{err}
	}
	conn, outcomes := attemptAddresses(ctx, addrs, e.Target.Port, network, true)
	return conn, outcomes, nil
}

// connectFirst dials every resolved address at once and returns as soon as
// one connects, cancelling the rest. It is used where a working path is
// all that is needed (TLS, HTTP): the outcomes it returns are real but
// may be incomplete, because attempts still in flight are abandoned.
func connectFirst(ctx context.Context, e model.Experiment, network string) (net.Conn, []model.AddressOutcome, error) {
	addrs, err := resolveAll(ctx, e)
	if err != nil {
		return nil, nil, &prereqError{err}
	}
	conn, outcomes := attemptAddresses(ctx, addrs, e.Target.Port, network, false)
	return conn, outcomes, nil
}

// attemptAddresses runs one dial per address, bounded by addrAttemptLimit.
func attemptAddresses(ctx context.Context, addrs []string, port uint16, network string, waitAll bool) (net.Conn, []model.AddressOutcome) {
	results := make(chan dialAttempt, len(addrs))
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
			conn, err := dialOne(runCtx, ip, port, network)
			results <- dialAttempt{ip: ip, conn: conn, err: err, d: time.Since(start)}
		}(ip)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var (
		winner   net.Conn
		outcomes []model.AddressOutcome
	)
	for a := range results {
		outcomes = append(outcomes, outcomeFromAttempt(a))
		if a.err != nil {
			continue
		}
		if winner == nil {
			winner = a.conn
		} else {
			_ = a.conn.Close()
		}
		if !waitAll {
			// A working path is enough: stop the remaining attempts and
			// close whatever they still deliver.
			cancel()
			go func() {
				for rest := range results {
					if rest.conn != nil {
						_ = rest.conn.Close()
					}
				}
			}()
			break
		}
	}
	sortOutcomes(outcomes, addrs)
	return winner, outcomes
}

// classifyDialError maps a connection error onto status plus the evidence
// kind that describes it.
func classifyDialError(err error) (model.Status, string, string) {
	switch {
	case isRefused(err):
		return model.Fail, model.KindTCPRefused, "connection refused"
	case isUnreachable(err):
		return model.Fail, model.KindNetworkUnreachable, "network unreachable"
	case isReset(err):
		return model.Fail, model.KindTCPReset, "connection reset"
	case isTimeout(err):
		return model.Timeout, model.KindTimeout, "timed out"
	case isCanceled(err):
		return model.Timeout, model.KindTimeout, "canceled"
	default:
		return model.Unknown, "", err.Error()
	}
}

// aggregateStatus summarizes per-address outcomes when none of them
// connected: an explicit failure (refused, reset, unreachable) is
// stronger evidence than a timeout, so it wins.
func aggregateStatus(outcomes []model.AddressOutcome) (model.Status, string, string) {
	status, kind, text := model.Unknown, "", "all addresses failed"
	for _, o := range outcomes {
		switch o.Status {
		case model.Pass:
			// Caller only reaches here when nothing passed.
		case model.Fail:
			if status != model.Fail {
				status, kind, text = model.Fail, o.Kind, o.Error
			}
			if kind == "" {
				kind, text = o.Kind, o.Error
			}
		case model.Timeout:
			if status == model.Unknown {
				status, kind, text = model.Timeout, o.Kind, o.Error
			}
		default:
			if status == model.Unknown && kind == "" {
				kind, text = o.Kind, o.Error
			}
		}
	}
	return status, kind, text
}

// addFailureEvidence records the evidence entry for a failure kind.
func addFailureEvidence(o *model.Observation, kind string) {
	switch kind {
	case "":
		return
	case model.KindTimeout:
		o.AddEvidence(kind, map[string]any{"stage": string(o.Layer)})
	case model.KindQUICHandshakeFailure:
		o.AddEvidence(kind, map[string]any{"reason": "handshake_failed"})
	default:
		o.AddEvidence(kind, nil)
	}
}

// fillConnError classifies a connection-level error from a probe that
// dials a single address (UDP reachability).
func fillConnError(ctx context.Context, o *model.Observation, err error, start time.Time) {
	o.Duration = time.Since(start)
	var pe *prereqError
	if errors.As(err, &pe) {
		fillPrereq(o, err)
		return
	}
	status, kind, text := classifyDialError(err)
	o.Status = status
	o.Error = text
	addFailureEvidence(o, kind)
}

// fillPrereq marks an observation as skipped because a prerequisite
// (name resolution) failed.
func fillPrereq(o *model.Observation, err error) {
	var pe *prereqError
	msg := err.Error()
	if errors.As(err, &pe) {
		msg = pe.err.Error()
	}
	o.Status = model.Skipped
	o.Error = "dns resolution failed: " + msg
	o.AddEvidence(model.KindDNSError, map[string]any{"error": msg})
}

// prereqError marks a failed prerequisite (DNS resolution) so probes can
// distinguish it from the probed layer's own failures.
type prereqError struct{ err error }

func (p *prereqError) Error() string { return p.err.Error() }
func (p *prereqError) Unwrap() error { return p.err }

// remaining returns the remaining wall time allowed by ctx, or a default
// when the context has no deadline.
func remaining(ctx context.Context, def time.Duration) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return def
	}
	d := time.Until(dl)
	if d <= 0 {
		return time.Millisecond
	}
	return d
}

// isTimeout reports whether err is a deadline/timeout error. Timeouts
// become Status Timeout, never Status Fail.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isCanceled reports whether err is plain parent-context cancellation
// (as opposed to a deadline the probe itself hit).
func isCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

// Windows reports connect failures with the real WSA errnos (10061
// ECONNREFUSED, 10054 ECONNRESET), whose numeric values do not equal the
// synthetic syscall.E* constants defined on that platform. Compare
// against both; the WSA numbers never collide with real Unix errnos.
const (
	wsaConnRefused = syscall.Errno(10061)
	wsaConnReset   = syscall.Errno(10054)
	wsaNetDown     = syscall.Errno(10050)
	wsaNetUnreach  = syscall.Errno(10051)
	wsaHostUnreach = syscall.Errno(10065)
)

// isUnreachable reports "no route" verdicts from the OS kernel
// (ENETUNREACH / EHOSTUNREACH / ENETDOWN). The kernel stating "no route"
// is definitive evidence for this machine and network — not
// insufficient evidence — so it becomes Status Fail.
func isUnreachable(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN,
			wsaNetUnreach, wsaHostUnreach, wsaNetDown:
			return true
		}
	}
	return false
}

// isRefused reports ECONNREFUSED (nothing listening / actively refused).
func isRefused(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ECONNREFUSED || errno == wsaConnRefused
	}
	return false
}

// isReset reports ECONNRESET (connection reset by peer).
func isReset(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.ECONNRESET || errno == wsaConnReset
	}
	return false
}

// certErrorClass categorizes an x509 verification error chain. x509
// error types mix value and pointer receivers, so errors.As cannot be
// used uniformly; walk the chain manually.
func certErrorClass(err error) string {
	for err != nil {
		switch e := err.(type) {
		case x509.HostnameError, *x509.HostnameError:
			return "hostname_mismatch"
		case x509.UnknownAuthorityError, *x509.UnknownAuthorityError:
			return "unknown_authority"
		case x509.CertificateInvalidError:
			return strconv.Itoa(int(e.Reason))
		case *x509.CertificateInvalidError:
			return strconv.Itoa(int(e.Reason))
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return ""
		}
		err = u.Unwrap()
	}
	return ""
}

// alpnProtos maps the experiment ALPN level onto TLS NextProtos.
// Empty means offer both HTTP/2 and HTTP/1.1.
func alpnProtos(alpn string) []string {
	switch alpn {
	case "":
		return []string{"h2", "http/1.1"}
	default:
		return []string{alpn}
	}
}

// ms converts a duration to integer milliseconds for evidence values.
func ms(d time.Duration) int64 {
	if d < 0 {
		return 0
	}
	return d.Milliseconds()
}
