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
	"strconv"
	"syscall"
	"time"

	"github.com/arahe-dev/fairy/internal/model"
)

// resolveFirst resolves the experiment host within the requested address
// family and returns the first address. Family "any" prefers IPv4 so
// results stay deterministic on dual-stack hosts.
func resolveFirst(ctx context.Context, e model.Experiment) (string, error) {
	family := "ip4"
	switch e.IPFamily {
	case model.IPv6:
		family = "ip6"
	case model.FamilyAny:
		family = "ip"
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, family, e.Target.Host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", errors.New("no addresses returned")
	}
	if family == "ip" {
		// Deterministic preference: IPv4 first, then IPv6.
		for _, a := range addrs {
			if a.Is4() || a.Is4In6() {
				return a.Unmap().String(), nil
			}
		}
	}
	return addrs[0].String(), nil
}

// dialIP dials the explicit IP for the experiment's host, so that routing
// behavior and hostname-dependent behavior (TLS SNI) stay separable.
func dialIP(ctx context.Context, e model.Experiment, network string) (net.Conn, error) {
	ip, err := resolveFirst(ctx, e)
	if err != nil {
		return nil, &prereqError{err}
	}
	d := net.Dialer{}
	return d.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(int(e.Target.Port))))
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
