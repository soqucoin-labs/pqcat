package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Cancellation plumbing for the scanner.
//
// Every Scan* entry point takes a context as its first argument. Before this,
// none did: a range scan over a /16 ran to completion whatever happened to the
// caller, so a dashboard scan kept working after the client disconnected, and
// the only bound on a long scan was per-host timeouts multiplied by host count.
//
// Two levels of responsiveness, deliberately:
//
//   - Between units of work, the worker pools check the context and stop
//     dispatching. Cancellation then takes effect within one host's timeout,
//     which is what bounds a range scan.
//   - Within a unit of work, dialing is context-aware, so an in-flight connect
//     aborts immediately rather than waiting out its timeout.
//
// A cancelled scan is NOT a clean scan. Callers must treat context.Canceled and
// DeadlineExceeded as NO_DATA (see compliance.ClassifyScan), never as "nothing
// found," or cancellation becomes a way to manufacture a passing score.

// dialContext connects with both a per-attempt timeout and caller cancellation.
// It replaces net.DialTimeout throughout the scanner: that function cannot be
// interrupted, so a cancelled scan still held its socket for the full timeout.
func dialContext(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, network, addr)
}

// dialTLSContext performs a TLS handshake under caller cancellation. The
// standard tls.DialWithDialer ignores context entirely, so a handshake against
// an unresponsive host could not be aborted.
func dialTLSContext(ctx context.Context, network, addr string, timeout time.Duration, cfg *tls.Config) (*tls.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: cfg}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// tls.Dialer.DialContext returns net.Conn; the concrete type is *tls.Conn,
	// and callers need it for ConnectionState.
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		conn.Close()
		return nil, &net.OpError{Op: "dial", Net: network, Err: errNotTLSConn}
	}
	return tlsConn, nil
}

// errNotTLSConn should be unreachable; it exists so the type assertion above has
// something honest to report rather than panicking.
var errNotTLSConn = errStr("tls dialer returned a non-TLS connection")

type errStr string

func (e errStr) Error() string { return string(e) }

// ctxDone reports whether the context is finished, for loops that want to stop
// between units of work without plumbing a select into every branch.
func ctxDone(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// orBackground keeps a nil context from panicking. Call sites inside the package
// pass a real context; this guards against a caller in another package handing
// us a zero value, which would otherwise turn a scan into a panic.
func orBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
