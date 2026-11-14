// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netutil contains misc shared networking code & types.
package netutil

import (
	"bufio"
	"crypto/x509"
	"github.com/metacubex/http"
	"github.com/metacubex/tls"
	"io"
	"net"
	"time"

	"github.com/metacubex/tailscale/net/netx"
	"github.com/metacubex/tailscale/syncs"
)

// NewDefaultTransport returns a new *http.Transport configured identically to
// the Go standard library's http.DefaultTransport.
//
// Unlike http.DefaultTransport.(*http.Transport).Clone(), it does not panic
// when a program has replaced http.DefaultTransport with a RoundTripper that
// is not a *http.Transport. In the common case (the global is still the
// standard *http.Transport) it returns a clone of it, preserving the existing
// behavior exactly; otherwise it returns a fresh transport mirroring the
// stdlib defaults.
func NewDefaultTransport() *http.Transport {
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		return tr.Clone()
	}
	// Values copied verbatim from net/http's DefaultTransport.
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewSystemHTTPClient returns an HTTP client that uses dialer for all new
// connections and trusts roots in addition to the platform's default roots.
func NewSystemHTTPClient(dialer netx.DialFunc, roots *x509.CertPool) *http.Client {
	tr := NewDefaultTransport()
	if dialer != nil {
		tr.Dial = nil
		tr.DialContext = dialer
		tr.DialTLS = nil
		tr.DialTLSContext = nil
	}
	if roots != nil {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = new(tls.Config)
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{Transport: tr}
}

// NewOneConnListener returns a net.Listener that returns c on its
// first Accept and EOF thereafter.
//
// The returned Listener's Addr method returns addr if non-nil. If nil,
// Addr returns a non-nil dummy address instead.
func NewOneConnListener(c net.Conn, addr net.Addr) net.Listener {
	if addr == nil {
		addr = dummyAddr("one-conn-listener")
	}
	return &oneConnListener{
		addr: addr,
		conn: c,
	}
}

type oneConnListener struct {
	addr net.Addr

	mu   syncs.Mutex
	conn net.Conn
}

func (ln *oneConnListener) Accept() (c net.Conn, err error) {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	c = ln.conn
	if c == nil {
		err = io.EOF
		return
	}
	err = nil
	ln.conn = nil
	return
}

func (ln *oneConnListener) Addr() net.Addr { return ln.addr }

func (ln *oneConnListener) Close() error {
	ln.Accept() // guarantee future call returns io.EOF
	return nil
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// NewDrainBufConn returns a net.Conn conditionally wrapping c,
// prefixing any bytes that are in initialReadBuf, which may be nil.
func NewDrainBufConn(c net.Conn, initialReadBuf *bufio.Reader) net.Conn {
	r := initialReadBuf
	if r != nil && r.Buffered() == 0 {
		r = nil
	}
	return &drainBufConn{c, r}
}

// drainBufConn is a net.Conn with an initial bunch of bytes in a
// bufio.Reader. Read drains the bufio.Reader until empty, then passes
// through subsequent reads to the Conn directly.
type drainBufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *drainBufConn) Read(bs []byte) (int, error) {
	if b.r == nil {
		return b.Conn.Read(bs)
	}
	n, err := b.r.Read(bs)
	if b.r.Buffered() == 0 {
		b.r = nil
	}
	return n, err
}

// NewAltReadWriteCloserConn returns a net.Conn that wraps rwc (for
// Read, Write, and Close) and c (for all other methods).
func NewAltReadWriteCloserConn(rwc io.ReadWriteCloser, c net.Conn) net.Conn {
	return wrappedConn{c, rwc}
}

type wrappedConn struct {
	net.Conn
	rwc io.ReadWriteCloser
}

func (w wrappedConn) Read(bs []byte) (int, error) {
	return w.rwc.Read(bs)
}

func (w wrappedConn) Write(bs []byte) (int, error) {
	return w.rwc.Write(bs)
}

func (w wrappedConn) Close() error {
	return w.rwc.Close()
}
