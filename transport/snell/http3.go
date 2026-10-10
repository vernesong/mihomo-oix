package snell

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
)

// HTTP3Client shares one ECH-verified QUIC session across independent Snell
// streams. The caller owns its lifetime and must call Close on config reload.
type HTTP3Client struct {
	Host string
	Path string
	Dial func(context.Context) (*quic.Conn, error)
	// DialTimeout bounds a session dial, which no single Open cancels; zero is 10 s.
	DialTimeout time.Duration
	mu          sync.Mutex
	closed      bool
	pending     *http3Dial
	conn        *quic.Conn
	client      *http3.ClientConn
	connections map[*quic.Conn]int
}

type http3Dial struct {
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

// get returns the current session, joining or starting its dial. The dial runs
// detached from every caller: one that gives up leaves it running for the others,
// and a failure reaches all of its waiters instead of each starting another dial.
func (c *HTTP3Client) get(ctx context.Context) (*quic.Conn, *http3.ClientConn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, nil, net.ErrClosed
		}
		if c.conn != nil && c.conn.Context().Err() == nil {
			conn, client := c.conn, c.client
			c.connections[conn]++
			c.mu.Unlock()
			return conn, client, nil
		}
		pending := c.pending
		if pending == nil {
			timeout := c.DialTimeout
			if timeout <= 0 {
				timeout = 10 * time.Second
			}
			dialCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
			pending = &http3Dial{cancel: cancel, done: make(chan struct{})}
			c.pending = pending
			go c.dial(dialCtx, pending)
		}
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-pending.done:
		}
		if pending.err != nil {
			return nil, nil, pending.err
		}
	}
}

func (c *HTTP3Client) dial(ctx context.Context, pending *http3Dial) {
	conn, err := c.Dial(ctx)
	pending.cancel()
	if err == nil {
		state := conn.ConnectionState().TLS
		if !state.ECHAccepted || state.NegotiatedProtocol != http3.NextProtoH3 {
			_ = conn.CloseWithError(0, "")
			err = errors.New("snell HTTP/3 requires accepted ECH and h3 ALPN")
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed && err == nil {
		_ = conn.CloseWithError(0, "")
		err = net.ErrClosed
	}
	if err == nil {
		// Waiters take their references as they return; a session no one waits
		// for any more stays current for the next Open.
		c.conn = conn
		c.client = (&http3.Transport{DisableCompression: true, MaxResponseHeaderBytes: 8 * 1024}).NewClientConn(conn)
		if c.connections == nil {
			c.connections = make(map[*quic.Conn]int)
		}
		c.connections[conn] = 0
		context.AfterFunc(conn.Context(), func() {
			c.mu.Lock()
			delete(c.connections, conn)
			c.mu.Unlock()
		})
	}
	pending.err = err
	close(pending.done)
	c.pending = nil
}

// SmoothedRTT reports the current session's smoothed round-trip time, or zero
// while no session is up.
func (c *HTTP3Client) SmoothedRTT() time.Duration {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil || conn.Context().Err() != nil {
		return 0
	}
	return conn.ConnectionStats().SmoothedRTT
}

// Open completes Extended CONNECT before returning a stream. It never sends
// Snell authentication or business data on a failed / retried transport.
func (c *HTTP3Client) Open(ctx context.Context) (_ net.Conn, exporter []byte, err error) {
	conn, client, err := c.get(ctx)
	if err != nil {
		return nil, nil, err
	}
	var stream *http3Conn
	defer func() {
		if err != nil {
			if stream != nil {
				_ = stream.Close()
			} else {
				c.release(conn)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-conn.Context().Done():
		return nil, nil, context.Cause(conn.Context())
	case <-client.ReceivedSettings():
	}
	if !client.Settings().EnableExtendedConnect {
		return nil, nil, errors.New("snell server did not enable Extended CONNECT")
	}
	request, err := client.OpenRequestStream(ctx)
	if err != nil {
		if ctx.Err() == nil {
			c.retire(conn)
		}
		return nil, nil, err
	}
	stream = &http3Conn{
		RequestStream: request, local: conn.LocalAddr(), remote: conn.RemoteAddr(),
		release: func() { c.release(conn) },
	}
	done := N.SetupContextForConn(ctx, stream)
	defer done(&err)
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}
	stream.writeMu.Lock()
	err = request.SendRequestHeader(&http.Request{
		Method: http.MethodConnect, Proto: "websocket", Host: c.Host,
		URL: &url.URL{Scheme: "https", Host: c.Host, Path: c.Path},
	})
	stream.writeMu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	response, err := request.ReadResponse()
	if err != nil {
		return nil, nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusServiceUnavailable {
			c.retire(conn)
		}
		return nil, nil, fmt.Errorf("snell HTTP/3 CONNECT status %d", response.StatusCode)
	}
	state := conn.ConnectionState().TLS
	exporter, err = state.ExportKeyingMaterial(IdentityExporterLabel, []byte{}, IdentityExporterLength)
	if err != nil {
		return nil, nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, exporter, nil
}

// A draining peer can refuse new streams while existing ones still carry
// traffic. Pending CONNECTs also hold a reference until they fail or close.
func (c *HTTP3Client) retire(conn *quic.Conn) {
	c.mu.Lock()
	if c.conn == conn {
		c.conn, c.client = nil, nil
	}
	idle := c.connections[conn] == 0
	c.mu.Unlock()
	if idle {
		_ = conn.CloseWithError(0, "")
	}
}

func (c *HTTP3Client) release(conn *quic.Conn) {
	c.mu.Lock()
	active, tracked := c.connections[conn]
	if tracked {
		active--
		c.connections[conn] = active
	}
	closeConn := tracked && active == 0 && c.conn != conn
	c.mu.Unlock()
	if closeConn {
		_ = conn.CloseWithError(0, "")
	}
}

func (c *HTTP3Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.pending != nil {
		c.pending.cancel()
	}
	for conn := range c.connections {
		_ = conn.CloseWithError(0, "")
	}
	return nil
}

type http3Conn struct {
	*http3.RequestStream
	local, remote net.Addr
	writeMu       sync.Mutex
	closed        atomic.Bool
	release       func()
}

func (c *http3Conn) LocalAddr() net.Addr  { return c.local }
func (c *http3Conn) RemoteAddr() net.Addr { return c.remote }
func (c *http3Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.RequestStream.Write(b)
}

func (c *http3Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.RequestStream.Close()
}

func (c *http3Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	defer c.release()
	c.CancelRead(0)
	_ = c.SetWriteDeadline(time.Now())
	return c.CloseWrite()
}
