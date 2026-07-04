package outboundgroup

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type urlTestFakeProxy struct {
	name      string
	alive     bool
	delay     uint16
	dialErr   error
	listenErr error
	conn      C.Conn
}

func newURLTestFakeProxy(name string, delay uint16) *urlTestFakeProxy {
	return &urlTestFakeProxy{
		name:  name,
		alive: true,
		delay: delay,
	}
}

func (p *urlTestFakeProxy) Name() string { return p.name }

func (p *urlTestFakeProxy) Type() C.AdapterType { return C.Socks5 }

func (p *urlTestFakeProxy) Addr() string { return "" }

func (p *urlTestFakeProxy) SupportUDP() bool { return true }

func (p *urlTestFakeProxy) ProxyInfo() C.ProxyInfo { return C.ProxyInfo{} }

func (p *urlTestFakeProxy) MarshalJSON() ([]byte, error) { return nil, nil }

func (p *urlTestFakeProxy) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	if p.dialErr == nil && p.conn != nil {
		return p.conn, nil
	}
	return nil, p.dialErr
}

func (p *urlTestFakeProxy) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	return nil, p.listenErr
}

func (p *urlTestFakeProxy) SupportUOT() bool { return false }

func (p *urlTestFakeProxy) IsL3Protocol(*C.Metadata) bool { return false }

func (p *urlTestFakeProxy) Unwrap(*C.Metadata, bool) C.Proxy { return p }

func (p *urlTestFakeProxy) Close() error { return nil }

func (p *urlTestFakeProxy) Adapter() C.ProxyAdapter { return p }

func (p *urlTestFakeProxy) AliveForTestUrl(string) bool { return p.alive }

func (p *urlTestFakeProxy) DelayHistory() []C.DelayHistory { return nil }

func (p *urlTestFakeProxy) DelayHistoryForTestUrl(string) []C.DelayHistory { return nil }

func (p *urlTestFakeProxy) ExtraDelayHistories() map[string]C.ProxyState { return nil }

func (p *urlTestFakeProxy) LastDelayForTestUrl(string) uint16 { return p.delay }

func (p *urlTestFakeProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	return p.delay, nil
}

func (p *urlTestFakeProxy) StatusTest(context.Context, string) (uint16, bool, error) {
	return 0, false, nil
}

type urlTestFakeProvider struct {
	proxies []C.Proxy
}

func (p *urlTestFakeProvider) Name() string { return "fake" }

func (p *urlTestFakeProvider) VehicleType() P.VehicleType { return P.Compatible }

func (p *urlTestFakeProvider) Type() P.ProviderType { return P.Proxy }

func (p *urlTestFakeProvider) Path() string { return "" }

func (p *urlTestFakeProvider) Initial() error { return nil }

func (p *urlTestFakeProvider) Update() error { return nil }

func (p *urlTestFakeProvider) Proxies() []C.Proxy { return p.proxies }

func (p *urlTestFakeProvider) Count() int { return len(p.proxies) }

func (p *urlTestFakeProvider) Touch() {}

func (p *urlTestFakeProvider) HealthCheck() {}

func (p *urlTestFakeProvider) Version() uint32 { return 1 }

func (p *urlTestFakeProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}

func (p *urlTestFakeProvider) HealthCheckURL() string { return "" }

type urlTestFakeConn struct {
	writeErr      error
	needHandshake bool
}

func (c *urlTestFakeConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *urlTestFakeConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func (c *urlTestFakeConn) Close() error { return nil }

func (c *urlTestFakeConn) LocalAddr() net.Addr { return nil }

func (c *urlTestFakeConn) RemoteAddr() net.Addr { return nil }

func (c *urlTestFakeConn) SetDeadline(time.Time) error { return nil }

func (c *urlTestFakeConn) SetReadDeadline(time.Time) error { return nil }

func (c *urlTestFakeConn) SetWriteDeadline(time.Time) error { return nil }

func (c *urlTestFakeConn) ReadBuffer(*buf.Buffer) error { return io.EOF }

func (c *urlTestFakeConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	_, err := c.Write(buffer.Bytes())
	return err
}

func (c *urlTestFakeConn) NeedHandshake() bool { return c.needHandshake }

func (c *urlTestFakeConn) Chains() C.Chain { return nil }

func (c *urlTestFakeConn) ProviderChains() C.Chain { return nil }

func (c *urlTestFakeConn) AppendToChains(C.ProxyAdapter) {}

func (c *urlTestFakeConn) RemoteDestination() string { return "" }

func TestURLTestDropsCachedProxyWhenHealthTurnsFalse(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	fast := newURLTestFakeProxy("fast", 10)
	slower := newURLTestFakeProxy("slower", 50)
	provider := &urlTestFakeProvider{proxies: []C.Proxy{fast, slower}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, slower, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	if got := group.Now(); got != "fast" {
		t.Fatalf("initial selection mismatch: got %q, want %q", got, "fast")
	}

	fast.alive = false

	if got := group.Now(); got != "slower" {
		t.Fatalf("stale selection was not dropped: got %q, want %q", got, "slower")
	}
}

func TestURLTestSelectFastKeepsColdSelectionPolicyWhenFirstProxyIsDead(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	first := newURLTestFakeProxy("first", 10)
	second := newURLTestFakeProxy("second", 50)
	first.alive = false
	provider := &urlTestFakeProvider{proxies: []C.Proxy{first, second}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, second, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	if got := group.selectFast(provider.proxies, nil).Name(); got != "first" {
		t.Fatalf("cold selection policy changed: got %q, want %q", got, "first")
	}
}

func TestURLTestResetsCachedProxyAfterDialFailure(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	failing := newURLTestFakeProxy("failing", 10)
	backup := newURLTestFakeProxy("backup", 50)
	failing.dialErr = errors.New("dial failed")
	provider := &urlTestFakeProvider{proxies: []C.Proxy{failing, backup}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, backup, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := group.DialContext(context.Background(), &C.Metadata{}); err == nil {
		t.Fatal("expected dial failure")
	}

	failing.alive = false

	if got := group.Now(); got != "backup" {
		t.Fatalf("dial failure did not clear stale cached proxy: got %q, want %q", got, "backup")
	}
}

func TestURLTestResetsCachedProxyAfterListenPacketFailure(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	failing := newURLTestFakeProxy("failing", 10)
	backup := newURLTestFakeProxy("backup", 50)
	failing.listenErr = errors.New("listen failed")
	provider := &urlTestFakeProvider{proxies: []C.Proxy{failing, backup}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, backup, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := group.ListenPacketContext(context.Background(), &C.Metadata{}); err == nil {
		t.Fatal("expected listen failure")
	}

	failing.delay = 100

	if got := group.Now(); got != "backup" {
		t.Fatalf("listen failure did not reset cached proxy before health changed: got %q, want %q", got, "backup")
	}
}

func TestURLTestResetsCachedProxyAfterFirstWriteFailure(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	failing := newURLTestFakeProxy("failing", 10)
	backup := newURLTestFakeProxy("backup", 50)
	failing.conn = &urlTestFakeConn{
		writeErr:      errors.New("first write failed"),
		needHandshake: true,
	}
	provider := &urlTestFakeProvider{proxies: []C.Proxy{failing, backup}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, backup, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := group.DialContext(context.Background(), &C.Metadata{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := conn.Write([]byte("hello")); err == nil {
		t.Fatal("expected first write failure")
	}

	failing.delay = 100

	if got := group.Now(); got != "backup" {
		t.Fatalf("first-write failure did not reset cached proxy before health changed: got %q, want %q", got, "backup")
	}
}

func TestURLTestResetsCachedProxyAfterDialFailureBeforeHealthStateChanges(t *testing.T) {
	const testURL = "https://cp.cloudflare.com/generate_204"
	failing := newURLTestFakeProxy("failing", 10)
	backup := newURLTestFakeProxy("backup", 50)
	failing.dialErr = errors.New("dial failed")
	provider := &urlTestFakeProvider{proxies: []C.Proxy{failing, backup}}

	group, err := NewURLTest(GroupCommonOption{
		Name: "Auto - UrlTest",
		URL:  testURL,
	}, URLTestOption{}, backup, []P.ProxyProvider{provider})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := group.DialContext(context.Background(), &C.Metadata{}); err == nil {
		t.Fatal("expected dial failure")
	}

	failing.delay = 100

	if got := group.Now(); got != "backup" {
		t.Fatalf("dial failure did not reset cached proxy before health changed: got %q, want %q", got, "backup")
	}
}
