package dns

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

type bootstrapFallbackFixture struct {
	resolver.Resolver
	calls atomic.Int32
}

func (r *bootstrapFallbackFixture) LookupIP(context.Context, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("192.0.2.9")}, nil
}

func TestBootstrapUsesFixedResolverAndKeepsIPv6Answers(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[ipv6], func(t *testing.T) {
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
				r := new(D.Msg).SetReply(q)
				h := D.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: D.ClassINET, Ttl: 60}
				if ipv6 && h.Rrtype == D.TypeAAAA {
					r.Answer = []D.RR{&D.AAAA{Hdr: h, AAAA: net.ParseIP("2001:db8::1")}}
				}
				if !ipv6 && h.Rrtype == D.TypeA {
					r.Answer = []D.RR{&D.A{Hdr: h, A: net.ParseIP("192.0.2.1").To4()}}
				}
				_ = w.WriteMsg(r)
			})}
			go func() { _ = server.ActivateAndServe() }()
			defer server.Shutdown()
			fallback := &bootstrapFallbackFixture{}
			b := NewBootstrapResolver([]string{packet.LocalAddr().String()}, func() resolver.Resolver { return fallback })
			defer b.ResetConnection()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ips, err := b.LookupIP(ctx, "endpoint.fixture.test")
			if err != nil || len(ips) != 1 || ips[0].Is6() != ipv6 || fallback.calls.Load() != 0 {
				t.Fatalf("fixed bootstrap failed: err=%v count=%d fallback=%d", err, len(ips), fallback.calls.Load())
			}
		})
	}
}

func TestBootstrapFallbackCannotOutliveCaller(t *testing.T) {
	fallback := &bootstrapFallbackFixture{}
	b := NewBootstrapResolver(nil, func() resolver.Resolver { return fallback })
	defer b.ResetConnection()
	if ips, err := b.LookupIP(context.Background(), "endpoint.fixture.test"); err != nil || len(ips) != 1 || fallback.calls.Load() != 1 {
		t.Fatal("system fallback was not used after fixed bootstrap failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.LookupIP(ctx, "cancelled.fixture.test"); err == nil || fallback.calls.Load() != 1 {
		t.Fatal("cancelled lookup reached the system fallback")
	}
}

type bootstrapClearClient struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (c *bootstrapClearClient) Address() string  { return "bootstrap-clear-fixture" }
func (c *bootstrapClearClient) ResetConnection() {}
func (c *bootstrapClearClient) ExchangeContext(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	call := c.calls.Add(1)
	if call == 1 {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	reply := new(D.Msg).SetReply(q)
	reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, byte(call))}}
	return reply, nil
}

func TestBootstrapClearDoesNotJoinOrCachePreClearQueries(t *testing.T) {
	client := &bootstrapClearClient{entered: make(chan struct{}), release: make(chan struct{})}
	r := NewResolverFromClient(client)
	b := &bootstrapResolver{Resolver: r, system: func() resolver.Resolver { return nil }}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	old := make(chan error, 1)
	go func() { _, err := b.LookupIPv4(ctx, "network-switch.fixture.test"); old <- err }()
	select {
	case <-client.entered:
	case <-ctx.Done():
		t.Fatal("old bootstrap query did not start")
	}
	b.ClearCache()
	b.ResetConnection()
	freshCtx, freshCancel := context.WithTimeout(ctx, 300*time.Millisecond)
	fresh, err := b.LookupIPv4(freshCtx, "network-switch.fixture.test")
	freshCancel()
	if err != nil || len(fresh) != 1 || fresh[0].String() != "192.0.2.2" {
		t.Errorf("new bootstrap query joined the old exchange: %v %v", fresh, err)
	}
	b.ClearCache()
	close(client.release)
	if err := <-old; err != nil {
		t.Fatal(err)
	}
	q := new(D.Msg).SetQuestion("network-switch.fixture.test.", D.TypeA)
	if _, _, hit := getMsgFromCache(r.cache, q.Question[0]); hit {
		t.Error("old bootstrap query restored the cleared cache")
	}
	fresh, err = b.LookupIPv4(ctx, "network-switch.fixture.test")
	if err != nil || len(fresh) != 1 || fresh[0].String() != "192.0.2.3" {
		t.Fatalf("cleared bootstrap did not remain reusable: %v %v", fresh, err)
	}
}
