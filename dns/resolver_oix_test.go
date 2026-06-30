package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/oix/oixdns"
	D "github.com/miekg/dns"
)

type oixResolverCache struct {
	values map[string]*D.Msg
	expiry map[string]time.Time
}

func newOIXResolverCache() *oixResolverCache {
	return &oixResolverCache{
		values: map[string]*D.Msg{},
		expiry: map[string]time.Time{},
	}
}

func (c *oixResolverCache) GetWithExpire(key string) (*D.Msg, time.Time, bool) {
	msg, ok := c.values[key]
	if !ok {
		return nil, time.Time{}, false
	}
	return msg, c.expiry[key], true
}

func (c *oixResolverCache) SetWithExpire(key string, value *D.Msg, expire time.Time) {
	c.values[key] = value
	c.expiry[key] = expire
}

func (c *oixResolverCache) Clear() {
	c.values = map[string]*D.Msg{}
	c.expiry = map[string]time.Time{}
}

type staticDNSClient struct {
	count  int
	ip     net.IP
	qname  string
	qclass uint16
}

func (c *staticDNSClient) ExchangeContext(_ context.Context, msg *D.Msg) (*D.Msg, error) {
	c.count++
	c.qname = msg.Question[0].Name
	c.qclass = msg.Question[0].Qclass
	resp := msg.Copy()
	resp.SetRcode(msg, D.RcodeSuccess)
	resp.Answer = []D.RR{
		&D.A{
			Hdr: D.RR_Header{Name: msg.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
			A:   c.ip,
		},
	}
	return resp, nil
}

func (c *staticDNSClient) Address() string {
	return "static"
}

func (c *staticDNSClient) ResetConnection() {}

func withOIXDNSState(t *testing.T) {
	t.Helper()

	oldNodesDomains := oixdns.NodesDomains
	oldDNSPrivateKey := oixdns.DNSPrivateKey
	oldEnsured := atomic.LoadInt32(&oixdns.Ensured)

	oixdns.NodesDomains = "example.com"
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	atomic.StoreInt32(&oixdns.Ensured, 0)

	t.Cleanup(func() {
		oixdns.NodesDomains = oldNodesDomains
		oixdns.DNSPrivateKey = oldDNSPrivateKey
		atomic.StoreInt32(&oixdns.Ensured, oldEnsured)
	})
}

func newOIXTestQuery(name string) *D.Msg {
	msg := new(D.Msg)
	msg.SetQuestion(D.Fqdn(name), D.TypeA)
	return msg
}

func firstA(t *testing.T, msg *D.Msg) string {
	t.Helper()

	if len(msg.Answer) == 0 {
		t.Fatal("expected at least one answer")
	}
	rr, ok := msg.Answer[0].(*D.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", msg.Answer[0])
	}
	return rr.A.String()
}

func TestExchangeContextBypassesPreEnsureCacheAfterOIXEnsured(t *testing.T) {
	withOIXDNSState(t)

	mainClient := &staticDNSClient{ip: net.ParseIP("192.0.2.1")}
	oixClient := &staticDNSClient{ip: net.ParseIP("198.51.100.2")}
	resolver := &Resolver{
		main:      []dnsClient{mainClient},
		oixClient: oixClient,
		cache:     newOIXResolverCache(),
	}

	msg, err := resolver.ExchangeContext(context.Background(), newOIXTestQuery("node.example.com"))
	if err != nil {
		t.Fatalf("pre-ensure exchange failed: %v", err)
	}
	if got := firstA(t, msg); got != "192.0.2.1" {
		t.Fatalf("expected pre-ensure main DNS answer, got %s", got)
	}

	oixdns.SetEnsured()
	msg, err = resolver.ExchangeContext(context.Background(), newOIXTestQuery("node.example.com"))
	if err != nil {
		t.Fatalf("post-ensure exchange failed: %v", err)
	}
	if got := firstA(t, msg); got != "198.51.100.2" {
		t.Fatalf("expected post-ensure OIX DNS answer, got %s", got)
	}
	if oixClient.count != 1 {
		t.Fatalf("expected OIX DNS client to be used once, got %d", oixClient.count)
	}
}

func TestExchangeContextCachesOIXAnswersByOriginalQuestion(t *testing.T) {
	withOIXDNSState(t)
	oixdns.SetEnsured()

	oixClient := &staticDNSClient{ip: net.ParseIP("198.51.100.3")}
	resolver := &Resolver{
		oixClient: oixClient,
		cache:     newOIXResolverCache(),
	}

	if _, err := resolver.ExchangeContext(context.Background(), newOIXTestQuery("cache.example.com")); err != nil {
		t.Fatalf("first exchange failed: %v", err)
	}
	if _, err := resolver.ExchangeContext(context.Background(), newOIXTestQuery("cache.example.com")); err != nil {
		t.Fatalf("second exchange failed: %v", err)
	}
	if oixClient.count != 1 {
		t.Fatalf("expected cached OIX answer after first exchange, got %d calls", oixClient.count)
	}
}

func TestExchangeContextRestoresOIXAnswerOwnerNames(t *testing.T) {
	withOIXDNSState(t)
	oixdns.SetEnsured()

	oixClient := &staticDNSClient{ip: net.ParseIP("198.51.100.4")}
	resolver := &Resolver{
		oixClient: oixClient,
		cache:     newOIXResolverCache(),
	}

	msg, err := resolver.ExchangeContext(context.Background(), newOIXTestQuery("owner.example.com"))
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if got := msg.Question[0].Name; got != "owner.example.com." {
		t.Fatalf("expected original question, got %q", got)
	}
	if got := msg.Answer[0].Header().Name; got != "owner.example.com." {
		t.Fatalf("expected original answer owner, got %q", got)
	}
}

func TestExchangeContextKeepsOIXCacheKeysClassSpecific(t *testing.T) {
	withOIXDNSState(t)
	oixdns.SetEnsured()

	oixClient := &staticDNSClient{ip: net.ParseIP("198.51.100.5")}
	resolver := &Resolver{
		oixClient: oixClient,
		cache:     newOIXResolverCache(),
	}

	inQuery := newOIXTestQuery("class.example.com")
	if _, err := resolver.ExchangeContext(context.Background(), inQuery); err != nil {
		t.Fatalf("IN exchange failed: %v", err)
	}
	chaosQuery := newOIXTestQuery("class.example.com")
	chaosQuery.Question[0].Qclass = D.ClassCHAOS
	if _, err := resolver.ExchangeContext(context.Background(), chaosQuery); err != nil {
		t.Fatalf("CHAOS exchange failed: %v", err)
	}

	if oixClient.count != 2 {
		t.Fatalf("expected class-specific OIX cache misses, got %d client calls", oixClient.count)
	}
	if oixClient.qclass != D.ClassCHAOS {
		t.Fatalf("expected second query class to reach OIX client, got %d", oixClient.qclass)
	}
}
