package dns

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

func newTestDNSUpstream(t *testing.T, handler D.HandlerFunc) NameServer {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{})
	done := make(chan error, 1)
	server := &D.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() {
		if err := server.Shutdown(); err != nil {
			t.Error(err)
		}
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return NameServer{Net: "udp", Addr: pc.LocalAddr().String()}
}

func TestResolverLookupIPWithOnlyAAAA(t *testing.T) {
	upstream := newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
		reply := new(D.Msg)
		reply.SetReply(q)
		if q.Question[0].Qtype == D.TypeAAAA {
			reply.Answer = []D.RR{&D.AAAA{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeAAAA, Class: D.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::42")}}
		}
		if err := w.WriteMsg(reply); err != nil {
			t.Error(err)
		}
	})
	r := NewResolver(Config{Main: []NameServer{upstream}, IPv6: true, IPv6Timeout: 1000})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	ips, err := r.LookupIP(ctx, "ipv6-only.example")
	if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("2001:db8::42") {
		t.Fatalf("LookupIP() = %v, %v; want the available IPv6 address", ips, err)
	}
}

func TestResolverFallbackDomainAppliesToAllQuestionTypes(t *testing.T) {
	var mainCalls, fallbackCalls, policyCalls atomic.Int32
	upstream := func(counter *atomic.Int32) NameServer {
		return newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
			counter.Add(1)
			reply := new(D.Msg)
			reply.SetReply(q)
			if err := w.WriteMsg(reply); err != nil {
				t.Error(err)
			}
		})
	}
	main := upstream(&mainCalls)
	fallback := upstream(&fallbackCalls)
	policy := upstream(&policyCalls)
	domains := trie.New[struct{}]()
	if err := domains.Insert("+.video.example", struct{}{}); err != nil {
		t.Fatal(err)
	}
	for _, withPolicy := range []bool{false, true} {
		cfg := Config{Main: []NameServer{main}, Fallback: []NameServer{fallback}, FallbackDomainFilter: []C.DomainMatcher{domains.NewDomainSet()}}
		expected := "fallback"
		counter := &fallbackCalls
		if withPolicy {
			cfg.Policy = []Policy{{Domain: "+.video.example", NameServers: []NameServer{policy}}}
			expected = "policy"
			counter = &policyCalls
		}
		r := NewResolver(cfg)
		for _, kind := range []uint16{D.TypeA, D.TypeAAAA, D.TypeCNAME, D.TypeHTTPS, D.TypeSVCB, D.TypeTXT} {
			t.Run(expected+"/"+D.TypeToString[kind], func(t *testing.T) {
				query := new(D.Msg)
				query.SetQuestion("cdn.video.example.", kind)
				before := counter.Load()
				_, err := r.ExchangeContext(t.Context(), query)
				if err != nil {
					t.Fatal(err)
				}
				if counter.Load() != before+1 {
					t.Fatalf("query did not reach %s", expected)
				}
			})
		}
	}
	if mainCalls.Load() != 0 || fallbackCalls.Load() != 6 || policyCalls.Load() != 6 {
		t.Errorf("upstream queries: main=%d fallback=%d policy=%d", mainCalls.Load(), fallbackCalls.Load(), policyCalls.Load())
	}
}

func TestResolverRefreshWithZeroTTLDiscardsOldAnswer(t *testing.T) {
	var calls atomic.Int32
	upstream := newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
		calls.Add(1)
		reply := new(D.Msg)
		reply.SetReply(q)
		if q.Question[0].Name != "empty.example." {
			reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 0}, A: net.ParseIP("192.0.2.2")}}
		}
		if err := w.WriteMsg(reply); err != nil {
			t.Error(err)
		}
	})
	for _, algorithm := range []string{"lru", "arc"} {
		for _, host := range []string{"rotating.example.", "empty.example."} {
			t.Run(algorithm+"/"+host, func(t *testing.T) {
				r := NewResolver(Config{Main: []NameServer{upstream}, CacheAlgorithm: algorithm})
				q := new(D.Msg)
				q.SetQuestion(host, D.TypeA)
				stale := new(D.Msg)
				stale.SetReply(q)
				stale.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.1")}}
				r.cache.SetWithExpire(q.Question[0].String(), stale, time.Now().Add(-time.Minute))
				// Execute the exact refresh path synchronously so the next request cannot
				// race with an outstanding background refresh.
				if _, err := r.exchangeWithoutCache(t.Context(), q); err != nil {
					t.Fatal(err)
				}
				if _, _, hit := getMsgFromCache(r.cache, q.Question[0]); hit {
					t.Fatal("a completed TTL=0 refresh left a stale answer reusable")
				}
				before := calls.Load()
				for range 2 {
					reply, err := r.ExchangeContext(t.Context(), q)
					if err != nil {
						t.Fatal(err)
					}
					if host == "empty.example." {
						if len(reply.Answer) != 0 {
							t.Fatal("empty refresh retained the old answer")
						}
						continue
					}
					if ips := msgToIP(reply); len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.2") {
						t.Fatalf("served superseded address: %v", ips)
					}
					if reply.Answer[0].Header().Ttl != 0 {
						t.Fatal("TTL=0 response was made cacheable")
					}
				}
				if got := calls.Load() - before; got != 2 {
					t.Fatalf("TTL=0 requests made %d upstream queries, want 2", got)
				}
			})
		}
	}
}

func TestResolverDirectNameserverPolicyAndCacheIsolation(t *testing.T) {
	upstream := func(ip string) NameServer {
		return newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
			reply := new(D.Msg)
			reply.SetReply(q)
			reply.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}}
			if err := w.WriteMsg(reply); err != nil {
				t.Error(err)
			}
		})
	}
	main, direct, policy := upstream("192.0.2.1"), upstream("192.0.2.2"), upstream("192.0.2.3")
	for _, follow := range []bool{false, true} {
		r := NewResolver(Config{
			Main: []NameServer{main}, DirectServer: []NameServer{direct}, DirectFollowPolicy: follow,
			Policy: []Policy{{Domain: "+.policy.example", NameServers: []NameServer{policy}}},
		})
		for range 2 { // Repeat against each resolver's own cache.
			for _, tc := range []struct {
				resolver *Resolver
				host     string
				want     string
			}{
				{r.Resolver, "plain.example", "192.0.2.1"},
				{r.DirectResolver, "plain.example", "192.0.2.2"},
				{r.Resolver, "cdn.policy.example", "192.0.2.3"},
				{r.DirectResolver, "cdn.policy.example", "192.0.2.2"},
			} {
				if follow && tc.resolver == r.DirectResolver && tc.host == "cdn.policy.example" {
					tc.want = "192.0.2.3"
				}
				ips, err := tc.resolver.LookupIPv4(t.Context(), tc.host)
				if err != nil || len(ips) != 1 || ips[0].String() != tc.want {
					t.Fatalf("follow=%v host=%s: got %v, %v, want %s", follow, tc.host, ips, err, tc.want)
				}
			}
		}
	}
}

func TestResolverSharedTransportKeepsQueryFiltersSeparate(t *testing.T) {
	upstream := newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
		reply := new(D.Msg)
		reply.SetReply(q)
		header := D.RR_Header{Name: q.Question[0].Name, Rrtype: q.Question[0].Qtype, Class: D.ClassINET, Ttl: 60}
		switch header.Rrtype {
		case D.TypeAAAA:
			reply.Answer = []D.RR{&D.AAAA{Hdr: header, AAAA: net.ParseIP("2001:db8::42")}}
		case D.TypeHTTPS:
			reply.Answer = []D.RR{&D.HTTPS{SVCB: D.SVCB{Hdr: header, Priority: 1, Target: "."}}}
		}
		if err := w.WriteMsg(reply); err != nil {
			t.Error(err)
		}
	})
	main, proxy := upstream, upstream
	main.Params = map[string]string{"disable-ipv6": "true"}
	proxy.Params = map[string]string{"disable-qtype-65": "true"}
	r := NewResolver(Config{Main: []NameServer{main}, DirectServer: []NameServer{upstream}, ProxyServer: []NameServer{proxy}, IPv6: true})
	for range 2 {
		for _, tc := range []struct {
			resolver *Resolver
			qtype    uint16
			answers  int
		}{
			{r.Resolver, D.TypeAAAA, 0},
			{r.DirectResolver, D.TypeAAAA, 1},
			{r.ProxyResolver, D.TypeAAAA, 1},
			{r.ProxyResolver, D.TypeHTTPS, 0},
			{r.Resolver, D.TypeHTTPS, 1},
			{r.DirectResolver, D.TypeHTTPS, 1},
		} {
			q := new(D.Msg)
			q.SetQuestion("cdn.example.", tc.qtype)
			reply, err := tc.resolver.ExchangeContext(t.Context(), q)
			if err != nil {
				t.Fatal(err)
			}
			if len(reply.Answer) != tc.answers {
				t.Fatalf("%s filter leaked between resolvers: %v", D.TypeToString[tc.qtype], reply.Answer)
			}
		}
	}
}
