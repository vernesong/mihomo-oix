package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

type dnsClientFunc func(context.Context, *D.Msg) (*D.Msg, error)

func (f dnsClientFunc) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	return f(ctx, msg)
}

func (dnsClientFunc) Address() string { return "test" }

func (dnsClientFunc) ResetConnection() {}

func useManagedDNSClient(t *testing.T, client dnsClient) {
	t.Helper()
	const addr = "127.0.0.1:65353"
	oldKey, oldDomains, oldAddr := oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr
	wasEnsured := oixdns.IsEnsured()
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	oixdns.NodesDomains, oixdns.DNSAddr = "cloud-nodes.example", addr
	oixdns.SetEnsured()
	oixClientCache.Lock()
	previousAddr, previousClient := oixClientCache.addr, oixClientCache.client
	oixClientCache.addr, oixClientCache.client = addr, client
	oixClientCache.Unlock()
	t.Cleanup(func() {
		oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr = oldKey, oldDomains, oldAddr
		if !wasEnsured {
			oixdns.ClearEnsured()
		}
		oixClientCache.Lock()
		oixClientCache.addr, oixClientCache.client = previousAddr, previousClient
		oixClientCache.Unlock()
	})
}

func TestManagedDNSServiceSignsOnceAndRestoresReply(t *testing.T) {
	const name = "node.cloud-nodes.example."
	var calls int
	useManagedDNSClient(t, dnsClientFunc(func(_ context.Context, query *D.Msg) (*D.Msg, error) {
		calls++
		if got := query.Question[0].Name; D.CountLabel(got) != D.CountLabel(name)+2 || !strings.HasSuffix(got, "."+name) {
			t.Errorf("managed query must be signed exactly once, got %q", got)
		}
		reply := new(D.Msg)
		reply.SetReply(query)
		reply.Answer = []D.RR{&D.A{
			Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
			A:   net.IPv4(192, 0, 2, 1),
		}}
		return reply, nil
	}))
	r := &Resolver{cache: Config{}.newCache()}
	service := NewService(r, NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSNormal}))
	for i := 0; i < 2; i++ {
		query := new(D.Msg)
		query.SetQuestion(name, D.TypeA)
		reply, err := service.ServeMsg(context.Background(), query)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Id != query.Id || reply.Question[0] != query.Question[0] {
			t.Fatalf("reply does not match original query: %v", reply.Question)
		}
		if len(reply.Answer) != 1 || reply.Answer[0].Header().Name != name {
			t.Fatalf("answer does not match original name: %v", reply.Answer)
		}
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 with cached reply", calls)
	}
}

func TestManagedDNSFakeIPKeepsOriginalName(t *testing.T) {
	useManagedDNSClient(t, dnsClientFunc(func(_ context.Context, _ *D.Msg) (*D.Msg, error) {
		t.Error("fake IP lookup unexpectedly reached upstream")
		return nil, nil
	}))
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.0/16"), Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(&Resolver{cache: Config{}.newCache()}, NewEnhancer(EnhancerConfig{
		EnhancedMode: C.DNSFakeIP, FakeIPPool: pool, FakeIPSkipper: &fakeip.Skipper{},
	}))
	query := new(D.Msg)
	query.SetQuestion("node.cloud-nodes.example.", D.TypeA)
	reply, err := service.ServeMsg(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Question[0] != query.Question[0] || reply.Answer[0].Header().Name != query.Question[0].Name {
		t.Fatalf("fake IP response contains signed name: %v", reply)
	}
	ips := msgToIP(reply)
	if host, ok := pool.LookBack(ips[0]); !ok || host != "node.cloud-nodes.example" {
		t.Fatalf("fake IP mapping = %q, %v", host, ok)
	}
}

func TestManagedDNSResolveECHSignsOnce(t *testing.T) {
	const host = "node.cloud-nodes.example"
	client := dnsClientFunc(func(_ context.Context, query *D.Msg) (*D.Msg, error) {
		if got := query.Question[0].Name; D.CountLabel(got) != D.CountLabel(host)+2 {
			t.Errorf("ECH query must be signed exactly once, got %q", got)
		}
		reply := new(D.Msg)
		reply.SetReply(query)
		reply.Answer = []D.RR{&D.HTTPS{SVCB: D.SVCB{
			Hdr:      D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: 60},
			Priority: 1, Target: ".", Value: []D.SVCBKeyValue{&D.SVCBECHConfig{ECH: []byte{1, 2, 3}}},
		}}}
		return reply, nil
	})
	useManagedDNSClient(t, client)
	r := &Resolver{cache: Config{}.newCache(), main: []dnsClient{client}}
	config, err := resolver.ResolveECHWithResolver(context.Background(), host, r)
	if err != nil || string(config) != string([]byte{1, 2, 3}) {
		t.Fatalf("ResolveECHWithResolver() = %v, %v", config, err)
	}
}

func TestManagedDNSCacheDropsOPTAndHonorsRecordTTLs(t *testing.T) {
	query := new(D.Msg)
	query.SetQuestion("node.cloud-nodes.example.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(query)
	reply.Answer = []D.RR{&D.A{
		Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 1),
	}}
	reply.Ns = []D.RR{&D.NS{
		Hdr: D.RR_Header{Name: "cloud-nodes.example.", Rrtype: D.TypeNS, Class: D.ClassINET, Ttl: 60},
		Ns:  "ns.cloud-nodes.example.",
	}}
	reply.SetEdns0(4096, true)
	cache := Config{}.newCache()
	putoixMsgToCache(cache, query.Question[0], reply)
	cached, expires, ok := getMsgFromCache(cache, query.Question[0])
	if !ok {
		t.Fatal("successful managed response was not cached")
	}
	if cached.IsEdns0() != nil {
		t.Fatal("cached response retains per-hop OPT record")
	}
	if cached.Ns[0].Header().Ttl != 60 || time.Until(expires) > time.Minute {
		t.Fatalf("cache extended authoritative TTL: %v, %s", cached.Ns, time.Until(expires))
	}
	if reply.IsEdns0() == nil || reply.Answer[0].Header().Ttl != 300 {
		t.Fatal("caching mutated caller response")
	}
}

func TestManagedDNSHedgesTCPWhenUDPIsBlackholed(t *testing.T) {
	udp := dnsClientFunc(func(ctx context.Context, _ *D.Msg) (*D.Msg, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	tcp := dnsClientFunc(func(ctx context.Context, request *D.Msg) (*D.Msg, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		response := new(D.Msg)
		response.SetReply(request)
		return response, nil
	})
	client := &oixDNSClient{udp: udp, tcp: tcp}
	request := new(D.Msg)
	request.SetQuestion("node.cloud-nodes.example.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := time.Now()
	response, err := client.ExchangeContext(ctx, request)
	if err != nil {
		t.Fatalf("ExchangeContext() error = %v", err)
	}
	if response == nil {
		t.Fatal("ExchangeContext() response is nil")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("TCP fallback took %s", elapsed)
	}
}

func TestManagedDNSDoesNotMutateCallerQuestion(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	const managedAddr = "127.0.0.1:65353"
	oldKey, oldDomains, oldAddr := oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(seed)
	oixdns.NodesDomains = "cloud-nodes.example"
	oixdns.DNSAddr = managedAddr
	oixdns.SetEnsured()
	t.Cleanup(func() {
		oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr = oldKey, oldDomains, oldAddr
		oixdns.ClearEnsured()
		oixdns.ResetManagedDNS()
	})

	const question = "node1.cloud-nodes.example."
	request := new(D.Msg)
	request.SetQuestion(question, D.TypeA)

	var observed string
	fake := dnsClientFunc(func(_ context.Context, query *D.Msg) (*D.Msg, error) {
		observed = query.Question[0].Name
		if name := request.Question[0].Name; name != question {
			t.Errorf("caller question mutated to %q while the query is in flight", name)
		}
		reply := new(D.Msg)
		reply.SetReply(query)
		reply.Answer = append(reply.Answer, &D.A{
			Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
			A:   net.IPv4(127, 0, 0, 1),
		})
		return reply, nil
	})

	oixClientCache.Lock()
	previousAddr, previousClient := oixClientCache.addr, oixClientCache.client
	oixClientCache.addr, oixClientCache.client = managedAddr, fake
	oixClientCache.Unlock()
	t.Cleanup(func() {
		oixClientCache.Lock()
		oixClientCache.addr, oixClientCache.client = previousAddr, previousClient
		oixClientCache.Unlock()
	})

	r := &Resolver{cache: Config{}.newCache()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	response, err := r.exchangeWithoutCache(ctx, request)
	if err != nil {
		t.Fatalf("exchangeWithoutCache() error = %v", err)
	}
	if response == nil {
		t.Fatal("exchangeWithoutCache() response is nil")
	}
	if !strings.HasSuffix(observed, "."+question) || observed == "."+question {
		t.Fatalf("query name %q is not an obfuscated cloud domain", observed)
	}
	if name := request.Question[0].Name; name != question {
		t.Fatalf("caller question = %q, want %q", name, question)
	}
}

func TestManagedDNSHedgesTCPOverNetworkWhenUDPIsBlackholed(t *testing.T) {
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenPacket("udp4", tcpListener.Addr().String())
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udpConn.Close() })

	server := &D.Server{
		Listener: tcpListener,
		Handler: D.HandlerFunc(func(w D.ResponseWriter, request *D.Msg) {
			response := new(D.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, &D.A{
				Hdr: D.RR_Header{Name: request.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
				A:   net.IPv4(127, 0, 0, 1),
			})
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	addr := tcpListener.Addr().String()
	client := &oixDNSClient{
		udp: newClient(addr, nil, "udp", nil, nil, ""),
		tcp: newClient(addr, nil, "tcp", nil, nil, ""),
	}
	request := new(D.Msg)
	request.SetQuestion("node.cloud-nodes.example.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	started := time.Now()
	response, err := client.ExchangeContext(ctx, request)
	if err != nil {
		t.Fatalf("ExchangeContext() error = %v", err)
	}
	if ips := msgToIP(response); len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("ExchangeContext() IPs = %v", ips)
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("TCP hedge took %s", elapsed)
	}
}

func TestSystemResolverUsesManagedDNSForCloudDomains(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var lastQname atomic.Value
	srv := &D.Server{
		PacketConn: pc,
		Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
			lastQname.Store(req.Question[0].Name)
			reply := new(D.Msg)
			reply.SetReply(req)
			reply.Answer = append(reply.Answer, &D.A{
				Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
				A:   net.IPv4(127, 0, 0, 1),
			})
			_ = w.WriteMsg(reply)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}

	oldKey, oldDomains, oldAddr := oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(seed)
	oixdns.NodesDomains = "cloud-nodes.example"
	oixdns.DNSAddr = pc.LocalAddr().String()
	oixdns.SetEnsured()
	t.Cleanup(func() {
		oixdns.DNSPrivateKey, oixdns.NodesDomains, oixdns.DNSAddr = oldKey, oldDomains, oldAddr
		oixdns.ClearEnsured()
		oixdns.ResetManagedDNS()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := resolver.LookupIPv4WithResolver(ctx, "node1.cloud-nodes.example", nil)
	if err != nil {
		t.Fatalf("LookupIPv4WithResolver() error = %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "127.0.0.1" {
		t.Fatalf("ips = %v, want [127.0.0.1]", ips)
	}

	qname, _ := lastQname.Load().(string)
	if qname == "" {
		t.Fatal("managed DNS server received no query")
	}
	if !strings.HasSuffix(qname, ".node1.cloud-nodes.example.") {
		t.Fatalf("query name %q not an obfuscated cloud domain", qname)
	}
	if strings.TrimSuffix(qname, ".node1.cloud-nodes.example.") == "" {
		t.Fatalf("query name %q missing obfuscation labels", qname)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	oldProxyResolver := resolver.ProxyServerHostResolver
	resolver.ProxyServerHostResolver = nil
	t.Cleanup(func() { resolver.ProxyServerHostResolver = oldProxyResolver })
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort("node2.cloud-nodes.example", port))
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("accept managed DNS connection: %v", err)
	}
}
