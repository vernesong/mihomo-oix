package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"

	D "github.com/miekg/dns"
)

type dnsClientFunc func(context.Context, *D.Msg) (*D.Msg, error)

func (f dnsClientFunc) ExchangeContext(ctx context.Context, msg *D.Msg) (*D.Msg, error) {
	return f(ctx, msg)
}

func (dnsClientFunc) Address() string { return "test" }

func (dnsClientFunc) ResetConnection() {}

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
