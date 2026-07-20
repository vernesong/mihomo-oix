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
