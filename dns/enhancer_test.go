package dns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"

	D "github.com/miekg/dns"
)

func TestMappingExpiresAcrossConfigReload(t *testing.T) {
	old := NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSMapping})
	expired := netip.MustParseAddr("192.0.2.1")
	fresh := netip.MustParseAddr("192.0.2.2")
	inserted := netip.MustParseAddr("192.0.2.3")
	old.mapping.SetWithExpire(expired, "old.example", time.Now().Add(-time.Minute))
	old.mapping.SetWithExpire(fresh, "fresh.example", time.Now().Add(time.Minute))
	old.InsertHostByIP(inserted, "inserted.example")
	current := NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSMapping})
	current.PatchFrom(old)
	for _, enhancer := range []*ResolverEnhancer{old, current} {
		if host, ok := enhancer.FindHostByIP(expired); ok {
			t.Errorf("expired IP still maps to %q", host)
		}
		if host, ok := enhancer.FindHostByIP(fresh); !ok || host != "fresh.example" {
			t.Errorf("fresh mapping lost: %q, %v", host, ok)
		}
		if host, ok := enhancer.FindHostByIP(inserted); !ok || host != "inserted.example" {
			t.Errorf("explicit mapping lost: %q, %v", host, ok)
		}
	}
}

func TestMappingLifetimeIncludesCNAMEChain(t *testing.T) {
	upstream := newTestDNSUpstream(t, func(w D.ResponseWriter, q *D.Msg) {
		reply := new(D.Msg)
		reply.SetReply(q)
		reply.Answer = []D.RR{
			&D.CNAME{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 10}, Target: "edge.example."},
			&D.A{Hdr: D.RR_Header{Name: "edge.example.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 600}, A: net.ParseIP("192.0.2.4")},
		}
		if err := w.WriteMsg(reply); err != nil {
			t.Error(err)
		}
	})
	r := NewResolver(Config{Main: []NameServer{upstream}})
	mapper := NewEnhancer(EnhancerConfig{EnhancedMode: C.DNSMapping})
	service := NewService(r, mapper)
	q := new(D.Msg)
	q.SetQuestion("cdn.example.", D.TypeA)
	before := time.Now()
	if _, err := service.ServeMsg(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	host, expires, hit := mapper.mapping.GetWithExpire(netip.MustParseAddr("192.0.2.4"))
	if !hit || host != "cdn.example" || expires.After(before.Add(11*time.Second)) || !expires.After(before) {
		t.Fatalf("mapping outlives its CNAME: %q, %s, %v", host, expires, hit)
	}
}
