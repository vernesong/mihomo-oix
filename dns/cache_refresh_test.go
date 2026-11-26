package dns

import (
	"testing"
	"time"

	D "github.com/miekg/dns"
)

func TestNegativeRefreshHonorsSOAMinimumAndZero(t *testing.T) {
	for _, minimum := range []uint32{5, 0} {
		cache := Config{}.newCache()
		query := new(D.Msg)
		query.SetQuestion("node.fixture.example.", D.TypeA)
		reply := new(D.Msg)
		reply.SetReply(query)
		reply.Answer = []D.RR{&D.CNAME{Hdr: D.RR_Header{Name: query.Question[0].Name, Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 300}, Target: "absent.fixture.example."}}
		reply.Ns = []D.RR{&D.SOA{Hdr: D.RR_Header{Name: "fixture.example.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 60}, Ns: "ns.fixture.example.", Mbox: "admin.fixture.example.", Minttl: minimum}}
		putMsgToCache(cache, query.Question[0], reply)
		_, expiry, hit := getMsgFromCache(cache, query.Question[0])
		if minimum == 0 {
			if hit {
				t.Fatal("zero negative lifetime was cached")
			}
			continue
		}
		if !hit || time.Until(expiry) > 5*time.Second || time.Until(expiry) < 4*time.Second {
			t.Fatalf("SOA MINIMUM was not honored: hit=%v lifetime=%s", hit, time.Until(expiry))
		}
		if reply.Ns[0].Header().Ttl != 60 {
			t.Fatal("cached negative response mutated caller")
		}
	}
}
