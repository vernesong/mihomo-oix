package route

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"
	D "github.com/miekg/dns"
)

type dnsQueryResolver struct{}

func (r *dnsQueryResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *dnsQueryResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *dnsQueryResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *dnsQueryResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (r *dnsQueryResolver) ExchangeContext(_ context.Context, msg *D.Msg) (*D.Msg, error) {
	resp := msg.Copy()
	resp.Question[0].Name = "signed.node.example.com."
	resp.Answer = []D.RR{
		&D.A{
			Hdr: D.RR_Header{Name: "signed.node.example.com.", Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60},
		},
	}
	return resp, nil
}

func (r *dnsQueryResolver) Invalid() bool {
	return true
}

func (r *dnsQueryResolver) ClearCache() {}

func (r *dnsQueryResolver) ResetConnection() {}

var _ resolver.Resolver = (*dnsQueryResolver)(nil)

func TestQueryDNSMasksOIXQuestion(t *testing.T) {
	oldResolver := resolver.DefaultResolver
	oldNodesDomains := oixdns.NodesDomains
	resolver.DefaultResolver = &dnsQueryResolver{}
	oixdns.NodesDomains = "example.com"
	t.Cleanup(func() {
		resolver.DefaultResolver = oldResolver
		oixdns.NodesDomains = oldNodesDomains
	})

	req := httptest.NewRequest("GET", "/dns/query?name=node.example.com&type=A", nil)
	rec := httptest.NewRecorder()
	queryDNS(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !reflect.DeepEqual(body["Question"], []any{"***"}) {
		t.Fatalf("expected masked question, got %#v", body["Question"])
	}
}
