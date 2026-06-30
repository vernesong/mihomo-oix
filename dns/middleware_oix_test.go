package dns

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	icontext "github.com/metacubex/mihomo/context"
	D "github.com/miekg/dns"
)

type exchangeRecordingResolver struct {
	qname string
}

func (r *exchangeRecordingResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *exchangeRecordingResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *exchangeRecordingResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *exchangeRecordingResolver) ResolveECH(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (r *exchangeRecordingResolver) ExchangeContext(_ context.Context, msg *D.Msg) (*D.Msg, error) {
	r.qname = msg.Question[0].Name
	resp := msg.Copy()
	resp.SetRcode(msg, D.RcodeSuccess)
	return resp, nil
}

func (r *exchangeRecordingResolver) Invalid() bool {
	return true
}

func (r *exchangeRecordingResolver) ClearCache() {}

func (r *exchangeRecordingResolver) ResetConnection() {}

var _ resolver.Resolver = (*exchangeRecordingResolver)(nil)

func TestNewHandlerDoesNotObfuscateBeforeResolver(t *testing.T) {
	oldNodesDomains := oixdns.NodesDomains
	oldDNSPrivateKey := oixdns.DNSPrivateKey
	oixdns.NodesDomains = "example.com"
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	t.Cleanup(func() {
		oixdns.NodesDomains = oldNodesDomains
		oixdns.DNSPrivateKey = oldDNSPrivateKey
	})

	recorder := &exchangeRecordingResolver{}
	handler := newHandler(recorder, &ResolverEnhancer{mode: C.DNSNormal, ipv6: true})
	query := new(D.Msg)
	query.SetQuestion(D.Fqdn("node.example.com"), D.TypeA)

	if _, err := handler(icontext.NewDNSContext(context.Background()), query); err != nil {
		t.Fatalf("handler failed: %v", err)
	}
	if recorder.qname != "node.example.com." {
		t.Fatalf("expected original qname to reach resolver, got %q", recorder.qname)
	}
}
