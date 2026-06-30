package resolver

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
	D "github.com/miekg/dns"
)

type echRecordingResolver struct {
	host string
}

func (r *echRecordingResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *echRecordingResolver) LookupIPv4(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *echRecordingResolver) LookupIPv6(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

func (r *echRecordingResolver) ResolveECH(_ context.Context, host string) ([]byte, error) {
	r.host = host
	return nil, nil
}

func (r *echRecordingResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, nil
}

func (r *echRecordingResolver) Invalid() bool {
	return true
}

func (r *echRecordingResolver) ClearCache() {}

func (r *echRecordingResolver) ResetConnection() {}

func TestResolveECHWithResolverDelegatesOriginalOIXHost(t *testing.T) {
	oldNodesDomains := oixdns.NodesDomains
	oldDNSPrivateKey := oixdns.DNSPrivateKey
	oixdns.NodesDomains = "example.com"
	oixdns.DNSPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	t.Cleanup(func() {
		oixdns.NodesDomains = oldNodesDomains
		oixdns.DNSPrivateKey = oldDNSPrivateKey
	})

	recorder := &echRecordingResolver{}
	_, _ = ResolveECHWithResolver(context.Background(), "node.example.com", recorder)

	if recorder.host != "node.example.com" {
		t.Fatalf("expected original host to be delegated, got %q", recorder.host)
	}
}
