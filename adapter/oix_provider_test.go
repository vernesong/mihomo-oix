package adapter

import (
	"context"
	"errors"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
	C "github.com/metacubex/mihomo/constant"
)

type availabilityAdapter struct {
	C.ProxyAdapter
	address string
	calls   int
}

func (a *availabilityAdapter) Addr() string { return a.address }
func (a *availabilityAdapter) DialContext(context.Context, *C.Metadata) (C.Conn, error) {
	a.calls++
	return nil, errors.New("fixture transport")
}
func (a *availabilityAdapter) ListenPacketContext(context.Context, *C.Metadata) (C.PacketConn, error) {
	a.calls++
	return nil, errors.New("fixture transport")
}

func TestManagedProviderRevocationStopsNewStreamsBeforePoolReuse(t *testing.T) {
	oldDomain, oldEnsured := oixdns.ManagedNodesDomain(), oixdns.IsEnsured()
	oixdns.ConfigureManagedDNS("nodes.example.invalid")
	t.Cleanup(func() {
		oixdns.ResetManagedDNS()
		oixdns.ConfigureManagedDNS(oldDomain)
		if oldEnsured {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
	})
	for _, enabled := range []bool{false, true} {
		if enabled {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
		for _, address := range []string{"node.nodes.example.invalid:443", "public.example.invalid:443"} {
			transport := &availabilityAdapter{address: address}
			proxy := NewProxy(transport)
			_, _ = proxy.DialContext(context.Background(), &C.Metadata{})
			_, _ = proxy.ListenPacketContext(context.Background(), &C.Metadata{})
			want := 2
			if !enabled && address == "node.nodes.example.invalid:443" {
				want = 0
			}
			if transport.calls != want {
				t.Fatalf("enabled=%v address=%s transport calls=%d want=%d", enabled, address, transport.calls, want)
			}
		}
	}
}
