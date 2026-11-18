package dns

import (
	"context"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
)

// NewBootstrapResolver keeps endpoint discovery off the tunnel before trying the
// system path, within the caller's remaining deadline.
func NewBootstrapResolver(servers []string, system func() resolver.Resolver) resolver.Resolver {
	upstreams := make([]NameServer, 0, len(servers))
	for _, server := range servers {
		upstreams = append(upstreams, NameServer{Net: "udp", Addr: server})
	}
	return &bootstrapResolver{Resolver: NewResolver(Config{Main: upstreams, IPv6: true}).Resolver, system: system}
}

type bootstrapResolver struct {
	resolver.Resolver
	system func() resolver.Resolver
}

func (b *bootstrapResolver) lookup(ctx context.Context, host string, family int) ([]netip.Addr, error) {
	lookup := func(r resolver.Resolver, ctx context.Context) ([]netip.Addr, error) {
		switch family {
		case 4:
			return r.LookupIPv4(ctx, host)
		case 6:
			return r.LookupIPv6(ctx, host)
		default:
			return r.LookupIP(ctx, host)
		}
	}
	primary, cancel := context.WithTimeout(ctx, time.Second)
	ips, err := lookup(b.Resolver, primary)
	cancel()
	if err == nil && len(ips) != 0 {
		return ips, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if fallback := b.system(); fallback != nil && fallback != b {
		return lookup(fallback, ctx)
	}
	return ips, err
}

func (b *bootstrapResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return b.lookup(ctx, host, 0)
}

func (b *bootstrapResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return b.lookup(ctx, host, 4)
}

func (b *bootstrapResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return b.lookup(ctx, host, 6)
}
