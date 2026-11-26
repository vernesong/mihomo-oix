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
		var ips []netip.Addr
		var err error
		switch family {
		case 4:
			ips, err = r.LookupIPv4(ctx, host)
		case 6:
			ips, err = r.LookupIPv6(ctx, host)
		default:
			ips, err = r.LookupIP(ctx, host)
		}
		if err == nil {
			ips = usableBootstrapAddresses(ips)
			if len(ips) == 0 {
				err = resolver.ErrIPNotFound
			}
		}
		return ips, err
	}
	// The fixed servers get a second, or half of what the caller has left when that
	// is less: the system resolver behind them must still have time to answer.
	limit := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		limit = min(limit, time.Until(deadline)/2)
	}
	primary, cancel := context.WithTimeout(ctx, limit)
	ips, err := lookup(b.Resolver, primary)
	cancel()
	if err == nil {
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
