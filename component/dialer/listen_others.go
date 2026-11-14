//go:build !darwin

package dialer

import (
	"context"
	"net"
)

func listenPacket(ctx context.Context, lc *net.ListenConfig, network, address string) (net.PacketConn, error) {
	return lc.ListenPacket(ctx, network, address)
}
