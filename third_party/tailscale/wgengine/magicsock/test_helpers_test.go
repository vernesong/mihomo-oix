// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/metacubex/tailscale/health"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/logger"
	"github.com/metacubex/tailscale/util/eventbus"
	"github.com/metacubex/tailscale/util/usermetric"
)

type localhostListener struct{}

func (localhostListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	switch network {
	case "udp4":
		if host != "" && host != "0.0.0.0" && host != "127.0.0.1" {
			return nil, fmt.Errorf("localhostListener cannot listen on %q", address)
		}
		host = "127.0.0.1"
	case "udp6":
		if host != "" && host != "::" && host != "::1" {
			return nil, fmt.Errorf("localhostListener cannot listen on %q", address)
		}
		host = "::1"
	}
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, network, net.JoinHostPort(host, port))
}

func newTestConn(t testing.TB) *Conn {
	t.Helper()
	bus := eventbus.NewWithOptions(eventbus.BusOptions{Logf: t.Logf})
	t.Cleanup(bus.Close)
	netMon, err := netmon.New(bus, logger.WithPrefix(t.Logf, "... netmon: "))
	if err != nil {
		t.Fatalf("netmon.New: %v", err)
	}
	t.Cleanup(func() { netMon.Close() })
	conn, err := NewConn(Options{
		NetMon:                 netMon,
		EventBus:               bus,
		HealthTracker:          health.NewTracker(bus),
		Metrics:                new(usermetric.Registry),
		DisablePortMapper:      true,
		Logf:                   t.Logf,
		TestOnlyPacketListener: localhostListener{},
		EndpointsFunc:          func([]tailcfg.Endpoint) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
