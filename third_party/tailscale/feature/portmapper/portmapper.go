// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package portmapper registers support for NAT-PMP, PCP, and UPnP port
// mapping protocols to help get direction connections through NATs.
package portmapper

import (
	"github.com/metacubex/tailscale/feature"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/net/netx"
	"github.com/metacubex/tailscale/net/portmapper"
	"github.com/metacubex/tailscale/net/portmapper/portmappertype"
	"github.com/metacubex/tailscale/types/logger"
	"github.com/metacubex/tailscale/util/eventbus"
)

func init() {
	feature.Register("portmapper")
	portmappertype.HookNewPortMapper.Set(newPortMapper)
}

func newPortMapper(
	logf logger.Logf,
	bus *eventbus.Bus,
	netMon *netmon.Monitor,
	dialer netx.DialFunc,
	packetListener netx.ListenPacketFunc,
	disableUPnPOrNil func() bool,
	onlyTCP443OrNil func() bool) portmappertype.Client {

	pm := portmapper.NewClient(portmapper.Config{
		EventBus:       bus,
		Logf:           logf,
		NetMon:         netMon,
		Dialer:         dialer,
		PacketListener: packetListener,
		DebugKnobs: &portmapper.DebugKnobs{
			DisableAll:      onlyTCP443OrNil,
			DisableUPnPFunc: disableUPnPOrNil,
		},
	})
	pm.SetGatewayLookupFunc(netMon.GatewayAndSelfIP)
	return pm
}
