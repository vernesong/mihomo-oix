// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package ipnlocal

import (
	"encoding/binary"
	"testing"

	"go4.org/mem"

	storemem "github.com/metacubex/tailscale/ipn/store/mem"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/net/tsdial"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/tsd"
	"github.com/metacubex/tailscale/types/key"
	"github.com/metacubex/tailscale/types/logger"
	"github.com/metacubex/tailscale/types/logid"
	"github.com/metacubex/tailscale/wgengine"
)

func makeNodeKeyFromID(nodeID tailcfg.NodeID) key.NodePublic {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint64(raw[24:], uint64(nodeID))
	return key.NodePublicFromRaw32(mem.B(raw))
}

func makeDiscoKeyFromID(nodeID tailcfg.NodeID) key.DiscoPublic {
	raw := make([]byte, 32)
	binary.BigEndian.PutUint64(raw[24:], uint64(nodeID))
	return key.DiscoPublicFromRaw32(mem.B(raw))
}

func newTestLocalBackend(t testing.TB) *LocalBackend {
	sys := tsd.NewSystem()
	sys.Set(new(storemem.Store))

	eng, err := wgengine.NewFakeUserspaceEngine(
		logger.Discard,
		sys.Set,
		sys.HealthTracker.Get(),
		sys.UserMetricsRegistry(),
		sys.Bus.Get(),
	)
	if err != nil {
		t.Fatalf("NewFakeUserspaceEngine: %v", err)
	}
	t.Cleanup(eng.Close)
	sys.Set(eng)

	if _, ok := sys.Dialer.GetOK(); !ok {
		dialer := tsdial.NewDialer(netmon.NewStatic())
		dialer.SetBus(sys.Bus.Get())
		sys.Set(dialer)
	}

	lb, err := NewLocalBackend(logger.Discard, logid.PublicID{}, sys, 0)
	if err != nil {
		t.Fatalf("NewLocalBackend: %v", err)
	}
	t.Cleanup(lb.Shutdown)
	return lb
}
