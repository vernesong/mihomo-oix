// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package resolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/metacubex/tailscale/net/tsdial"
)

func TestPacketListenerUsesSystemHook(t *testing.T) {
	wantErr := errors.New("packet listener called")
	d := &tsdial.Dialer{
		SystemPacketListener: func(_ context.Context, network, address string) (net.PacketConn, error) {
			if network != "udp4" || address != ":0" {
				t.Fatalf("ListenPacket(%q, %q), want udp4, :0", network, address)
			}
			return nil, wantErr
		},
	}
	f := &forwarder{dialer: d}

	ln, err := f.packetListener(netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ln.ListenPacket(context.Background(), "udp4", ":0"); !errors.Is(err, wantErr) {
		t.Fatalf("ListenPacket error = %v, want %v", err, wantErr)
	}
}
