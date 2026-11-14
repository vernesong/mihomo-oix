// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"net"
	"testing"
)

func TestSystemNetworkHooks(t *testing.T) {
	d := new(Dialer)
	d.SystemDialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("dial = %s %s, want tcp example.com:443", network, address)
		}
		client, server := net.Pipe()
		t.Cleanup(func() { server.Close() })
		return client, nil
	}
	d.SystemPacketListener = func(ctx context.Context, network, address string) (net.PacketConn, error) {
		if network != "udp4" || address != "127.0.0.1:0" {
			t.Fatalf("listen = %s %s, want udp4 127.0.0.1:0", network, address)
		}
		var lc net.ListenConfig
		return lc.ListenPacket(ctx, network, address)
	}

	conn, err := d.SystemDial(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	pc, err := d.SystemPacketListen(context.Background(), "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
}
