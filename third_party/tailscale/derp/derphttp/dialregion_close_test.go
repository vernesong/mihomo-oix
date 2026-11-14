// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tailcfg"
)

type closeCountingConn struct {
	net.Conn
	closes *atomic.Int32
}

func (c closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

// A dialer may keep its conns reachable, as tsdial's SystemDial does, so a
// failed handshake must close the conn rather than leave it to a finalizer.
func TestDialRegionTLSClosesConnOnFailure(t *testing.T) {
	notTLS := func(c net.Conn) {
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		_, _ = io.Copy(io.Discard, c)
	}
	silent := func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }

	tests := []struct {
		name    string
		serve   func(net.Conn)
		timeout time.Duration
	}{
		{"handshake_error", notTLS, 10 * time.Second},
		{"context_expires", silent, 100 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						tt.serve(c)
					}()
				}
			}()

			var closes atomic.Int32
			dc := NewNetcheckClient(t.Logf, netmon.NewStatic())
			defer dc.Close()
			dc.SetURLDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
				c, err := new(net.Dialer).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return closeCountingConn{c, &closes}, nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()
			reg := &tailcfg.DERPRegion{RegionID: 1, RegionCode: "test", Nodes: []*tailcfg.DERPNode{{
				Name:     "1",
				RegionID: 1,
				HostName: "derp.invalid",
				IPv4:     "127.0.0.1",
				IPv6:     "none",
				DERPPort: ln.Addr().(*net.TCPAddr).Port,
			}}}
			if _, _, _, err = dc.DialRegionTLS(ctx, reg); err == nil {
				t.Fatal("handshake unexpectedly succeeded")
			}
			if closes.Load() == 0 {
				t.Fatal("the failed connection was not closed")
			}
		})
	}
}
