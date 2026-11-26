// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/tempfork/goupnp/soap"
	"github.com/metacubex/tailscale/util/eventbus"
)

func TestClientUsesSystemHooks(t *testing.T) {
	wantDialErr := errors.New("dialer called")
	wantListenErr := errors.New("packet listener called")
	c := NewClient(Config{
		EventBus: eventbus.New(),
		NetMon:   netmon.NewStatic(),
		Dialer: func(_ context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "192.0.2.1:80" {
				t.Fatalf("Dial(%q, %q), want tcp, 192.0.2.1:80", network, address)
			}
			return nil, wantDialErr
		},
		PacketListener: func(_ context.Context, network, address string) (net.PacketConn, error) {
			if network != "udp4" || address != ":0" {
				t.Fatalf("ListenPacket(%q, %q), want udp4, :0", network, address)
			}
			return nil, wantListenErr
		},
	})
	t.Cleanup(func() { c.Close() })

	if _, err := c.listenPacket(context.Background(), "udp4", ":0"); !errors.Is(err, wantListenErr) {
		t.Fatalf("listenPacket error = %v, want %v", err, wantListenErr)
	}

	httpClient := c.upnpHTTPClientLocked()
	tr, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTP transport has type %T, want *http.Transport", httpClient.Transport)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "192.0.2.1:80"); !errors.Is(err, wantDialErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantDialErr)
	}

	soapClient := new(soap.SOAPClient)
	ctx := upnpHTTPClientKey.WithValue(context.Background(), httpClient)
	setUPnPHTTPClient(ctx, soapClient)
	if soapClient.HTTPClient.Transport != httpClient.Transport {
		t.Fatal("SOAP client does not use the configured HTTP transport")
	}
}
