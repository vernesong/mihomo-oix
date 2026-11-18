// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/metacubex/http"
)

func TestNewSystemHTTPClient(t *testing.T) {
	wantErr := errors.New("dialer called")
	roots := x509.NewCertPool()
	c := NewSystemHTTPClient(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "example.com:443" {
			t.Fatalf("Dial(%q, %q), want tcp, example.com:443", network, address)
		}
		return nil, wantErr
	}, roots)

	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport has type %T, want *http.Transport", c.Transport)
	}
	if tr.Dial != nil || tr.DialTLS != nil || tr.DialTLSContext != nil {
		t.Fatal("transport retains a dial function that can bypass DialContext")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs != roots {
		t.Fatal("transport does not use the provided root pool")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, wantErr) {
		t.Fatalf("DialContext error = %v, want %v", err, wantErr)
	}
}
