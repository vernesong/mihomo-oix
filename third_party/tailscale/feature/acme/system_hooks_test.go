// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/tailscale/ipn/ipnlocal"
)

type testCertStore struct {
	acmeKey []byte
}

func (s testCertStore) Read(string, time.Time) (*ipnlocal.TLSCertKeyPair, error) {
	panic("unused")
}
func (s testCertStore) ACMEKey() ([]byte, error)  { return s.acmeKey, nil }
func (s testCertStore) WriteACMEKey([]byte) error { panic("unused") }
func (s testCertStore) WriteTLSCertAndKey(string, []byte, []byte) error {
	panic("unused")
}

func TestACMEClientUsesSystemHTTPClient(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keyPEM bytes.Buffer
	if err := encodeECDSAKey(&keyPEM, key); err != nil {
		t.Fatal(err)
	}

	want := new(http.Client)
	e := &extension{httpClient: want}
	client, err := e.acmeClient(testCertStore{acmeKey: keyPEM.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	if client.HTTPClient != want {
		t.Fatalf("HTTPClient = %p, want %p", client.HTTPClient, want)
	}
}

func TestSystemResolverUsesDialer(t *testing.T) {
	wantErr := errors.New("dialer called")
	r := newSystemResolver(func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			t.Fatalf("Dial(%q, %q), want udp, 192.0.2.53:53", network, address)
		}
		return nil, wantErr
	})
	if !r.PreferGo {
		t.Fatal("resolver does not force the Go resolver")
	}
	if _, err := r.Dial(context.Background(), "udp", "192.0.2.53:53"); !errors.Is(err, wantErr) {
		t.Fatalf("Dial error = %v, want %v", err, wantErr)
	}
}
