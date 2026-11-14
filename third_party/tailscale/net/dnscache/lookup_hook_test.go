// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestResolverLookupHook(t *testing.T) {
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	r := &Resolver{
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if host != "example.com" {
				t.Fatalf("host = %q, want example.com", host)
			}
			return want, nil
		},
	}
	_, _, got, err := r.LookupIP(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("LookupIP = %v, want %v", got, want)
	}
}

func TestResolverLookupHookDoesNotFallback(t *testing.T) {
	wantErr := errors.New("lookup failed")
	r := &Resolver{
		LookupHook: func(context.Context, string) ([]netip.Addr, error) {
			return nil, wantErr
		},
		LookupIPFallback: func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("LookupIPFallback called with LookupHook configured")
			return nil, nil
		},
	}
	_, _, _, err := r.LookupIP(context.Background(), "example.com")
	if !errors.Is(err, wantErr) {
		t.Fatalf("LookupIP error = %v, want %v", err, wantErr)
	}
}
