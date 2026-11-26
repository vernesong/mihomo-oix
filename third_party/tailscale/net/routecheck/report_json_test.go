// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package routecheck_test

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/metacubex/tailscale/net/routecheck"
	"github.com/metacubex/tailscale/tailcfg"
)

func TestNodeSetJSON(t *testing.T) {
	want := routecheck.NodeSet{
		2: {
			ID:     2,
			Name:   "node-2.example.ts.net.",
			Addr:   netip.MustParseAddr("100.64.0.2"),
			Routes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		},
		1: {
			ID:     1,
			Name:   "node-1.example.ts.net.",
			Addr:   netip.MustParseAddr("100.64.0.1"),
			Routes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		},
	}

	b, err := json.Marshal(&want)
	if err != nil {
		t.Fatal(err)
	}
	var ordered []struct {
		ID tailcfg.NodeID `json:"id"`
	}
	if err := json.Unmarshal(b, &ordered); err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 2 {
		t.Fatalf("decoded %d nodes, want 2; JSON: %s", len(ordered), b)
	}
	if got := []tailcfg.NodeID{ordered[0].ID, ordered[1].ID}; !reflect.DeepEqual(got, []tailcfg.NodeID{1, 2}) {
		t.Fatalf("node order = %v, want [1 2]", got)
	}

	var got routecheck.NodeSet
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}

func TestEmptyNodeSetJSON(t *testing.T) {
	ns := make(routecheck.NodeSet)
	b, err := json.Marshal(&ns)
	if err != nil {
		t.Fatal(err)
	}
	var got routecheck.NodeSet
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
}
