// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsnet

import (
	"net/netip"
	"testing"

	"github.com/metacubex/tailscale/types/nettype"
)

func TestFallbackUDPHandler(t *testing.T) {
	var s Server
	src := netip.MustParseAddrPort("100.64.0.1:1234")
	dst := netip.MustParseAddrPort("100.64.0.2:5678")

	callbackCalls := 0
	handlerCalls := 0
	unregister := s.RegisterFallbackUDPHandler(func(gotSrc, gotDst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
		callbackCalls++
		if gotSrc != src || gotDst != dst {
			t.Fatalf("callback flow = (%v, %v), want (%v, %v)", gotSrc, gotDst, src, dst)
		}
		return func(nettype.ConnPacketConn) { handlerCalls++ }, true
	})

	handler, intercept := s.getFallbackUDPHandlerForFlow(src, dst)
	if !intercept || handler == nil {
		t.Fatalf("getUDPHandlerForFlow returned handler=%v, intercept=%v", handler != nil, intercept)
	}
	handler(nil)
	if callbackCalls != 1 || handlerCalls != 1 {
		t.Fatalf("calls after handling = callback %d, handler %d; want 1, 1", callbackCalls, handlerCalls)
	}

	unregister()
	handler, intercept = s.getFallbackUDPHandlerForFlow(src, dst)
	if !intercept || handler != nil {
		t.Fatalf("after unregister: handler=%v, intercept=%v; want nil, true", handler != nil, intercept)
	}
	if callbackCalls != 1 {
		t.Fatalf("callback called after unregister; got %d calls", callbackCalls)
	}
}
