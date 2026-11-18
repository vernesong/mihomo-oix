// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package nettype

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

type testPacketConn struct {
	readAddr  net.Addr
	wroteAddr net.Addr
}

func (c *testPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	copy(p, "packet")
	return len("packet"), c.readAddr, nil
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.wroteAddr = addr
	return len(p), nil
}

func (*testPacketConn) Close() error                     { return nil }
func (*testPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (*testPacketConn) SetDeadline(time.Time) error      { return nil }
func (*testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (*testPacketConn) SetWriteDeadline(time.Time) error { return nil }

type wrappedAddr struct{ net.Addr }

func (a wrappedAddr) Network() string   { return "wrapped" }
func (a wrappedAddr) String() string    { return "opaque" }
func (a wrappedAddr) RawAddr() net.Addr { return a.Addr }

func TestMakePacketConn(t *testing.T) {
	want := netip.MustParseAddrPort("192.0.2.1:1234")
	base := &testPacketConn{readAddr: wrappedAddr{&net.UDPAddr{IP: want.Addr().AsSlice(), Port: int(want.Port())}}}
	pc := MakePacketConn(base)

	buf := make([]byte, 16)
	_, got, err := pc.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ReadFromUDPAddrPort address = %v, want %v", got, want)
	}

	if _, err := pc.WriteToUDPAddrPort([]byte("packet"), want); err != nil {
		t.Fatal(err)
	}
	addr, ok := base.wroteAddr.(*net.UDPAddr)
	if !ok || addr.AddrPort() != want {
		t.Fatalf("WriteTo address = %v, want %v", base.wroteAddr, want)
	}
}
