// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package nettype defines an interface that doesn't exist in the Go net package.
package nettype

import (
	"context"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/tailscale/net/netaddr"
)

// PacketListener defines the ListenPacket method as implemented
// by net.ListenConfig, net.ListenPacket, and tstest/natlab.
type PacketListener interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type PacketListenerWithNetIP interface {
	ListenPacket(ctx context.Context, network, address string) (PacketConn, error)
}

// Std implements PacketListener using the Go net package's ListenPacket func.
type Std struct{}

func (Std) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	var conf net.ListenConfig
	return conf.ListenPacket(ctx, network, address)
}

// PacketConn is like a net.PacketConn but uses the newer netip.AddrPort
// write/read methods.
type PacketConn interface {
	WriteToUDPAddrPort([]byte, netip.AddrPort) (int, error)
	ReadFromUDPAddrPort([]byte) (int, netip.AddrPort, error)
	io.Closer
	LocalAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// MakePacketConn adapts pc to the netip-aware PacketConn interface.
func MakePacketConn(pc net.PacketConn) PacketConn {
	if pc, ok := pc.(PacketConn); ok {
		return pc
	}
	return packetConnAdapter{pc}
}

type packetConnAdapter struct {
	net.PacketConn
}

func (pc packetConnAdapter) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	return pc.PacketConn.WriteTo(p, net.UDPAddrFromAddrPort(addr))
}

func (pc packetConnAdapter) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	n, addr, err := pc.PacketConn.ReadFrom(p)
	return n, netaddr.FromStdNetAddr(addr), err
}

func MakePacketListenerWithNetIP(ln PacketListener) PacketListenerWithNetIP {
	return packetListenerAdapter{ln}
}

type packetListenerAdapter struct {
	PacketListener
}

func (a packetListenerAdapter) ListenPacket(ctx context.Context, network, address string) (PacketConn, error) {
	pc, err := a.PacketListener.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return MakePacketConn(pc), nil
}

// ConnPacketConn is the interface that's a superset of net.Conn and net.PacketConn.
type ConnPacketConn interface {
	net.Conn
	net.PacketConn
}
