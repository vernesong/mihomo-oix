// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package winipcfg

import (
	"net/netip"

	"golang.org/x/sys/windows"
)

type LUID uint64

func LUIDFromGUID(*windows.GUID) (LUID, error) { return 0, nil }
func LUIDFromIndex(uint32) (LUID, error)       { return 0, nil }

func (l LUID) GUID() (windows.GUID, error) { return windows.GUID{}, nil }
func (l LUID) DNS() ([]netip.Addr, error)  { return nil, nil }

func (l LUID) IPInterface(AddressFamily) (*MibIPInterfaceRow, error) {
	return &MibIPInterfaceRow{}, nil
}

func (l LUID) Interface() (*MibIfRow2, error) {
	return &MibIfRow2{}, nil
}

type AddressFamily uint16
type GAAFlags uint32
type IfOperStatus uint32
type MibNotificationType uint32

const (
	GAAFlagIncludeAllInterfaces GAAFlags = 1 << iota
)

const (
	IfOperStatusUp IfOperStatus = 1
)

const (
	IfTypeSoftwareLoopback = 24
	IfTypePropVirtual      = 53
)

const (
	IPAAFlagIpv4Enabled = 1 << iota
	IPAAFlagIpv6Enabled
)

const (
	MibParameterNotification MibNotificationType = iota
	MibAddInstance
)

type IPAdapterAddresses struct {
	LUID       LUID
	MTU        uint32
	IfType     uint32
	IfIndex    uint32
	Ipv4Metric uint32
	Ipv6Metric uint32
	Flags      uint32
	OperStatus IfOperStatus
}

func (a *IPAdapterAddresses) FriendlyName() string { return "" }
func (a *IPAdapterAddresses) Description() string  { return "" }

type MibIfRow2 struct {
	Type       uint32
	OperStatus IfOperStatus
}

func (r *MibIfRow2) Description() string { return "" }

type MibIPInterfaceRow struct {
	Connected     bool
	InterfaceLUID LUID
	Metric        uint32
	OperStatus    IfOperStatus
}

type RawSockaddrInet struct {
	addr netip.Addr
}

func (s *RawSockaddrInet) SetAddr(addr netip.Addr) error {
	s.addr = addr
	return nil
}

type IPAddress struct {
	addr netip.Addr
}

func (a IPAddress) Addr() netip.Addr { return a.addr }

type IPPrefix struct {
	PrefixLength uint8
	prefix       netip.Prefix
}

func (p IPPrefix) Prefix() netip.Prefix { return p.prefix }

type MibUnicastIPAddressRow struct {
	Address IPAddress
}

type MibIPforwardRow2 struct {
	Loopback          bool
	DestinationPrefix IPPrefix
	InterfaceLUID     LUID
	Metric            uint32
	NextHop           IPAddress
}

func GetIPForwardTable2(AddressFamily) ([]MibIPforwardRow2, error) {
	return nil, nil
}

func GetAdaptersAddresses(AddressFamily, GAAFlags) ([]*IPAdapterAddresses, error) {
	return nil, nil
}

func GetIPInterfaceTable(AddressFamily) ([]MibIPInterfaceRow, error) {
	return nil, nil
}

type UnicastAddressChangeCallback struct{}
type RouteChangeCallback struct{}
type InterfaceChangeCallback struct{}

func RegisterUnicastAddressChangeCallback(func(MibNotificationType, *MibUnicastIPAddressRow)) (*UnicastAddressChangeCallback, error) {
	return &UnicastAddressChangeCallback{}, nil
}

func RegisterRouteChangeCallback(func(MibNotificationType, *MibIPforwardRow2)) (*RouteChangeCallback, error) {
	return &RouteChangeCallback{}, nil
}

func RegisterInterfaceChangeCallback(func(MibNotificationType, *MibIPInterfaceRow)) (*InterfaceChangeCallback, error) {
	return &InterfaceChangeCallback{}, nil
}

func (*UnicastAddressChangeCallback) Unregister() error { return nil }
func (*RouteChangeCallback) Unregister() error          { return nil }
func (*InterfaceChangeCallback) Unregister() error      { return nil }
