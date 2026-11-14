package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
)

const reservedPortAttempts = 8

// XNU picks the ephemeral port of a dual-stack UDP socket after checking IPv6
// sockets only, so the port can already belong to an IPv4 socket of another
// process, which keeps receiving every IPv4 datagram sent to it
// (golang/go#67226, FB25058707). An IPv4 socket's ephemeral port is checked
// against IPv4 and dual-stack sockets, so the port comes from one, held until
// the dual-stack socket is bound to it.
func listenPacket(ctx context.Context, lc *net.ListenConfig, network, address string) (net.PacketConn, error) {
	host, ok := dualStackEphemeral(network, address)
	if !ok {
		return lc.ListenPacket(ctx, network, address)
	}
	var reserved []int
	defer func() {
		for _, fd := range reserved {
			_ = syscall.Close(fd)
		}
	}()
	for range reservedPortAttempts {
		fd, port, err := reserveUDP4Port()
		if err != nil {
			break
		}
		reserved = append(reserved, fd)
		pc, err := lc.ListenPacket(ctx, network, net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			return pc, nil
		}
		// An IPv6 socket holds the port.
		if !errors.Is(err, syscall.EADDRINUSE) {
			break
		}
	}
	return lc.ListenPacket(ctx, network, address)
}

// dualStackEphemeral reports whether net.ListenConfig would create a
// dual-stack socket on a kernel-chosen port, and returns the host to keep.
func dualStackEphemeral(network, address string) (string, bool) {
	if network != "udp" {
		return "", false
	}
	if address == "" {
		return "", true
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "" && port != "0" {
		return "", false
	}
	if host == "" {
		return host, true
	}
	ip, err := netip.ParseAddr(host)
	return host, err == nil && ip.IsUnspecified()
}

var reserveUDP4Port = func() (int, int, error) {
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return -1, 0, err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrInet4{}); err == nil {
		var sa syscall.Sockaddr
		if sa, err = syscall.Getsockname(fd); err == nil {
			if sa4, ok := sa.(*syscall.SockaddrInet4); ok && sa4.Port != 0 {
				return fd, sa4.Port, nil
			}
			err = syscall.EAFNOSUPPORT
		}
	}
	_ = syscall.Close(fd)
	return -1, 0, err
}
