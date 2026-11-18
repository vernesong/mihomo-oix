package dialer

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

func TestDualStackEphemeral(t *testing.T) {
	for _, tc := range []struct {
		network, address string
		want             bool
	}{
		{"udp", "", true},
		{"udp", ":0", true},
		{"udp", "0.0.0.0:0", true},
		{"udp", "[::]:0", true},
		{"udp4", "", false},
		{"udp6", "", false},
		{"tcp", "", false},
		{"udp", ":53", false},
		{"udp", "127.0.0.1:0", false},
		{"udp", "[::1]:0", false},
		{"udp", "192.0.2.1:0", false},
	} {
		if _, got := dualStackEphemeral(tc.network, tc.address); got != tc.want {
			t.Errorf("dualStackEphemeral(%q, %q) = %v, want %v", tc.network, tc.address, got, tc.want)
		}
	}
}

func TestListenPacketRetriesPortHeldForIPv6(t *testing.T) {
	// The IPv4 port search ignores IPv6-only sockets, so it may return a port
	// one holds; take such a port that no IPv4 socket holds as well.
	var heldPort, reservedFD int
	for range 16 {
		held, err := net.ListenPacket("udp6", "[::]:0")
		if err != nil {
			t.Skipf("IPv6 unavailable: %v", err)
		}
		port := held.LocalAddr().(*net.UDPAddr).Port
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: port}); err != nil {
			_ = syscall.Close(fd)
			_ = held.Close()
			continue
		}
		t.Cleanup(func() { _ = held.Close() })
		heldPort, reservedFD = port, fd
		break
	}
	if heldPort == 0 {
		t.Fatal("no IPv6-held port was free for IPv4")
	}

	reserve := reserveUDP4Port
	t.Cleanup(func() { reserveUDP4Port = reserve })
	calls := 0
	reserveUDP4Port = func() (int, int, error) {
		calls++
		if calls > 1 {
			return reserve()
		}
		return reservedFD, heldPort, nil
	}

	pc, err := ListenPacket(context.Background(), "udp", "", netip.AddrPort{})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if port := pc.LocalAddr().(*net.UDPAddr).Port; port == heldPort || calls < 2 {
		t.Fatalf("bound port %d after %d reservations, IPv6 holds %d", port, calls, heldPort)
	}
	if _, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv6loopback, Port: heldPort}); err != nil {
		t.Fatalf("dual-stack socket cannot send IPv6: %v", err)
	}
}
