package outbound

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
)

// Surge and WebRTC apps hold many IPv4 wildcard UDP ports; macOS could give a
// DIRECT session's dual-stack socket one of them, and the IPv4 replies then
// went to the other socket.
func TestDirectUDPRepliesBesideHeldIPv4Ports(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("only macOS assigns dual-stack UDP ports without checking IPv4 sockets")
	}
	echo4 := listenUDPEcho(t, "udp4", "127.0.0.1:0")
	echo6 := listenUDPEcho(t, "udp6", "[::1]:0")

	held := make(map[int]bool)
	for _, address := range []string{"0.0.0.0:0", "127.0.0.1:0"} {
		for range 2048 {
			c, err := net.ListenPacket("udp4", address)
			if err != nil {
				break
			}
			t.Cleanup(func() { _ = c.Close() })
			held[c.LocalAddr().(*net.UDPAddr).Port] = true
		}
	}
	// 128 sessions with a quarter of the range held: the unfixed socket misses
	// a reply with probability above 1-1e-15.
	if len(held) < 4000 {
		t.Skipf("only %d IPv4 ports could be held", len(held))
	}

	direct := NewDirect()
	for session := range 128 {
		target := echo4.LocalAddr().(*net.UDPAddr).AddrPort()
		pc, err := direct.ListenPacketContext(context.Background(), &C.Metadata{
			NetWork: C.UDP,
			DstIP:   target.Addr(),
			DstPort: target.Port(),
		})
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(N.CustomAddr).RawAddr().(*net.UDPAddr).Port
		for _, echo := range []net.PacketConn{echo4, echo6} {
			if echo == nil {
				continue
			}
			if err := exchangeUDP(pc, echo.LocalAddr()); err != nil {
				_ = pc.Close()
				t.Fatalf("session %d on port %d (held for IPv4: %v), %v: %v", session, port, held[port], echo.LocalAddr(), err)
			}
		}
		_ = pc.Close()
	}
}

func listenUDPEcho(t *testing.T, network, address string) net.PacketConn {
	pc, err := net.ListenPacket(network, address)
	if err != nil {
		if network == "udp6" {
			t.Logf("IPv6 echo unavailable: %v", err)
			return nil
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], from)
		}
	}()
	return pc
}

func exchangeUDP(pc net.PacketConn, to net.Addr) error {
	want := netip.MustParseAddrPort(to.String())
	if _, err := pc.WriteTo([]byte("ping"), to); err != nil {
		return err
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		got, err := netip.ParseAddrPort(from.String())
		if err == nil && got.Addr().Unmap() == want.Addr() && got.Port() == want.Port() && string(buf[:n]) == "ping" {
			return nil
		}
	}
}
