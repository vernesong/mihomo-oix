package tproxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/metacubex/mihomo/component/dialer"
)

// Run only inside a disposable Linux network namespace/container with NET_ADMIN:
// MIHOMO_TEST_FIREWALL=1 <test binary> -test.run "Test(NFT|IPTables)Kernel" -test.v
// fw4 reload is modeled with a replacement of the independent inet fw4 table;
// this is kernel integration coverage, not a claim of testing OpenWrt firmware.
func TestNFTKernel(t *testing.T)      { testFirewallKernel(t, false) }
func TestIPTablesKernel(t *testing.T) { testFirewallKernel(t, true) }

func testFirewallKernel(t *testing.T, legacy bool) {
	if os.Getenv("MIHOMO_TEST_FIREWALL") != "1" {
		t.Skip("requires a disposable network namespace with NET_ADMIN")
	}
	command := func(input, name string, args ...string) {
		t.Helper()
		if _, err := runFirewallCommand(input, name, args...); err != nil {
			t.Fatal(err)
		}
	}
	command("", "ip", "link", "set", "lo", "up")
	command("", "ip", "link", "add", "br-lan", "type", "veth", "peer", "name", "client")
	command("", "ip", "link", "set", "client", "up")
	t.Cleanup(func() { _, _ = runFirewallCommand("", "ip", "link", "del", "br-lan") })
	command("", "ip", "addr", "add", "192.0.2.1/24", "dev", "br-lan")
	command("", "ip", "link", "set", "br-lan", "up")
	command("", "ip", "route", "add", "default", "dev", "br-lan")

	f := testNFTFirewall(t)
	f.run = runFirewallCommand
	setup, cleanup := f.setup, f.cleanup
	if legacy {
		oldRun, oldMark := runIPTablesCommand, dialer.DefaultRoutingMark.Load()
		t.Cleanup(func() { runIPTablesCommand = oldRun; dialer.DefaultRoutingMark.Store(oldMark) })
		dialer.DefaultRoutingMark.Store(f.mark)
		runIPTablesCommand = func(command string) (string, error) {
			args := strings.Fields(command)
			if args[0] == "iptables" {
				args[0] = "iptables-legacy"
			}
			out, err := runFirewallCommand("", args[0], args[1:]...)
			return string(out), err
		}
		setup = func() error { return SetTProxyIPTables(f.ifname, f.bypass, f.tport, f.dnsredir, f.dport) }
		cleanup = CleanupTProxyIPTables
	}
	reloadFW4 := func(t *testing.T) {
		t.Helper()
		// Like a normal router, LAN/loopback input is accepted and WAN input
		// is denied. TPROXY must coexist with those policies, not override them.
		command(`add table inet fw4
delete table inet fw4
table inet fw4 {
chain input { type filter hook input priority filter; policy drop; ct state established,related accept; iifname { "lo", "br-lan" } accept; }
chain forward { type filter hook forward priority filter; policy drop; ct state established,related accept; iifname "br-lan" accept; }
chain output { type filter hook output priority filter; policy accept; }
}
`, "nft", "-f", "-")
	}
	reloadFW4(t)
	t.Cleanup(func() { _, _ = runFirewallCommand("", "nft", "delete", "table", "inet", "fw4") })
	if err := setup(); err != nil {
		_ = cleanup()
		t.Fatal(err)
	}
	policy, err := runFirewallCommand("", "nft", "list", "chain", "inet", "fw4", "input")
	if err != nil || !strings.Contains(string(policy), "policy drop") {
		t.Fatalf("Firewall4 input policy changed: %s, %v", policy, err)
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})

	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		var err error
		if controlErr := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1) }); controlErr != nil {
			return controlErr
		}
		return err
	}}
	proxy, err := lc.Listen(context.Background(), "tcp4", "0.0.0.0:9898")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	destinations := make(chan string, 8)
	go func() {
		for {
			conn, err := proxy.Accept()
			if err != nil {
				return
			}
			destinations <- conn.LocalAddr().String()
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	udp, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:9898")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dnsTCP, err := net.Listen("tcp4", "0.0.0.0:1053")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsTCP.Close()
	go func() {
		for {
			conn, err := dnsTCP.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	dnsUDP, err := net.ListenPacket("udp4", "0.0.0.0:1053")
	if err != nil {
		t.Fatal(err)
	}
	defer dnsUDP.Close()

	tcpEcho := func(t *testing.T, address string) {
		t.Helper()
		conn, err := net.DialTimeout("tcp4", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("firewall-test")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len("firewall-test"))
		if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "firewall-test" {
			t.Fatalf("echo: %q, %v", buf, err)
		}
	}
	udpReceive := func(t *testing.T, address string, listener net.PacketConn) {
		t.Helper()
		conn, err := net.DialTimeout("udp4", address, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("udp-test")); err != nil {
			t.Fatal(err)
		}
		_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 100)
		n, _, err := listener.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "udp-test" {
			t.Fatalf("UDP interception: %q, %v", buf[:n], err)
		}
	}
	t.Run("TCP original destination", func(t *testing.T) {
		tcpEcho(t, "198.18.0.1:18080")
		select {
		case destination := <-destinations:
			if destination != "198.18.0.1:18080" {
				t.Fatal(destination)
			}
		case <-time.After(time.Second):
			t.Fatal("TPROXY did not accept connection")
		}
	})
	t.Run("UDP interception", func(t *testing.T) { udpReceive(t, "198.18.0.1:18081", udp) })
	t.Run("TCP DNS redirect", func(t *testing.T) { tcpEcho(t, "8.8.8.8:53") })
	t.Run("UDP DNS redirect", func(t *testing.T) { udpReceive(t, "8.8.8.8:53", dnsUDP) })
	t.Run("Firewall4 reload", func(t *testing.T) {
		reloadFW4(t)
		tcpEcho(t, "198.18.0.1:18082")
		<-destinations
		udpReceive(t, "8.8.4.4:53", dnsUDP)
	})
	t.Run("outbound routing mark bypass", func(t *testing.T) {
		dialer := net.Dialer{Timeout: 200 * time.Millisecond, Control: func(network, address string, raw syscall.RawConn) error {
			var err error
			if controlErr := raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(f.mark)) }); controlErr != nil {
				return controlErr
			}
			return err
		}}
		conn, err := dialer.Dial("tcp4", "198.18.0.1:18083")
		if err == nil {
			conn.Close()
			t.Fatal("marked outbound socket was intercepted")
		}
		select {
		case got := <-destinations:
			t.Fatalf("outbound loop: %s", got)
		default:
		}
	})
	t.Run("LAN UDP and DNS ingress", func(t *testing.T) {
		for _, tc := range []struct {
			port     uint16
			listener net.PacketConn
		}{{18081, udp}, {53, dnsUDP}} {
			sendFirewallUDPPacket(t, "client", "br-lan", "192.0.2.2", "8.8.8.8", tc.port)
			_ = tc.listener.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 100)
			n, _, err := tc.listener.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "ingress-test" {
				t.Fatalf("LAN UDP port %d: %q, %v", tc.port, buf[:n], err)
			}
		}
	})
	t.Run("WAN DNS is not exposed", func(t *testing.T) {
		command("", "ip", "link", "add", "wan-test", "type", "veth", "peer", "name", "external")
		defer runFirewallCommand("", "ip", "link", "del", "wan-test")
		command("", "ip", "addr", "add", "198.51.100.1/24", "dev", "wan-test")
		command("", "ip", "link", "set", "wan-test", "up")
		command("", "ip", "link", "set", "external", "up")
		sendFirewallUDPPacket(t, "external", "wan-test", "198.51.100.2", "198.51.100.1", 53)
		_ = dnsUDP.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		if _, _, err := dnsUDP.ReadFrom(make([]byte, 100)); err == nil {
			t.Fatal("WAN DNS was redirected to the local resolver")
		}
	})

	t.Run("legacy gateway masquerade", func(t *testing.T) {
		client, err := net.InterfaceByName("client")
		if err != nil {
			t.Fatal(err)
		}
		command("", "ip", "neigh", "add", "10.0.0.2", "lladdr", client.HardwareAddr.String(), "nud", "permanent", "dev", "br-lan")
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0x0008) // htons(ETH_P_IP)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: client.Index, Protocol: 0x0008}); err != nil {
			t.Fatal(err)
		}
		if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
			t.Fatal(err)
		}
		sendFirewallUDPPacket(t, "client", "br-lan", "192.0.2.2", "10.0.0.2", 18090)
		buf := make([]byte, 2048)
		for {
			n, from, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				t.Fatal(err)
			}
			if link, ok := from.(*unix.SockaddrLinklayer); ok && link.Pkttype == unix.PACKET_OUTGOING {
				continue
			}
			if n < 42 || !net.IP(buf[30:34]).Equal(net.ParseIP("10.0.0.2")) {
				continue
			}
			if got := net.IP(buf[26:30]).String(); got != "192.0.2.1" {
				t.Fatalf("forwarded source was not masqueraded: %s", got)
			}
			break
		}
	})

	t.Run("legacy default lo still intercepts LAN", func(t *testing.T) {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		f.ifname = "lo"
		if err := setup(); err != nil {
			t.Fatal(err)
		}
		sendFirewallUDPPacket(t, "client", "br-lan", "192.0.2.2", "9.9.9.9", 18085)
		_ = udp.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 100)
		n, _, err := udp.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "ingress-test" {
			t.Fatalf("default lo lost LAN interception: %q, %v", buf[:n], err)
		}
		conn, err := net.DialTimeout("tcp4", "198.18.0.1:18086", 150*time.Millisecond)
		if err == nil {
			conn.Close()
			t.Fatal("default lo unexpectedly intercepts output on another interface")
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		f.ifname = "br-lan"
		if err := setup(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("disabled DNS keeps TPROXY", func(t *testing.T) {
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
		f.dnsredir = false
		if err := setup(); err != nil {
			t.Fatal(err)
		}
		tcpEcho(t, "8.8.8.8:53")
		select {
		case got := <-destinations:
			if got != "8.8.8.8:53" {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("DNS should use TPROXY when redirect is disabled")
		}
	})
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	out, err := runFirewallCommand("", "nft", "list", "tables")
	if err != nil || strings.Contains(string(out), nftTProxyTable) || !strings.Contains(string(out), "fw4") {
		t.Fatalf("cleanup touched other tables: %s, %v", out, err)
	}
	out, err = runFirewallCommand("", "ip", "-4", "rule", "show")
	if err != nil || strings.Contains(string(out), "fwmark 0x2d0") {
		t.Fatalf("policy rule survived: %s, %v", out, err)
	}
	if legacy {
		out, err := runIPTablesCommand("iptables -t mangle -S")
		if err != nil || strings.Contains(out, "mihomo_") {
			t.Fatalf("legacy rules survived: %s, %v", out, err)
		}
	}
}

// Inject from a veth peer so these packets traverse PREROUTING as LAN/WAN
// traffic rather than masquerading as local socket traffic.
func sendFirewallUDPPacket(t *testing.T, sender, receiver, source, destination string, port uint16) {
	t.Helper()
	send, err := net.InterfaceByName(sender)
	if err != nil {
		t.Fatal(err)
	}
	recv, err := net.InterfaceByName(receiver)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("ingress-test")
	packet := make([]byte, 14+20+8+len(payload))
	copy(packet[:6], recv.HardwareAddr)
	copy(packet[6:12], send.HardwareAddr)
	binary.BigEndian.PutUint16(packet[12:14], unix.ETH_P_IP)
	ip := packet[14:34]
	ip[0], ip[8], ip[9] = 0x45, 64, unix.IPPROTO_UDP
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(packet)-14))
	copy(ip[12:16], net.ParseIP(source).To4())
	copy(ip[16:20], net.ParseIP(destination).To4())
	var sum uint32
	for i := 0; i < len(ip); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))
	udp := packet[34:]
	binary.BigEndian.PutUint16(udp[0:2], 32000+port%1000)
	binary.BigEndian.PutUint16(udp[2:4], port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload) // zero UDP checksum is valid for IPv4
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Sendto(fd, packet, 0, &unix.SockaddrLinklayer{Ifindex: send.Index, Halen: 6}); err != nil {
		t.Fatal(err)
	}
}
