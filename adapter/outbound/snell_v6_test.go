package outbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/socks5"
)

func TestSnellV6Profile(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"tcp", "h3", "auto"} {
		opt := SnellOption{Name: "v6", Server: "127.0.0.1", Port: 443, Psk: "fixture", Version: 6, UDP: true, Reuse: true, ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig, "transport": transport}}
		s, err := NewSnell(opt)
		if err != nil {
			t.Fatal(err)
		}
		if !s.identity || !s.reuse || s.echTLS.NextProtos[0] != "snell-ech/2" {
			t.Fatal("incomplete v6 profile")
		}
		s.Close()
		for _, change := range []map[string]any{{"alpn": "snell-ech/1"}, {"legacy-fallback": true}, {"identity-version": 1}, {"skip-cert-verify": true}, {"mode": ""}} {
			bad := opt
			bad.ObfsOpts = map[string]any{"mode": "ech-tls", "ech-config": echConfig, "transport": transport}
			for k, v := range change {
				bad.ObfsOpts[k] = v
			}
			s, err = NewSnell(bad)
			if err == nil {
				s.Close()
				t.Fatalf("accepted invalid v6 options: %v", change)
			}
		}
	}
}

// Runs against dler-server's opt-in, fictional loopback fixture.
func TestSnellV6CompanionInterop(t *testing.T) {
	dir := os.Getenv("SNELL_HTTP3_INTEROP_DIR")
	if dir == "" {
		t.Skip("requires private loopback fixture")
	}
	data, err := os.ReadFile(filepath.Join(dir, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]string
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	host, portString, _ := net.SplitHostPort(f["address"])
	port, _ := strconv.Atoi(portString)
	target, echoPortString, _ := net.SplitHostPort(f["echo"])
	echoPort, _ := strconv.Atoi(echoPortString)
	for _, version := range []int{4, 6} {
		for _, transport := range []string{"tcp", "h3", "auto"} {
			t.Run(strconv.Itoa(version)+"/"+transport, func(t *testing.T) {
				psk := f["psk"]
				if version == 6 && f["psk_v6"] != "" {
					psk = f["psk_v6"]
				}
				s, err := NewSnell(SnellOption{Name: "fixture", Server: host, Port: port, Psk: psk, Version: version, UDP: true, Reuse: true, ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": f["ech_config"], "sni": f["server_name"], "ca-file": string(caPEM), "transport": transport}})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				conn, err := s.dialSnell(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if err = conn.Warmup(); err != nil {
					t.Fatal(err)
				}
				for _, size := range []int{1, 8192, 131071, 17} {
					if err = snell.WriteHeaderWithReuse(conn, target, uint(echoPort), version, true); err != nil {
						t.Fatal(err)
					}
					if err = conn.ReadReply(); err != nil {
						t.Fatal(err)
					}
					payload := bytes.Repeat([]byte{byte(size)}, size)
					written := make(chan error, 1)
					go func() {
						_, err := conn.Write(payload)
						if err == nil {
							err = snell.HalfClose(conn)
						}
						written <- err
					}()
					got := make([]byte, size)
					if _, err = io.ReadFull(conn.Conn, got); err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("TCP %d: %v", size, err)
					}
					var end [1]byte
					if _, err = conn.Conn.Read(end[:]); !errors.Is(err, shadowaead.ErrZeroChunk) {
						t.Fatalf("reuse boundary: %v", err)
					}
					if err = <-written; err != nil {
						t.Fatal(err)
					}
				}
				udpHost, udpPortString, _ := net.SplitHostPort(f["udp_echo"])
				udpPort, _ := strconv.Atoi(udpPortString)
				udp, err := s.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr(udpHost), DstPort: uint16(udpPort)})
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				_ = udp.SetDeadline(time.Now().Add(5 * time.Second))
				address := socks5.ParseAddr(f["udp_echo"]).UDPAddr()
				for _, size := range []int{1, 1200, 8192, 17} {
					payload := bytes.Repeat([]byte{7}, size)
					if _, err = udp.WriteTo(payload, address); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 16383)
					n, _, err := udp.ReadFrom(got)
					if err != nil || !bytes.Equal(got[:n], payload) {
						t.Fatalf("UDP %d: %v", size, err)
					}
				}
			})
		}
	}
}
