package outbound

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/masque"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	"github.com/metacubex/tls"
)

// Exercise first-use initialization through real CONNECT-IP packets, rather than
// treating successful construction or a transport handshake as a working tunnel.
func TestMasqueLazyStackRoundTrip(t *testing.T) {
	for _, mode := range memoryStackModes() {
		for _, network := range []string{"h2", "h3"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				option := masqueMemoryOption(t)
				option.IPStack.Mode, option.Network = mode, network
				option.Ipv6, option.URI, option.SNI = "fd00::2/128", "https://masque.test/tunnel", "masque.test"
				port, requests := startMasquePacketPeer(t, option)
				option.Port = port
				node, err := NewMasque(option)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = node.Close() })
				if node.tunDevice != nil {
					t.Fatal("constructed an unused stack")
				}
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				var wg sync.WaitGroup
				for _, address := range []string{"10.0.0.1", "fd00::1"} {
					for _, protocol := range []C.NetWork{C.TCP, C.UDP} {
						wg.Go(func() {
							metadata := &C.Metadata{NetWork: protocol, DstIP: netip.MustParseAddr(address), DstPort: 9000}
							if err := masqueEcho(ctx, node, metadata); err != nil {
								t.Errorf("%s/%s: %v", protocol, address, err)
							}
						})
					}
				}
				wg.Wait()
				if got := requests.Load(); got != 1 {
					t.Fatalf("concurrent first uses opened %d tunnels, want 1", got)
				}
			})
		}
	}
}

func masqueEcho(ctx context.Context, node *Masque, metadata *C.Metadata) error {
	payload := bytes.Repeat([]byte(metadata.DstIP.String()), 24)
	response := make([]byte, len(payload))
	deadline, _ := ctx.Deadline()
	if metadata.NetWork == C.TCP {
		conn, err := node.DialContext(ctx, metadata)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, response); err != nil {
			return err
		}
	} else {
		conn, err := node.ListenPacketContext(ctx, metadata)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(deadline)
		if _, err := conn.WriteTo(payload, net.UDPAddrFromAddrPort(metadata.AddrPort())); err != nil {
			return err
		}
		n, from, err := conn.ReadFrom(response)
		if err != nil {
			return err
		}
		if n != len(payload) || from.String() != metadata.AddrPort().String() {
			return fmt.Errorf("UDP reply: %d bytes from %s", n, from)
		}
	}
	if !bytes.Equal(response, payload) {
		return fmt.Errorf("echo payload mismatch")
	}
	return nil
}

// The peer uses a separate userspace IP stack, TCP/UDP echo sockets and the
// existing H2 capsule / H3 datagram framing. No host routes or external server
// are needed, and the client still checks the server's pinned public key.
func startMasquePacketPeer(t *testing.T, option MasqueOption) (int, *atomic.Int32) {
	t.Helper()
	peer, err := newIPStack(IPStackOption{Mode: ipStackMips}, []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("fd00::1/128"),
	}, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	t.Cleanup(func() { _ = peer.Close(); workers.Wait() })
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"10.0.0.1:9000", "[fd00::1]:9000"} {
		addr := netip.MustParseAddrPort(address)
		listener, err := peer.ListenTCP(t.Context(), "tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		workers.Go(func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				workers.Go(func() { defer conn.Close(); _, _ = io.Copy(conn, conn) })
			}
		})
		packetConn, err := peer.ListenUDP(t.Context(), "udp", addr)
		if err != nil {
			t.Fatal(err)
		}
		workers.Go(func() {
			buf := make([]byte, 2048)
			for {
				n, from, err := packetConn.ReadFrom(buf)
				if err != nil {
					return
				}
				if _, err := packetConn.WriteTo(buf[:n], from); err != nil {
					return
				}
			}
		})
	}
	var requests atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || requests.Add(1) != 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stop := context.AfterFunc(r.Context(), func() { _ = peer.Close() })
		defer stop()
		defer peer.Close()
		var receive func() ([]byte, error)
		var send func([]byte) error
		w.WriteHeader(http.StatusOK)
		if option.Network == "h2" {
			w.(http.Flusher).Flush()
			reader := quicvarint.NewReader(r.Body)
			receive = func() ([]byte, error) {
				kind, err := quicvarint.Read(reader)
				if err != nil {
					return nil, err
				}
				n, err := quicvarint.Read(reader)
				if err != nil {
					return nil, err
				}
				if kind != 0 || n > 65535 {
					return nil, fmt.Errorf("invalid IP capsule: %d/%d", kind, n)
				}
				packet := make([]byte, n)
				_, err = io.ReadFull(reader, packet)
				return packet, err
			}
			send = func(packet []byte) error {
				frame := quicvarint.Append(nil, 0)
				frame = quicvarint.Append(frame, uint64(len(packet)))
				_, err := w.Write(append(frame, packet...))
				w.(http.Flusher).Flush()
				return err
			}
		} else {
			stream := w.(http3.HTTPStreamer).HTTPStream()
			defer stream.Close()
			defer stream.CancelRead(0)
			workers.Go(func() { _, _ = io.Copy(io.Discard, stream) })
			receive = func() ([]byte, error) {
				data, err := stream.ReceiveDatagram(r.Context())
				if err != nil {
					return nil, err
				}
				id, n, err := quicvarint.Parse(data)
				if err != nil || id != 0 {
					return nil, fmt.Errorf("invalid IP datagram context: %d/%v", id, err)
				}
				return data[n:], nil
			}
			send = func(packet []byte) error { return stream.SendDatagram(append([]byte{0}, packet...)) }
		}
		workers.Go(func() {
			defer peer.Close()
			for {
				packet, err := receive()
				if err != nil {
					return
				}
				if _, err := peer.Write([][]byte{packet}, 0); err != nil {
					return
				}
			}
		})
		buffer := make([]byte, 65535)
		sizes := []int{0}
		for {
			if _, err := peer.Read([][]byte{buffer}, sizes, 0); err != nil {
				return
			}
			if err := send(buffer[:sizes[0]]); err != nil {
				return
			}
		}
	})
	private, err := base64.StdEncoding.DecodeString(option.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := masque.GenerateCert(key)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: cert, PrivateKey: key}}}
	if option.Network == "h2" {
		server := httptest.NewUnstartedServer(handler)
		server.TLS, server.EnableHTTP2 = config, true
		server.StartTLS()
		t.Cleanup(func() { _ = peer.Close(); server.Close() })
		return server.Listener.Addr().(*net.TCPAddr).Port, &requests
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: config, EnableDatagrams: true, Handler: handler}
	workers.Go(func() { _ = server.Serve(listener) })
	t.Cleanup(func() { _ = peer.Close(); _ = server.Close(); _ = listener.Close() })
	return listener.LocalAddr().(*net.UDPAddr).Port, &requests
}
