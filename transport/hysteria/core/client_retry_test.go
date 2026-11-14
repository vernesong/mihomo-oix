package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/hysteria/transport"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type packetWriteError struct{ temporary bool }

func (e *packetWriteError) Error() string   { return "packet write failed" }
func (e *packetWriteError) Timeout() bool   { return false }
func (e *packetWriteError) Temporary() bool { return e.temporary }

type failingWritePacketConn struct {
	net.PacketConn
	failure atomic.Pointer[packetWriteError]
}

func (c *failingWritePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if err := c.failure.Load(); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(p, addr)
}

type reconnectProbe struct {
	attempts int
	err      error
}

func (d *reconnectProbe) Context() context.Context { return context.Background() }
func (d *reconnectProbe) RemoteAddr(string) (net.Addr, error) {
	d.attempts++
	return nil, d.err
}

func (d *reconnectProbe) ListenPacket(net.Addr) (net.PacketConn, error) {
	return nil, d.err
}

// A custom PacketConn's write error survives QUIC's immediate-close path.
// A QUIC-type-only classifier would silently change the existing reconnect policy.
func TestOpenStreamReconnectAfterPacketWriteFailure(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, temporary := range []bool{true, false} {
		name := "permanent"
		if temporary {
			name = "temporary"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}},
				NextProtos:   []string{"retry-test"},
			}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			raw, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			pc := &failingWritePacketConn{PacketConn: raw}
			qt := &quic.Transport{Conn: pc}
			defer qt.Close()
			qs, err := qt.Dial(ctx, listener.Addr(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"retry-test"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer qs.CloseWithError(0, "")
			peer, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.CloseWithError(0, "")
			stream, err := qs.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			failure := &packetWriteError{temporary: temporary}
			pc.failure.Store(failure)
			_, _ = stream.Write([]byte("trigger packet send"))
			select {
			case <-qs.Context().Done():
			case <-ctx.Done():
				t.Fatal("packet failure did not close QUIC")
			}
			dialer := &reconnectProbe{err: errors.New("reconnect attempted")}
			client := &Client{quicSession: qs, transport: &transport.ClientTransport{}}
			_, _, err = client.openStreamWithReconnect(dialer)
			if temporary {
				if !errors.Is(err, failure) || dialer.attempts != 0 {
					t.Fatalf("temporary failure changed: err=%v reconnects=%d", err, dialer.attempts)
				}
			} else if !errors.Is(err, dialer.err) || dialer.attempts != 1 {
				t.Fatalf("permanent failure changed: err=%v reconnects=%d", err, dialer.attempts)
			}
		})
	}
}
