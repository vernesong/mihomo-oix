package inbound_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/gobwas/ws"
	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInboundAnyTLS(t *testing.T, inboundOptions inbound.AnyTLSOption, outboundOptions outbound.AnyTLSOption) {
	t.Parallel()
	inboundOptions.BaseOption = inbound.BaseOption{
		NameStr: "anytls_inbound",
		Listen:  "127.0.0.1",
		Port:    "0",
	}
	inboundOptions.Users = map[string]string{"test": userUUID}
	in, err := inbound.NewAnyTLS(&inboundOptions)
	if !assert.NoError(t, err) {
		return
	}

	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	err = in.Listen(tunnel)
	if !assert.NoError(t, err) {
		return
	}
	defer in.Close()

	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return
	}

	outboundOptions.Name = "anytls_outbound"
	outboundOptions.Server = addrPort.Addr().String()
	outboundOptions.Port = int(addrPort.Port())
	outboundOptions.Password = userUUID
	outboundOptions.DialerForAPI = tunnel.NewDialer()
	outboundOptions.TunnelForAPI = tunnel

	out, err := outbound.NewAnyTLS(outboundOptions)
	if !assert.NoError(t, err) {
		return
	}
	defer out.Close()

	tunnel.DoTest(t, out)
}

func TestInboundAnyTLS_TLS(t *testing.T) {
	inboundOptions := inbound.AnyTLSOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.AnyTLSOption{
		Fingerprint: tlsFingerprint,
	}
	testInboundAnyTLS(t, inboundOptions, outboundOptions)
	t.Run("ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("mTLS+ECH", func(t *testing.T) {
		inboundOptions := inboundOptions
		outboundOptions := outboundOptions
		inboundOptions.ClientAuthCert = tlsAuthCertificate
		outboundOptions.Certificate = tlsAuthCertificate
		outboundOptions.PrivateKey = tlsAuthPrivateKey
		inboundOptions.EchKey = echKeyPem
		outboundOptions.ECHOpts = outbound.ECHOptions{
			Enable: true,
			Config: echConfigBase64,
		}
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
}

func testInboundAnyTLSUTLS(t *testing.T, inboundOptions inbound.AnyTLSOption, outboundOptions outbound.AnyTLSOption) {
	t.Parallel()
	t.Run("Conn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
	t.Run("UConn", func(t *testing.T) {
		inboundOptions, outboundOptions := inboundOptions, outboundOptions // don't modify outside options value
		outboundOptions.ClientFingerprint = "chrome"
		testInboundAnyTLS(t, inboundOptions, outboundOptions)
	})
}

func TestInboundAnyTLS_ShadowTLS(t *testing.T) {
	const password = "shadow-tls-password"
	inboundOptions := inbound.AnyTLSOption{
		ShadowTLS: inbound.ShadowTLS{
			Enable:    true,
			Version:   3,
			Users:     []inbound.ShadowTLSUser{{Name: "test", Password: password}},
			Handshake: inbound.ShadowTLSHandshakeOptions{Dest: net.JoinHostPort(realityDest, "443")},
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:           realityDest,
		Fingerprint:   tlsFingerprint,
		ShadowTLSOpts: outbound.ShadowTLSOptions{Password: password, Version: 3},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundAnyTLS_Restls(t *testing.T) {
	const password = "restls-password"
	inboundOptions := inbound.AnyTLSOption{
		ResTLS: inbound.ResTLS{
			Enable:   true,
			Dest:     net.JoinHostPort(realityDest, "443"),
			Password: password,
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:         realityDest,
		Fingerprint: tlsFingerprint,
		RestlsOpts:  outbound.RestlsOptions{Password: password, VersionHint: "tls13"},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

func TestInboundAnyTLS_JLS(t *testing.T) {
	const username = "jls-user"
	const password = "jls-password"
	inboundOptions := inbound.AnyTLSOption{
		JLSConfig: inbound.JLSConfig{
			Enable: true,
			Users:  []inbound.JLSUser{{Username: username, Password: password}},
			SNI:    realityDest,
			Dest:   net.JoinHostPort(realityDest, "443"),
		},
	}
	outboundOptions := outbound.AnyTLSOption{
		SNI:     realityDest,
		JLSOpts: outbound.JLSOptions{Username: username, Password: password},
	}
	testInboundAnyTLSUTLS(t, inboundOptions, outboundOptions)
}

// relayWebSocket stands in for the CDN and the origin's reverse proxy: it ends
// the outer TLS and WebSocket, and hands the payload to the AnyTLS port.
func relayWebSocket(conn net.Conn, target string, largestFrame *atomic.Int64) {
	defer conn.Close()
	upgrader := ws.Upgrader{OnRequest: func(uri []byte) error {
		if string(uri) != "/anytls-ws" {
			return ws.RejectConnectionError(ws.RejectionStatus(404))
		}
		return nil
	}}
	if _, err := upgrader.Upgrade(conn); err != nil {
		return
	}
	origin, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer origin.Close()
	go func() {
		defer conn.Close()
		buffer := make([]byte, 64*1024)
		for {
			n, err := origin.Read(buffer)
			if n > 0 && ws.WriteFrame(conn, ws.NewBinaryFrame(buffer[:n])) != nil {
				return
			}
			if err != nil {
				return
			}
		}
	}()
	for {
		frame, err := ws.ReadFrame(conn)
		if err != nil || frame.Header.OpCode != ws.OpBinary || !frame.Header.Masked {
			return
		}
		if size := int64(len(frame.Payload)); size > largestFrame.Load() {
			largestFrame.Store(size)
		}
		if _, err = origin.Write(ws.UnmaskFrameInPlace(frame).Payload); err != nil {
			return
		}
	}
}

func relayCertificate(t *testing.T) (tls.Certificate, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,

		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestInboundAnyTLS_WebSocket(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	in, err := inbound.NewAnyTLS(&inbound.AnyTLSOption{
		BaseOption:  inbound.BaseOption{NameStr: "anytls_ws_inbound", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": userUUID},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	require.NoError(t, err)
	require.NoError(t, in.Listen(tunnel))
	defer in.Close()

	certificate, certificatePEM := relayCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
	})
	require.NoError(t, err)
	defer listener.Close()
	var largestFrame atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go relayWebSocket(conn, in.Address(), &largestFrame)
		}
	}()

	option := outbound.AnyTLSOption{
		Name:        "anytls_ws_outbound",
		Server:      "127.0.0.1",
		Port:        listener.Addr().(*net.TCPAddr).Port,
		Password:    userUUID,
		Network:     "ws",
		WSOpts:      outbound.AnyTLSWSOptions{Path: "/anytls-ws"},
		Fingerprint: tlsFingerprint,
	}
	option.DialerForAPI = tunnel.NewDialer()
	option.TunnelForAPI = tunnel

	t.Run("outer certificate is verified", func(t *testing.T) {
		option := option
		option.SkipCertVerify = true
		out, err := outbound.NewAnyTLS(option)
		require.NoError(t, err)
		defer out.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err = out.DialContext(ctx, &C.Metadata{Host: "example.invalid", DstPort: 80})
		assert.Error(t, err)
	})

	require.NoError(t, ca.AddCertificate(certificatePEM))
	defer ca.ResetCertificate()
	out, err := outbound.NewAnyTLS(option)
	require.NoError(t, err)
	defer out.Close()
	tunnel.DoTest(t, out)
	// The server refuses a larger WebSocket frame.
	assert.Positive(t, largestFrame.Load())
	assert.LessOrEqual(t, largestFrame.Load(), int64(64*1024))
}

func TestOutboundAnyTLS_RejectsBadWebSocketOptions(t *testing.T) {
	base := outbound.AnyTLSOption{Name: "anytls", Server: "127.0.0.1", Port: 443, Password: userUUID}
	for _, broken := range []func(*outbound.AnyTLSOption){
		func(o *outbound.AnyTLSOption) { o.Network = "grpc" },
		func(o *outbound.AnyTLSOption) { o.Network = "ws" },
		func(o *outbound.AnyTLSOption) { o.WSOpts.Path = "/anytls-ws" },
		func(o *outbound.AnyTLSOption) { o.Network, o.WSOpts.Path = "ws", "anytls-ws" },
		func(o *outbound.AnyTLSOption) { o.Network, o.WSOpts.Path = "ws", "/anytls?ed=2048" },
	} {
		option := base
		broken(&option)
		_, err := outbound.NewAnyTLS(option)
		assert.Error(t, err, "%+v", option)
	}
}
