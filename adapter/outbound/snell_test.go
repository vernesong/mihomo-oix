package outbound

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	tlsC "github.com/metacubex/mihomo/component/tls"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/transport/snell"
	"github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/tls"
)

func TestSnellReuseDialHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	adapter := &Snell{
		reuse: true,
		pool: snell.NewPool(func(factoryCtx context.Context) (*snell.Snell, error) {
			close(started)
			select {
			case <-factoryCtx.Done():
				return nil, factoryCtx.Err()
			case <-time.After(time.Second):
				return nil, errors.New("pool factory did not receive caller cancellation")
			}
		}),
	}
	result := make(chan error, 1)
	go func() {
		_, err := adapter.DialContext(ctx, &C.Metadata{})
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pooled dial remained blocked after cancellation")
	}
}

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "password",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if adapter.echTLS.ClientSessionCache == nil || adapter.echTLS.UClientSessionCache == nil {
		t.Fatal("ECH TLS session caches were not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellECHTLSResolvesClientFingerprint(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		obfs string
		top  string
		want string
	}{
		{name: "default", want: defaultSnellECHTLSClientFingerprint},
		{name: "obfs none", obfs: "none", want: defaultSnellECHTLSClientFingerprint},
		{name: "proxy none", top: "NONE", want: defaultSnellECHTLSClientFingerprint},
		{name: "explicit", obfs: "firefox", want: "firefox"},
		{name: "case", top: "FireFox120", want: "firefox120"},
		{name: "without ech", obfs: "safari", want: defaultSnellECHTLSClientFingerprint},
		{name: "unknown", obfs: "chrome131", want: defaultSnellECHTLSClientFingerprint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obfs := map[string]any{"mode": "ech-tls", "ech-config": echConfig}
			if tc.obfs != "" {
				obfs["client-fingerprint"] = tc.obfs
			}
			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
				ClientFingerprint: tc.top, ObfsOpts: obfs,
			})
			if err != nil {
				t.Fatalf("NewSnell() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.echTLS.ClientFingerprint; got != tc.want {
				t.Fatalf("ClientFingerprint = %q, want %q", got, tc.want)
			}
		})
	}
}

// clientBytesRecorder keeps what a server reads from its client.
type clientBytesRecorder struct {
	net.Conn
	read []byte
}

func (c *clientBytesRecorder) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read = append(c.read, b[:n]...)
	return n, err
}

func TestSnellECHTLSFingerprintsKeepALPNPrivate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"origin.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	echConfig, echKeyPEM, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(echKeyPEM))
	echKeys, err := ech.UnmarshalECHKeys(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := &tls.Config{
		NextProtos: []string{snellECHTLSALPN}, MinVersion: tls.VersionTLS13,
		Certificates:             []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		EncryptedClientHelloKeys: echKeys,
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	// Every name in component/tls's fingerprint table, then none, a wrong case and an unknown name.
	for _, fingerprint := range []string{
		"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random",
		"chrome120", "firefox120", "safari16", "chrome_psk", "chrome_psk_shuffle",
		"chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk", "randomized",
		"none", "Chrome", "chrome131",
	} {
		t.Run(fingerprint, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			hello := make(chan []byte, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					hello <- nil
					return
				}
				defer conn.Close()
				recorder := &clientBytesRecorder{Conn: conn}
				server := tls.Server(recorder, serverConfig)
				_ = server.SetDeadline(time.Now().Add(5 * time.Second))
				_ = server.Handshake()
				hello <- bytes.Clone(recorder.read)
				_, _ = io.Copy(io.Discard, server)
			}()

			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Psk: "password", Version: 4,
				ObfsOpts: map[string]any{
					"mode": "ech-tls", "ech-config": echConfig, "sni": "origin.example.com",
					"ca-file": caPEM, "client-fingerprint": fingerprint,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			used := adapter.echTLS.ClientFingerprint
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			raw, err := adapter.dialer.DialContext(ctx, "tcp", adapter.addr)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := vmess.StreamTLSConn(ctx, raw, adapter.echTLS)
			if err != nil {
				_ = raw.Close()
				t.Fatalf("handshake with %s: %v", used, err)
			}
			defer conn.Close()
			if state := tlsC.GetTLSConnectionState(conn); !state.ECHAccepted || state.NegotiatedProtocol != snellECHTLSALPN {
				t.Fatalf("%s: ECH accepted %v, ALPN %q", used, state.ECHAccepted, state.NegotiatedProtocol)
			}
			select {
			case raw := <-hello:
				for _, private := range []string{snellECHTLSALPN, "origin.example.com"} {
					if bytes.Contains(raw, []byte(private)) {
						t.Fatalf("%s sends %s in the clear", used, private)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server handshake did not finish")
			}
		})
	}
}

func TestSnellECHTLSRejectsSkippedCertificateVerification(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "skip-cert-verify": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires certificate verification") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSLegacyFallbackMustBeExplicit(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"identity-version": 2, "legacy-fallback": true, "ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if got := adapter.echTLS.NextProtos; len(got) != 2 || got[0] != snellECHTLSALPN || got[1] != snellECHTLSLegacyALPN {
		t.Fatalf("NextProtos = %q", got)
	}
}

func TestSnellECHTLSRejectsConflictingALPNAlias(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"protocol": "other/1", "ech-config": echConfig,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "values conflict") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSAcceptsPreviousProtocolAlias(t *testing.T) {
	got, err := resolveSnellECHTLSALPN("", snellECHTLSPreviousALPN)
	if err != nil || got != snellECHTLSALPN {
		t.Fatalf("resolveSnellECHTLSALPN() = (%q, %v)", got, err)
	}
}

func TestSnellHTTP3Options(t *testing.T) {
	config, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		transport string
		identity  int
		legacy    bool
		version   int
		valid     bool
	}{
		{"", 2, false, 4, true},
		{"tcp", 1, true, 4, true},
		{"h3", 2, false, 4, true},
		{"auto", 2, false, 4, true},
		{"quic", 2, false, 4, false},
		{"h3", 1, false, 4, false},
		{"auto", 2, true, 4, false},
		{"h3", 2, false, 3, false},
	} {
		adapter, err := NewSnell(SnellOption{
			Name: "fixture", Server: "127.0.0.1", Port: 443, Psk: "fixture", Version: tc.version,
			ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": config, "transport": tc.transport, "identity-version": tc.identity, "legacy-fallback": tc.legacy},
		})
		if (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
		if err == nil {
			_ = adapter.Close()
		}
	}
}

func TestSnellHTTP3ReceiveWindows(t *testing.T) {
	config := snellHTTP3QUICConfig()
	if config.MaxStreamReceiveWindow != 4*1024*1024 || config.MaxConnectionReceiveWindow != 16*1024*1024 {
		t.Fatalf("receive windows: stream %d, connection %d", config.MaxStreamReceiveWindow, config.MaxConnectionReceiveWindow)
	}
	// A stream that is never read keeps its initial window.
	if config.InitialStreamReceiveWindow != 64*1024 || config.InitialConnectionReceiveWindow != 1024*1024 {
		t.Fatalf("initial windows: stream %d, connection %d", config.InitialStreamReceiveWindow, config.InitialConnectionReceiveWindow)
	}
}

// blockingSnellDialer holds every dial until its context ends.
type blockingSnellDialer struct {
	C.Dialer
	started chan struct{}
	ended   chan struct{}
}

func (d *blockingSnellDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case d.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	select {
	case d.ended <- struct{}{}:
	default:
	}
	return nil, ctx.Err()
}

func TestSnellCloseStopsPreconnect(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	dialer := &blockingSnellDialer{started: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
	adapter, err := NewSnell(SnellOption{
		BasicOption: BasicOption{DialerForAPI: dialer},
		Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password", Version: 4, Reuse: true,
		ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	select {
	case <-dialer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("preconnect did not dial")
	}
	_ = adapter.Close()
	select {
	case <-dialer.ended:
	case <-time.After(2 * time.Second):
		t.Fatal("closing the proxy left the preconnect dial running")
	}
}

func TestSnellClampsPreconnect(t *testing.T) {
	for _, tc := range []struct{ preconnect, want int }{
		{-2, 0}, {-1, 0}, {0, 0}, {3, 3}, {4, 4}, {5, 4}, {200, 4},
	} {
		if got := clampSnellPreconnect("127.0.0.1:443", tc.preconnect); got != tc.want {
			t.Errorf("clampSnellPreconnect(%d) = %d, want %d", tc.preconnect, got, tc.want)
		}
	}
}

func TestSnellECHTLSLoadsPreconnectOutsideTheRangeClamped(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, preconnect := range []int{-2, 5, 200} {
		dialer := &blockingSnellDialer{started: make(chan struct{}, 1), ended: make(chan struct{}, 1)}
		adapter, err := NewSnell(SnellOption{
			BasicOption: BasicOption{DialerForAPI: dialer},
			Name:        "snell", Server: "127.0.0.1", Port: 443, Psk: "password", Version: 4, Reuse: true,
			ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": preconnect},
		})
		if err != nil {
			t.Fatalf("preconnect %d: NewSnell() error = %v", preconnect, err)
		}
		_ = adapter.Close()
	}
}

func TestSnellPreconnectWarningMasksManagedNodes(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	oixdns.ConfigureManagedDNS("managed.example", "127.0.0.1:53")
	t.Cleanup(oixdns.ResetManagedDNS)
	oixdns.MarkCloudIP("192.0.2.42")
	oixdns.MarkCloudIP("2001:db8::42")
	for _, tc := range []struct{ server, want string }{
		{"secret.managed.example", "***.managed.example"},
		{"192.0.2.42", "***.***.***.***"},
		{"2001:db8::42", "***.***.***.***"},
		{"public.example", "public.example"},
	} {
		t.Run(tc.server, func(t *testing.T) {
			events := log.Subscribe()
			defer log.UnSubscribe(events)
			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: tc.server, Port: 443, Psk: "password", Version: 4,
				ObfsOpts: map[string]any{"mode": "ech-tls", "ech-config": echConfig, "preconnect": -1},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			select {
			case event := <-events:
				if !strings.Contains(event.Payload, tc.want) || !strings.Contains(event.Payload, "preconnect -1") {
					t.Fatalf("unexpected warning: %s", event.Payload)
				}
				if tc.want != tc.server && strings.Contains(event.Payload, tc.server) {
					t.Fatalf("warning exposes managed node: %s", event.Payload)
				}
			case <-time.After(time.Second):
				t.Fatal("missing preconnect warning")
			}
		})
	}
}
