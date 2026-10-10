package snell

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/component/ech"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/tls"
)

func echoHTTP3Stream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Proto != "websocket" || r.URL.Path != "/fixture" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	stream := w.(http3.HTTPStreamer).HTTPStream()
	_, _ = io.Copy(stream, stream)
	_ = stream.Close()
}

func newHTTP3Fixture(t *testing.T, handler http.Handler) (*HTTP3Client, *atomic.Int32, *tls.Config) {
	t.Helper()
	if handler == nil {
		handler = http.HandlerFunc(echoHTTP3Stream)
	}
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
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	config, keyPEM, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(keyPEM))
	keys, err := ech.UnmarshalECHKeys(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	list, err := base64.StdEncoding.DecodeString(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, EncryptedClientHelloKeys: keys,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int32
	var workers sync.WaitGroup
	serveCtx, stop := context.WithCancel(t.Context())
	t.Cleanup(func() { stop(); workers.Wait() })
	workers.Go(func() {
		for {
			conn, err := listener.Accept(serveCtx)
			if err != nil {
				return
			}
			accepted.Add(1)
			workers.Go(func() {
				defer conn.CloseWithError(0, "")
				stopConn := context.AfterFunc(serveCtx, func() { _ = conn.CloseWithError(0, "") })
				defer stopConn()
				server := &http3.Server{Handler: handler}
				_ = server.ServeQUICConn(conn)
			})
		}
	})
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	tlsConfig := &tls.Config{
		NextProtos: []string{"h3"}, ServerName: "origin.example.com", RootCAs: roots,
		MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list,
	}
	client := &HTTP3Client{Host: "origin.example.com", Path: "/fixture", Dial: func(ctx context.Context) (*quic.Conn, error) {
		return quic.DialAddr(ctx, listener.Addr().String(), tlsConfig, &quic.Config{KeepAlivePeriod: 10 * time.Second})
	}}
	t.Cleanup(func() { _ = client.Close() })
	return client, &accepted, tlsConfig
}

func TestHTTP3MultiplexingBackpressureAndCancellation(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	first, firstExporter, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, exporter, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if len(exporter) != IdentityExporterLength || !bytes.Equal(exporter, firstExporter) {
		t.Fatal("streams did not share the QUIC exporter")
	}
	_ = first.Close()
	payload := bytes.Repeat([]byte("HTTP3 flow control payload\x00"), 128*1024)
	result := make(chan error, 1)
	go func() {
		_, err := second.Write(payload)
		if err == nil {
			err = second.(*http3Conn).CloseWrite()
		}
		result <- err
	}()
	_ = second.SetReadDeadline(time.Now().Add(8 * time.Second))
	got, err := io.ReadAll(second)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %d / %d bytes", len(got), len(payload))
	}
	if accepted.Load() != 1 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, _, err := client.Open(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled open: %v", err)
	}
	third, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = third.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err = third.Read(make([]byte, 1)); err == nil {
		t.Fatal("read deadline ignored")
	}
	_ = third.Close()
	_ = client.Close()
	if _, _, err = client.Open(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("open after close: %v", err)
	}
}

func TestHTTP3RequiresCertificateAndECH(t *testing.T) {
	for _, kind := range []string{"certificate", "ECH"} {
		t.Run(kind, func(t *testing.T) {
			client, _, config := newHTTP3Fixture(t, nil)
			if kind == "certificate" {
				config.RootCAs = x509.NewCertPool()
			} else {
				config.EncryptedClientHelloConfigList = nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			if conn, _, err := client.Open(ctx); err == nil {
				_ = conn.Close()
				t.Fatal("insecure HTTP3 connection accepted")
			}
		})
	}
}

func TestHTTP3SharedDialSurvivesCanceledOpener(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, nil)
	if rtt := client.SmoothedRTT(); rtt != 0 {
		t.Fatalf("RTT %v before any session", rtt)
	}
	started, proceed := make(chan struct{}), make(chan struct{})
	dial := client.Dial
	var dials atomic.Int32
	client.Dial = func(ctx context.Context) (*quic.Conn, error) {
		if dials.Add(1) == 1 {
			close(started)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-proceed:
			return dial(ctx)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	initiator, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	go func() { _, _, err := client.Open(initiator); result <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("session dial did not start")
	}
	stop()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled opener: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("canceled opener did not return")
	}
	close(proceed)
	stream, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if dials.Load() != 1 || accepted.Load() != 1 {
		t.Fatalf("shared dial restarted: %d dials, %d sessions", dials.Load(), accepted.Load())
	}
	if client.SmoothedRTT() <= 0 {
		t.Fatal("live session reported no RTT")
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("shared session survives caller cancellation")
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("shared session echo: %q, %v", got, err)
	}
	_ = client.Close()
	if rtt := client.SmoothedRTT(); rtt != 0 {
		t.Fatalf("RTT %v after close", rtt)
	}
}

func TestHTTP3CloseCancelsPendingDial(t *testing.T) {
	started := make(chan struct{})
	client := &HTTP3Client{Dial: func(ctx context.Context) (*quic.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	result := make(chan error, 1)
	go func() { _, _, err := client.Open(t.Context()); result <- err }()
	<-started
	_ = client.Close()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not cancel pending dial")
	}
}

// A session dial belongs to no single Open: an initiator that gives up leaves it
// running for later waiters, and its failure reaches them all instead of each
// starting another dial; DialTimeout still bounds a dial nobody cancels.
func TestHTTP3SharedDialOutlivesInitiatorAndFailsWaitersOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var dials atomic.Int32
		dialErr := errors.New("handshake failed")
		client := &HTTP3Client{DialTimeout: 2 * time.Second, Dial: func(ctx context.Context) (*quic.Conn, error) {
			dials.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
				return nil, dialErr
			}
		}}
		initiator, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, _, err := client.Open(initiator); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("initiator: %v", err)
		}
		errs := make(chan error, 2)
		for range 2 {
			go func() { _, _, err := client.Open(context.Background()); errs <- err }()
		}
		for range 2 {
			if err := <-errs; !errors.Is(err, dialErr) {
				t.Fatalf("waiter: %v", err)
			}
		}
		if dials.Load() != 1 {
			t.Fatalf("%d dials", dials.Load())
		}
		client.Dial = func(ctx context.Context) (*quic.Conn, error) {
			dials.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		start := time.Now()
		if _, _, err := client.Open(context.Background()); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 2*time.Second {
			t.Fatalf("unbounded dial: %v after %v", err, time.Since(start))
		}
	})
}

func TestHTTP3ReclaimsRejectedSessions(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	var connections []*quic.Conn
	dial := client.Dial
	client.Dial = func(ctx context.Context) (*quic.Conn, error) {
		conn, err := dial(ctx)
		if err == nil {
			connections = append(connections, conn)
		}
		return conn, err
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 3 {
		if stream, _, err := client.Open(ctx); err == nil {
			_ = stream.Close()
			t.Fatal("expected CONNECT rejection")
		}
	}
	if accepted.Load() != 3 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
	for _, conn := range connections {
		select {
		case <-conn.Context().Done():
		case <-time.After(time.Second):
			t.Fatal("rejected session remained open without active streams")
		}
	}
}

func TestHTTP3RetirementPreservesActiveStreams(t *testing.T) {
	var requests atomic.Int32
	client, accepted, _ := newHTTP3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		echoHTTP3Stream(w, r)
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	open := func() net.Conn {
		t.Helper()
		stream, _, err := client.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stream.Close() })
		deadline, _ := ctx.Deadline()
		_ = stream.SetDeadline(deadline)
		return stream
	}
	first, second := open(), open()
	client.mu.Lock()
	retired := client.conn
	client.mu.Unlock()
	if stream, _, err := client.Open(ctx); err == nil {
		_ = stream.Close()
		t.Fatal("expected CONNECT rejection")
	}
	successor := open()
	_ = first.Close()
	_ = first.Close()
	if err := retired.Context().Err(); err != nil {
		t.Fatalf("retired session closed with an active stream: %v", err)
	}
	remaining := []byte("retired session remains usable")
	if _, err := second.Write(remaining); err != nil {
		t.Fatal(err)
	}
	_ = second.(*http3Conn).CloseWrite()
	if got, err := io.ReadAll(second); err != nil || !bytes.Equal(got, remaining) {
		t.Fatalf("retired session echo: %q, %v", got, err)
	}
	if err := retired.Context().Err(); err != nil {
		t.Fatalf("half-close released the session: %v", err)
	}
	_ = second.Close()
	select {
	case <-retired.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("retired session remained open after its last stream closed")
	}
	payload := []byte("successor survives retirement")
	if _, err := successor.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(successor, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("successor echo: %q, %v", got, err)
	}
	if accepted.Load() != 2 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
}

func TestHTTP3RetirementWaitsForPendingOpen(t *testing.T) {
	for _, outcome := range []string{"success", "cancellation"} {
		t.Run(outcome, func(t *testing.T) {
			waiting, unblock := make(chan struct{}), make(chan struct{})
			var requests atomic.Int32
			client, _, _ := newHTTP3Fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) != 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				close(waiting)
				select {
				case <-unblock:
					echoHTTP3Stream(w, r)
				case <-r.Context().Done():
				}
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			type openResult struct {
				stream net.Conn
				err    error
			}
			result := make(chan openResult, 1)
			go func() {
				stream, _, err := client.Open(ctx)
				result <- openResult{stream, err}
			}()
			select {
			case <-waiting:
			case <-ctx.Done():
				t.Fatal("first CONNECT did not arrive")
			}
			client.mu.Lock()
			retired := client.conn
			client.mu.Unlock()
			if stream, _, err := client.Open(ctx); err == nil {
				_ = stream.Close()
				t.Fatal("expected CONNECT rejection")
			}
			if err := retired.Context().Err(); err != nil {
				t.Fatalf("retired session closed during CONNECT: %v", err)
			}
			if outcome == "cancellation" {
				cancel()
			} else {
				close(unblock)
			}
			select {
			case opened := <-result:
				if opened.stream != nil {
					_ = opened.stream.Close()
				}
				if outcome == "cancellation" {
					if !errors.Is(opened.err, context.Canceled) {
						t.Fatalf("canceled open: %v", opened.err)
					}
				} else if opened.err != nil {
					t.Fatal(opened.err)
				}
			case <-time.After(time.Second):
				t.Fatal("pending CONNECT did not finish")
			}
			select {
			case <-retired.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("retired session remained open after CONNECT finished")
			}
		})
	}
}
