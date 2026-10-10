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
	return newHTTP3ServerFixture(t, handler, nil, nil)
}

// newHTTP3ServerFixture also takes the server's QUIC limits and a hook that sees
// the http3.Server of every accepted session, for tests that drain or exhaust it.
func newHTTP3ServerFixture(t *testing.T, handler http.Handler, serverConfig *quic.Config, onServer func(*http3.Server)) (*HTTP3Client, *atomic.Int32, *tls.Config) {
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
	}, serverConfig)
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
				if onServer != nil {
					onServer(server)
				}
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

func assertHTTP3Echo(t *testing.T, stream net.Conn, message string) {
	t.Helper()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := stream.Write([]byte(message)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(stream, got); err != nil || string(got) != message {
		t.Fatalf("echo %q: %q, %v", message, got, err)
	}
}

func currentHTTP3Session(client *HTTP3Client) *quic.Conn {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.conn
}

func waitHTTP3SessionClosed(t *testing.T, conn *quic.Conn, within time.Duration, what string) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(within):
		t.Fatalf("%s stayed open", what)
	}
}

func requireHTTP3SessionOpen(t *testing.T, conn *quic.Conn, what string) {
	t.Helper()
	if err := conn.Context().Err(); err != nil {
		t.Fatalf("%s closed: %v", what, err)
	}
}

// A graceful server shutdown leaves the QUIC session up for its active streams but
// refuses new requests, either client-side after GOAWAY or with H3_REQUEST_REJECTED
// for a request that raced it. Nothing was sent, so the next session serves the Open.
func TestHTTP3OpenRetriesOnFreshSessionAfterGoAway(t *testing.T) {
	servers := make(chan *http3.Server, 4)
	client, accepted, _ := newHTTP3ServerFixture(t, nil, nil, func(s *http3.Server) { servers <- s })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	active, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	draining := currentHTTP3Session(client)
	shutdown := make(chan error, 1)
	go func() { shutdown <- (<-servers).Shutdown(context.Background()) }()
	time.Sleep(200 * time.Millisecond)

	next, _, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open after GOAWAY: %v", err)
	}
	if accepted.Load() != 2 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
	if current := currentHTTP3Session(client); current == draining || current == nil {
		t.Fatal("the draining session stayed current")
	}
	assertHTTP3Echo(t, next, "fresh session")
	assertHTTP3Echo(t, active, "draining session keeps its stream")
	requireHTTP3SessionOpen(t, draining, "draining session")

	_ = active.Close()
	waitHTTP3SessionClosed(t, draining, time.Second, "draining session without streams")
	_ = next.Close()
	select {
	case <-shutdown:
	case <-time.After(2 * time.Second):
		t.Fatal("server shutdown did not finish")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.connections) > 1 {
		t.Fatalf("%d sessions tracked after the drained one closed", len(client.connections))
	}
	for conn, active := range client.connections {
		if conn == draining || active != 0 {
			t.Fatalf("session reference count %d after every stream closed", active)
		}
	}
}

func rejectHTTP3Request(w http.ResponseWriter) {
	stream := w.(http3.HTTPStreamer).HTTPStream()
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
}

func TestHTTP3OpenRetriesRejectedRequestOnFreshSession(t *testing.T) {
	var requests atomic.Int32
	client, accepted, _ := newHTTP3ServerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			rejectHTTP3Request(w)
			return
		}
		echoHTTP3Stream(w, r)
	}), nil, nil)
	var rejecting *quic.Conn
	dial := client.Dial
	client.Dial = func(ctx context.Context) (*quic.Conn, error) {
		conn, err := dial(ctx)
		if rejecting == nil {
			rejecting = conn
		}
		return conn, err
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, _, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open after rejection: %v", err)
	}
	defer stream.Close()
	assertHTTP3Echo(t, stream, "after rejection")
	if accepted.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("%d sessions, %d requests", accepted.Load(), requests.Load())
	}
	waitHTTP3SessionClosed(t, rejecting, time.Second, "session that rejected the request")
}

func TestHTTP3OpenRetriesOnlyOnce(t *testing.T) {
	var requests atomic.Int32
	client, accepted, _ := newHTTP3ServerFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		rejectHTTP3Request(w)
	}), nil, nil)
	var sessions []*quic.Conn
	dial := client.Dial
	client.Dial = func(ctx context.Context) (*quic.Conn, error) {
		conn, err := dial(ctx)
		if err == nil {
			sessions = append(sessions, conn)
		}
		return conn, err
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if stream, _, err := client.Open(ctx); err == nil {
		_ = stream.Close()
		t.Fatal("rejected twice but opened")
	}
	if accepted.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("%d sessions, %d requests", accepted.Load(), requests.Load())
	}
	for _, conn := range sessions {
		waitHTTP3SessionClosed(t, conn, time.Second, "rejecting session")
	}
}

// With the server's stream limit used up OpenStreamSync waits for credit that may
// never come; a session whose limit stays exhausted must not hold new Opens until
// their deadline while a second session would serve them.
func TestHTTP3OpenDialsNewSessionWhenStreamLimitStaysExhausted(t *testing.T) {
	client, accepted, _ := newHTTP3ServerFixture(t, nil, &quic.Config{MaxIncomingStreams: 2}, nil)
	client.OpenTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	full := currentHTTP3Session(client)
	start := time.Now()
	third, _, err := client.Open(ctx)
	if err != nil {
		t.Fatalf("open with the stream limit used up: %v after %v", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed < client.OpenTimeout || elapsed > 2*time.Second {
		t.Fatalf("open took %v, want the open timeout plus a dial", elapsed)
	}
	if accepted.Load() != 2 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
	assertHTTP3Echo(t, third, "second session")
	assertHTTP3Echo(t, first, "exhausted session keeps its streams")
	assertHTTP3Echo(t, second, "exhausted session keeps its streams")
	requireHTTP3SessionOpen(t, full, "exhausted session")
	fourth, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.Load() != 2 || currentHTTP3Session(client) == full {
		t.Fatalf("new opens did not move to the second session: %d sessions", accepted.Load())
	}
	_ = fourth.Close()
	_ = third.Close()
	_ = first.Close()
	requireHTTP3SessionOpen(t, full, "exhausted session with a stream left")
	_ = second.Close()
	waitHTTP3SessionClosed(t, full, time.Second, "exhausted session without streams")
}

// Credit that arrives while Open waits for it is no reason to leave the session.
func TestHTTP3OpenWaitsForStreamCreditWithinTheTimeout(t *testing.T) {
	client, accepted, _ := newHTTP3ServerFixture(t, nil, &quic.Config{MaxIncomingStreams: 1}, nil)
	client.OpenTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(100*time.Millisecond, func() { _ = first.Close() })
	second, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	assertHTTP3Echo(t, second, "credit arrived")
	if accepted.Load() != 1 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
}

func TestHTTP3OpenKeepsCallerDeadlineBelowTheOpenTimeout(t *testing.T) {
	client, accepted, _ := newHTTP3ServerFixture(t, nil, &quic.Config{MaxIncomingStreams: 1}, nil)
	client.OpenTimeout = 5 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	held, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	short, stop := context.WithTimeout(ctx, 200*time.Millisecond)
	defer stop()
	if _, _, err = client.Open(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("open past the caller deadline: %v", err)
	}
	if accepted.Load() != 1 || currentHTTP3Session(client) == nil {
		t.Fatal("a caller's own deadline retired the session")
	}
}

// Nothing keeps a session alive once its last stream closed: the keepalive pings
// of an unused session wake a mobile radio until the client is reloaded.
func TestHTTP3IdleSessionClosesAndOpenDialsAnother(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, nil)
	client.IdleTimeout = 150 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	idle := currentHTTP3Session(client)
	assertHTTP3Echo(t, stream, "in use")
	time.Sleep(2 * client.IdleTimeout)
	requireHTTP3SessionOpen(t, idle, "session with an open stream")
	closed := time.Now()
	_ = stream.Close()
	waitHTTP3SessionClosed(t, idle, 2*time.Second, "unused session")
	if elapsed := time.Since(closed); elapsed < client.IdleTimeout/2 {
		t.Fatalf("session closed %v after its last stream, before the idle period", elapsed)
	}
	if rtt := client.SmoothedRTT(); rtt != 0 {
		t.Fatalf("RTT %v with no session", rtt)
	}
	next, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	assertHTTP3Echo(t, next, "fresh session")
	if accepted.Load() != 2 || currentHTTP3Session(client) == idle {
		t.Fatalf("%d sessions after the idle one closed", accepted.Load())
	}
}

func TestHTTP3NewStreamKeepsSessionFromIdleClose(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, nil)
	client.IdleTimeout = 500 * time.Millisecond
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session := currentHTTP3Session(client)
	_ = first.Close()
	time.Sleep(300 * time.Millisecond)
	second, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	requireHTTP3SessionOpen(t, session, "session used again within the idle period")
	assertHTTP3Echo(t, second, "still the first session")
	_ = second.Close()
	time.Sleep(300 * time.Millisecond)
	requireHTTP3SessionOpen(t, session, "session idle for less than the period since its last stream")
	third, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	if accepted.Load() != 1 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
	if currentHTTP3Session(client) != session {
		t.Fatal("the session was replaced")
	}
}

func TestHTTP3SessionNobodyWaitsForIsClosedWhenIdle(t *testing.T) {
	client, _, _ := newHTTP3Fixture(t, nil)
	client.IdleTimeout = 150 * time.Millisecond
	dial := client.Dial
	started, proceed := make(chan struct{}), make(chan struct{})
	var dialed atomic.Pointer[quic.Conn]
	client.Dial = func(ctx context.Context) (*quic.Conn, error) {
		close(started)
		<-proceed
		conn, err := dial(ctx)
		dialed.Store(conn)
		return conn, err
	}
	abandoned, stop := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, _, err := client.Open(abandoned); result <- err }()
	<-started
	stop()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("abandoned open: %v", err)
	}
	close(proceed)
	deadline := time.Now().Add(2 * time.Second)
	for dialed.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("dial did not finish")
		}
		time.Sleep(5 * time.Millisecond)
	}
	waitHTTP3SessionClosed(t, dialed.Load(), 2*time.Second, "session no Open ever used")
}

// Streams parked in the pool hold references on the session; the pool must let
// them go on its own, or the session never goes idle.
func TestHTTP3ParkedPoolStreamsDoNotPinTheSession(t *testing.T) {
	client, accepted, _ := newHTTP3Fixture(t, nil)
	client.IdleTimeout = 100 * time.Millisecond
	pool := NewPool(func(ctx context.Context) (*Snell, error) {
		stream, exporter, err := client.Open(ctx)
		if err != nil {
			return nil, err
		}
		return StreamConnWithExporterIdentity(stream, []byte("psk"), Version4, exporter), nil
	})
	pool.idleAge = 100 * time.Millisecond
	defer pool.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pool.Warm(ctx, 3)
	session := currentHTTP3Session(client)
	if session == nil || accepted.Load() != 1 {
		t.Fatalf("pool did not share one session: %d", accepted.Load())
	}
	client.mu.Lock()
	parked := client.connections[session]
	client.mu.Unlock()
	if parked != 3 {
		t.Fatalf("%d parked streams hold the session", parked)
	}
	waitHTTP3SessionClosed(t, session, 3*time.Second, "session held only by parked pool streams")
	conn, err := pool.GetContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if accepted.Load() != 2 {
		t.Fatalf("opened %d QUIC sessions", accepted.Load())
	}
}

func TestHTTP3OpenTimeoutDefaultsToAtLeastOneSecond(t *testing.T) {
	client, _, _ := newHTTP3Fixture(t, nil)
	stream, _, err := client.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	session := currentHTTP3Session(client)
	if got := client.openTimeout(session); got != time.Second {
		t.Fatalf("default open timeout %v on a loopback session", got)
	}
	client.OpenTimeout = 3 * time.Second
	if got := client.openTimeout(session); got != 3*time.Second {
		t.Fatalf("configured open timeout %v", got)
	}
}

// An expiry that already fired when a stream took the session, or when a later
// idle period began, must find the session in use or newer and leave it alone.
func TestHTTP3StaleIdleExpiryLeavesSessionAlone(t *testing.T) {
	client, _, _ := newHTTP3Fixture(t, nil)
	client.IdleTimeout = time.Hour
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	first, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	session := currentHTTP3Session(client)
	client.mu.Lock()
	armed := client.idleGen
	client.mu.Unlock()
	_ = first.Close()
	client.mu.Lock()
	idle := client.idleGen
	client.mu.Unlock()
	if idle == armed {
		t.Fatal("closing the last stream did not start an idle period")
	}
	client.expire(session, armed)
	requireHTTP3SessionOpen(t, session, "session with a newer idle period")
	second, _, err := client.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	client.expire(session, idle)
	requireHTTP3SessionOpen(t, session, "session in use")

	_ = second.Close()
	client.mu.Lock()
	current := client.idleGen
	client.mu.Unlock()
	client.expire(session, current)
	waitHTTP3SessionClosed(t, session, time.Second, "session whose idle period ended")
	if currentHTTP3Session(client) != nil {
		t.Fatal("an expired session stayed current")
	}
}

func TestHTTP3ClosedClientStartsNoIdleTimer(t *testing.T) {
	client, _, _ := newHTTP3Fixture(t, nil)
	stream, _, err := client.Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = stream.Close()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.idle != nil {
		t.Fatal("a closed client armed an idle timer")
	}
}
