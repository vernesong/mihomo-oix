package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDialContextDialerSelection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(host)
	original := &net.Dialer{Timeout: time.Second, KeepAlive: 17 * time.Second}
	keepAlive := original.KeepAlive
	config := original.KeepAliveConfig
	for _, tc := range []struct {
		name   string
		dialer NetDialer
	}{
		{"default", nil},
		{"net.Dialer copy", original},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialContext(ctx, "tcp4", address, port, option{netDialer: tc.dialer})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if conn.RemoteAddr().String() != listener.Addr().String() {
				t.Fatalf("wrong destination: %s", conn.RemoteAddr())
			}
		})
	}
	if original.KeepAlive != keepAlive || original.KeepAliveConfig != config {
		t.Fatal("caller-owned dialer was mutated")
	}
	t.Run("custom", func(t *testing.T) {
		wantErr := errors.New("custom dialer")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		custom := NetDialerFunc(func(gotCtx context.Context, network, addr string) (net.Conn, error) {
			if gotCtx != ctx || network != "tcp4" || addr != listener.Addr().String() {
				t.Errorf("custom dialer arguments changed: %s %s", network, addr)
			}
			return nil, wantErr
		})
		_, err := dialContext(ctx, "tcp4", address, port, option{netDialer: custom})
		if !errors.Is(err, wantErr) {
			t.Fatalf("custom dialer error = %v", err)
		}
	})
}

func TestTFODelayedWriteAfterDialContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := dialTFO(ctx, net.Dialer{}, "tcp", "127.0.0.1:1")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	tfo := conn.(*tfoConn)
	tfo.dialFn = func(ctx context.Context, earlyData []byte) (net.Conn, error) {
		if ctx.Err() != nil || string(earlyData) != "first write" {
			t.Fatalf("delayed dial lost its context or early data: %v %q", ctx.Err(), earlyData)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("delayed dial must retain its independent timeout")
		}
		return client, nil
	}
	if n, err := conn.Write([]byte("first write")); err != nil || n != len("first write") {
		t.Fatalf("delayed Write = %d, %v", n, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(tfo.ctx.Err(), context.Canceled) {
		t.Fatal("Close did not cancel the delayed dial context")
	}
}
