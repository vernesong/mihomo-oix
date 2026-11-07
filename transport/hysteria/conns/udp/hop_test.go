package udp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"
)

type loopbackHopDialer struct{ server net.Addr }

func (d loopbackHopDialer) Context() context.Context            { return context.Background() }
func (d loopbackHopDialer) RemoteAddr(string) (net.Addr, error) { return d.server, nil }
func (d loopbackHopDialer) ListenPacket(net.Addr) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func TestHopPacketRoundTripAndClose(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	dialer := loopbackHopDialer{server.LocalAddr()}
	port := strconv.Itoa(server.LocalAddr().(*net.UDPAddr).Port)
	conn, err := NewObfsUDPHopClientPacketConn(server.LocalAddr().String(), port, time.Hour, nil, dialer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var hop *ObfsUDPHopClientPacketConn
	switch c := conn.(type) {
	case *ObfsUDPHopClientPacketConn:
		hop = c
	case *ObfsUDPHopClientPacketConnWithSyscall:
		hop = c.ObfsUDPHopClientPacketConn
	default:
		t.Fatalf("unexpected connection %T", conn)
	}

	read := func(size int, want []byte) {
		t.Helper()
		type result struct {
			data []byte
			addr net.Addr
			err  error
		}
		done := make(chan result, 1)
		go func() {
			data := make([]byte, size)
			n, addr, err := conn.ReadFrom(data)
			done <- result{data[:n], addr, err}
		}()
		select {
		case got := <-done:
			if got.err != nil || !bytes.Equal(got.data, want) || got.addr.String() != server.LocalAddr().String() {
				t.Fatalf("ReadFrom: len=%d addr=%v err=%v, want len=%d", len(got.data), got.addr, got.err, len(want))
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ReadFrom blocked")
		}
	}
	for _, size := range []int{1, 4096, 8192} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if n, err := conn.WriteTo(payload, server.LocalAddr()); err != nil || n != size {
			t.Fatalf("WriteTo = %d, %v", n, err)
		}
		buf := make([]byte, udpBufferSize)
		n, from, err := server.ReadFrom(buf)
		if err != nil || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("server received %d bytes: %v", n, err)
		}
		if _, err := server.WriteTo(buf[:n], from); err != nil {
			t.Fatal(err)
		}
		read(size, payload)
	}
	oldAddr := conn.LocalAddr()
	hop.hop(dialer, server.LocalAddr())
	for _, addr := range []net.Addr{oldAddr, conn.LocalAddr()} {
		if _, err := server.WriteTo([]byte("truncate"), addr); err != nil {
			t.Fatal(err)
		}
		read(3, []byte("tru"))
	}
	done := make(chan error, 1)
	go func() { _, _, err := conn.ReadFrom(make([]byte, 1)); done <- err }()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked read after Close = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock ReadFrom")
	}
}
