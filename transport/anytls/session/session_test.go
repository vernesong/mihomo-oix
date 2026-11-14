package session

import (
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"

	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/network"
)

func TestClientSessionKeepalive(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	session := NewClientSession(client, &factory, "")
	session.keepalive = 10 * time.Millisecond
	session.Run()
	defer session.Close()
	go session.OpenStream()

	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	header := make([]byte, headerOverHeadSize)
	for {
		if _, err := io.ReadFull(server, header); err != nil {
			t.Fatal(err)
		}
		if header[0] == cmdHeartRequest {
			return
		}
		if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
			t.Fatal(err)
		}
	}
}

const testKeepalive = 100 * time.Millisecond

// keepaliveSession runs a client session with one open stream, its peer's frames
// going to answer. A nil answer leaves the peer not reading at all.
func keepaliveSession(t *testing.T, keepalive time.Duration, answer func(server net.Conn, cmd byte)) (*Session, *Stream, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	session := NewClientSession(client, &factory, "")
	session.keepalive = keepalive
	session.Run()
	t.Cleanup(func() { _ = session.Close() })
	if answer != nil {
		go func() {
			header := make([]byte, headerOverHeadSize)
			for {
				if _, err := io.ReadFull(server, header); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, server, int64(binary.BigEndian.Uint16(header[5:]))); err != nil {
					return
				}
				answer(server, header[0])
			}
		}()
	}
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	return session, stream, server
}

func dataFrame(sid uint32, size int) []byte {
	frame := make([]byte, headerOverHeadSize+size)
	frame[0] = cmdPSH
	binary.BigEndian.PutUint32(frame[1:], sid)
	binary.BigEndian.PutUint16(frame[5:], uint16(size))
	return frame
}

func wantOpen(t *testing.T, session *Session, intervals int) {
	t.Helper()
	select {
	case <-session.die:
		t.Fatal("the session closed")
	case <-time.After(time.Duration(intervals) * testKeepalive):
	}
}

func TestKeepaliveClosesASilentSession(t *testing.T) {
	started := time.Now()
	session, _, _ := keepaliveSession(t, testKeepalive, func(net.Conn, byte) {})
	select {
	case <-session.die:
	case <-time.After(20 * testKeepalive):
		t.Fatal("a silent session stayed open")
	}
	if elapsed := time.Since(started); elapsed < 2*testKeepalive {
		t.Fatalf("closed after %s, before two intervals", elapsed)
	}
	if err := session.Close(); err != io.ErrClosedPipe {
		t.Fatalf("second Close = %v", err)
	}
}

func TestKeepaliveClosesTwoIntervalsAfterTheLastFrame(t *testing.T) {
	const keepalive = 200 * time.Millisecond
	var replied atomic.Int64
	started := time.Now()
	session, _, _ := keepaliveSession(t, keepalive, func(server net.Conn, cmd byte) {
		if cmd == cmdHeartRequest && replied.Load() == 0 {
			response := make([]byte, headerOverHeadSize)
			response[0] = cmdHeartResponse
			_, _ = server.Write(response)
			replied.Store(int64(time.Since(started)))
		}
	})
	select {
	case <-session.die:
	case <-time.After(10 * keepalive):
		t.Fatal("the session stayed open")
	}
	closed := time.Since(started)
	lastFrame := time.Duration(replied.Load())
	if lastFrame == 0 {
		t.Fatal("no heartbeat was answered")
	}
	if silent := closed - lastFrame; silent < 2*keepalive-keepalive/4 || silent > 2*keepalive+keepalive/2 {
		t.Fatalf("closed %s after the last frame, want %s", silent, 2*keepalive)
	}
}

func TestKeepaliveClosesASessionThatCannotWrite(t *testing.T) {
	session, _, _ := keepaliveSession(t, testKeepalive, nil)
	select {
	case <-session.die:
	case <-time.After(20 * testKeepalive):
		t.Fatal("a session with a blocked write stayed open")
	}
}

func TestKeepaliveAcceptsHeartResponses(t *testing.T) {
	session, _, _ := keepaliveSession(t, testKeepalive, func(server net.Conn, cmd byte) {
		if cmd == cmdHeartRequest {
			response := make([]byte, headerOverHeadSize)
			response[0] = cmdHeartResponse
			_, _ = server.Write(response)
		}
	})
	wantOpen(t, session, 8)
}

func TestKeepaliveAcceptsDataWithoutHeartResponses(t *testing.T) {
	session, _, server := keepaliveSession(t, testKeepalive, func(net.Conn, byte) {})
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(testKeepalive / 2)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if _, err := server.Write(dataFrame(99, 32)); err != nil {
					return
				}
			}
		}
	}()
	wantOpen(t, session, 8)
}

// A reader that has stopped holds up the receive loop; that says nothing about
// the peer.
func TestKeepaliveWaitsForASlowReader(t *testing.T) {
	session, stream, server := keepaliveSession(t, testKeepalive, func(net.Conn, byte) {})
	go func() { _, _ = server.Write(dataFrame(stream.id, 32)) }()
	wantOpen(t, session, 8)

	buffer := make([]byte, 32)
	if _, err := io.ReadFull(stream, buffer); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.die:
	case <-time.After(20 * testKeepalive):
		t.Fatal("the session stayed open after the reader caught up and the peer stayed silent")
	}
}

func TestSessionWithoutKeepaliveStaysQuiet(t *testing.T) {
	var hearts atomic.Int32
	session, _, _ := keepaliveSession(t, 0, func(_ net.Conn, cmd byte) {
		if cmd == cmdHeartRequest {
			hearts.Add(1)
		}
	})
	wantOpen(t, session, 8)
	if hearts.Load() != 0 {
		t.Fatalf("%d heartbeats", hearts.Load())
	}
}

type closeWriteRecorder struct {
	net.Conn
	closeWrites atomic.Int32
}

func (c *closeWriteRecorder) CloseWrite() error {
	c.closeWrites.Add(1)
	return nil
}

// A relay half-closes through common.Cast, which follows NetConn. Reaching the
// session's TLS would end every other stream with it.
func TestStreamHalfCloseStaysOnTheStream(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go io.Copy(io.Discard, server)
	conn := &closeWriteRecorder{Conn: client}
	var factory atomic.Pointer[padding.PaddingFactory]
	padding.UpdatePaddingScheme(padding.DefaultPaddingScheme, &factory)
	session := NewClientSession(conn, &factory, "")
	session.Run()
	defer session.Close()
	stream, err := session.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	writer, ok := common.Cast[network.WriteCloser](stream)
	if !ok {
		t.Fatal("stream has no half-close")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if got := conn.closeWrites.Load(); got != 0 {
		t.Fatalf("half-close reached the session's transport %d times", got)
	}
	if session.IsClosed() {
		t.Fatal("half-close ended the session")
	}
}
