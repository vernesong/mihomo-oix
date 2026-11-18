package smux

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestWriteFramePayloadLifetime(t *testing.T) {
	for _, cause := range []string{"deadline", "close"} {
		t.Run(cause, func(t *testing.T) {
			s := &Session{shaper: make(chan writeRequest), die: make(chan struct{}), chSocketWriteError: make(chan struct{})}
			deadline := make(chan time.Time)
			payload := []byte("original frame")
			frame := newFrame(1, cmdPSH, 1)
			frame.data = payload
			done := make(chan error, 1)
			go func() { _, err := s.writeFrameInternal(frame, deadline, CLSDATA); done <- err }()
			request := <-s.shaper // queued, but the sender has not consumed the payload
			wantErr := error(ErrTimeout)
			if cause == "close" {
				close(s.die)
				wantErr = io.ErrClosedPipe
			} else {
				close(deadline)
			}
			if err := <-done; !errors.Is(err, wantErr) {
				t.Fatalf("write error = %v, want %v", err, wantErr)
			}
			// A caller may immediately reuse its buffer after Write returns.
			for i := range payload {
				payload[i] = 0
			}
			if !bytes.Equal(request.frame.data, []byte("original frame")) {
				t.Fatalf("queued payload changed after Write returned: %q", request.frame.data)
			}
		})
	}
}
