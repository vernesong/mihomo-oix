package httpmask

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

func TestHTTPTransportRetryClassification(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"interrupted syscall", syscall.EINTR, true},
		{"process descriptor limit", syscall.EMFILE, true},
		{"system descriptor limit", syscall.ENFILE, true},
		{"would block", syscall.EAGAIN, true},
		{"timeout", os.ErrDeadlineExceeded, true},
		{"temporary DNS failure", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, true},
		{"DNS timeout", &net.DNSError{Err: "timeout", IsTimeout: true}, true},
		{"DNS name not found", &net.DNSError{Err: "no such host", IsNotFound: true}, false},
		{"connection reset", syscall.ECONNRESET, true},
		{"EOF", io.EOF, true},
		{"overloaded server", &httpStatusError{code: 503}, true},
		{"unauthorized", &httpStatusError{code: 401}, false},
		{"canceled", context.Canceled, false},
		{"deadline exceeded", context.DeadlineExceeded, false},
		{"canceled transient failure", errors.Join(context.Canceled, syscall.EINTR), false},
		{"permanent protocol error", errors.New("malformed response"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// HTTP errors wrap network operations and syscall/DNS errors. Check both
			// the underlying error and that transport shape, including cancellation.
			wrapped := &url.Error{Op: "Post", URL: "http://example.invalid", Err: &net.OpError{
				Op: "write", Net: "tcp", Err: os.NewSyscallError("write", tc.err),
			}}
			for _, err := range []error{tc.err, wrapped} {
				if got := isRetryableHTTPTransportError(err); got != tc.retry {
					t.Errorf("retry(%T) = %v, want %v", err, got, tc.retry)
				}
			}
		})
	}
}

func TestPersistentRetryStopsAfterTransientFailures(t *testing.T) {
	permanent := errors.New("permanent protocol error")
	failures := []error{
		&net.DNSError{Err: "server misbehaving", IsTemporary: true},
		&net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.EINTR)},
		permanent,
	}
	attempts := 0
	err := retryPersistent(make(chan struct{}), nil, 0, 0, func() error {
		if attempts == len(failures) {
			t.Fatal("retried a permanent failure")
		}
		err := failures[attempts]
		attempts++
		return err
	})
	if err != permanent || attempts != len(failures) {
		t.Fatalf("retry result = (%v, %d attempts), want permanent failure after %d attempts", err, attempts, len(failures))
	}
}
