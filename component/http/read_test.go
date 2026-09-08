package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	C "github.com/metacubex/mihomo/constant"
)

type redirectDialer struct {
	C.Dialer
	address string
}

func (d redirectDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func TestGetRacesAuthenticatedReadsAndValidatesCompleteBodies(t *testing.T) {
	for _, invalid := range []string{"html", "truncated", "oversize"} {
		t.Run(invalid, func(t *testing.T) {
			started := make(chan struct{}, 2)
			both := make(chan struct{})
			go func() { <-started; <-started; close(both) }()
			handler := func(bad bool) stdhttp.HandlerFunc {
				return func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
					user, password, ok := r.BasicAuth()
					if !ok || user != "user" || password != "secret" || r.URL.Query().Get("token") != "private" {
						t.Error("credentials lost")
					}
					started <- struct{}{}
					select {
					case <-both:
					case <-r.Context().Done():
						return
					}
					if !bad {
						time.Sleep(20 * time.Millisecond)
						_, _ = io.WriteString(w, "valid")
						return
					}
					switch invalid {
					case "html":
						_, _ = io.WriteString(w, "<html>challenge</html>")
					case "oversize":
						_, _ = io.WriteString(w, strings.Repeat("x", 65))
					case "truncated":
						w.Header().Set("Content-Length", "20")
						_, _ = io.WriteString(w, "valid")
					}
				}
			}
			configured := httptest.NewServer(handler(true))
			defer configured.Close()
			direct := httptest.NewServer(handler(false))
			defer direct.Close()
			address := strings.Replace(direct.URL, "http://", "http://user:secret@", 1) + "/?token=private"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, data, err := Get(ctx, address, nil, 64, func(_ *http.Response, data []byte) error {
				if string(data) != "valid" {
					return errors.New("invalid content")
				}
				return nil
			}, WithDialer(redirectDialer{address: configured.Listener.Addr().String()}))
			if err != nil || string(data) != "valid" {
				t.Fatalf("data=%q error=%v", data, err)
			}
		})
	}
}

func TestGetAuthenticationCancelsPendingRead(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			started, canceled := make(chan struct{}), make(chan struct{})
			direct := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				close(started)
				w.WriteHeader(200)
				w.(stdhttp.Flusher).Flush()
				<-r.Context().Done()
				close(canceled)
			}))
			defer direct.Close()
			configured := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				select {
				case <-started:
				case <-r.Context().Done():
					return
				}
				w.WriteHeader(status)
			}))
			defer configured.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, _, err := Get(ctx, direct.URL, nil, 64, nil, WithDialer(redirectDialer{address: configured.Listener.Addr().String()}))
			if !IsAuthenticationError(err) {
				t.Fatalf("error=%v", err)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("loser body was not canceled")
			}
		})
	}
}

func TestRaceReadsDeadlineAndCancellationDuringValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := RaceReads(ctx, []func(context.Context) (int, error){func(ctx context.Context) (int, error) { <-ctx.Done(); return 0, ctx.Err() }}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, err = RaceReads(ctx, []func(context.Context) (int, error){func(context.Context) (int, error) { return 1, nil }}, func(int) error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("validation published canceled result: %v", err)
	}
}

func TestReadErrorsRedactCredentials(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := Get(ctx, "http://user:secret@127.0.0.1:1/?token=private", nil, 64, nil)
	if err == nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
		t.Fatalf("error=%v", err)
	}
}

func TestGetStripsCrossOriginCredentials(t *testing.T) {
	destination := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		for _, key := range []string{"Authorization", "Proxy-Authorization", "Cookie", "Referer"} {
			if r.Header.Get(key) != "" {
				t.Errorf("forwarded %s", key)
			}
		}
		if r.URL.Path != "/final" {
			stdhttp.Redirect(w, r, "/final", 302)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer destination.Close()
	origin := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Header.Get("Authorization") != "Bearer private" {
			t.Error("origin lost authorization")
		}
		stdhttp.Redirect(w, r, destination.URL, 302)
	}))
	defer origin.Close()
	_, _, err := Get(context.Background(), origin.URL+"/?token=private", map[string][]string{
		"Authorization": {"Bearer private"}, "Proxy-Authorization": {"secret"}, "Cookie": {"private"},
	}, 64, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPublicRead403OnlyStopsCredentialedRequests(t *testing.T) {
	for _, credential := range []string{"none", "Authorization", "Cookie", "Proxy-Authorization", "userinfo", "query"} {
		t.Run(credential, func(t *testing.T) {
			started := make(chan struct{})
			direct := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				close(started)
				timer := time.NewTimer(30 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
					_, _ = io.WriteString(w, "valid")
				case <-r.Context().Done():
				}
			}))
			defer direct.Close()
			configured := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				select {
				case <-started:
					w.WriteHeader(403)
				case <-r.Context().Done():
				}
			}))
			defer configured.Close()
			address := direct.URL
			headers := map[string][]string{}
			switch credential {
			case "userinfo":
				address = strings.Replace(address, "http://", "http://user:secret@", 1)
			case "query":
				address += "/?token=secret"
			case "none":
			default:
				headers[credential] = []string{"secret"}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, data, err := Get(ctx, address, headers, 64, nil, WithPublicRead(), WithDialer(redirectDialer{address: configured.Listener.Addr().String()}))
			if credential == "none" {
				if err != nil || string(data) != "valid" {
					t.Fatalf("data=%q error=%v", data, err)
				}
			} else if !IsAuthenticationError(err) {
				t.Fatalf("credentialed 403 was not authoritative: %v", err)
			}
		})
	}
}

func TestRaceReadsDoesNotStartCanceledOperation(t *testing.T) {
	cause := errors.New("account generation replaced")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	started := make(chan struct{}, 1)
	_, err := RaceReads(ctx, []func(context.Context) (int, error){func(context.Context) (int, error) {
		started <- struct{}{}
		return 1, nil
	}}, nil)
	if !errors.Is(err, cause) {
		t.Fatalf("cancellation cause lost: %v", err)
	}
	select {
	case <-started:
		t.Fatal("canceled operation started a read")
	case <-time.After(20 * time.Millisecond):
	}
}
