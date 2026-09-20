package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/age"
)

func TestFetchFromClientsWaitsForValidEncryptedBody(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	validConfig := base64.StdEncoding.EncodeToString(encrypted)
	started := make(chan struct{}, 2)
	both := make(chan struct{})
	go func() { <-started; <-started; close(both) }()
	client := func(valid bool) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("Authorization") != "Bearer private-token" {
				t.Error("lost authorization")
			}
			if req.URL.Path == "/api/v1/information" {
				started <- struct{}{}
				select {
				case <-both:
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
				return &http.Response{StatusCode: 404, Header: make(http.Header), Body: http.NoBody}, nil
			}
			config := base64.StdEncoding.EncodeToString([]byte(A.FileHeader + "invalid encrypted content"))
			if valid {
				config = validConfig
				time.Sleep(20 * time.Millisecond)
			}
			data, _ := json.Marshal(apiResponse{Ret: 200, Config: config})
			header := make(http.Header)
			header.Set("X-Flclash-Response-Signature", sign(req.Header.Get("X-Flclash-Timestamp")+"."+config))
			return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
		})}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	config, err := fetchFromClients(ctx, "private-token", "https://oix.test", t.TempDir(), []*http.Client{client(false), client(true)})
	if err != nil || config == nil || string(config.data) != string(encrypted) {
		t.Fatalf("config=%v error=%v", config, err)
	}
}

func TestFetchFromClientsAuthenticationCancelsOtherAccountRead(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			setupSignedFetchTest(t)
			started, canceled := make(chan struct{}), make(chan struct{})
			pending := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				close(started)
				<-req.Context().Done()
				close(canceled)
				return nil, req.Context().Err()
			})}
			rejected := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				select {
				case <-started:
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
			})}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := fetchFromClients(ctx, "token", "https://oix.test", t.TempDir(), []*http.Client{pending, rejected})
			if !IsAuthError(err) {
				t.Fatalf("error=%v", err)
			}
			select {
			case <-canceled:
			case <-time.After(time.Second):
				t.Fatal("other account read not canceled")
			}
		})
	}
}

func Test_oixWriteIsNeverReplayed(t *testing.T) {
	var calls atomic.Int32
	setoixHTTPClientForTest(t, &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
	})})
	req, _ := http.NewRequest(http.MethodPost, "https://oix.test/api/v1/logout", strings.NewReader("payload"))
	resp, err := oixHTTPDo(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if calls.Load() != 1 || resp.StatusCode != 500 {
		t.Fatalf("calls=%d status=%d", calls.Load(), resp.StatusCode)
	}
}

func TestFetchFromClientsSharesDeadline(t *testing.T) {
	setupSignedFetchTest(t)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := fetchFromClients(ctx, "token", "https://oix.test", t.TempDir(), []*http.Client{client, client})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
}
