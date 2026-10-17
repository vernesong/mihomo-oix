package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/age"
)

func TestFetchFromClientsUsesDirectBeforeProxy(t *testing.T) {
	for _, directResult := range []string{"valid", "invalid", "network", "timeout", "spare"} {
		t.Run(directResult, func(t *testing.T) {
			publicKey := setupSignedFetchTest(t)
			encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
			if err != nil {
				t.Fatal(err)
			}
			validConfig := base64.StdEncoding.EncodeToString(encrypted)
			var directCalls, proxyCalls atomic.Int32
			var directContext context.Context
			var mu sync.Mutex
			client := func(proxy bool) *http.Client {
				return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if req.Header.Get("Authorization") != "Bearer private-token" {
						t.Error("lost authorization")
					}
					config := validConfig
					if proxy {
						proxyCalls.Add(1)
						mu.Lock()
						defer mu.Unlock()
						if directCalls.Load() == 0 || directContext.Err() == nil {
							t.Error("proxy started before direct stage finished")
						}
					} else {
						directCalls.Add(1)
						mu.Lock()
						directContext = req.Context()
						mu.Unlock()
						switch directResult {
						case "invalid":
							config = base64.StdEncoding.EncodeToString([]byte(A.FileHeader + "invalid encrypted content"))
						case "network":
							return nil, errors.New("fixture network failure")
						case "timeout":
							<-req.Context().Done()
							return nil, req.Context().Err()
						case "spare":
							if req.URL.Host == "oix.test" {
								return nil, errors.New("primary unavailable")
							}
						}
					}
					data, _ := json.Marshal(apiResponse{Ret: 200, Config: config})
					header := make(http.Header)
					header.Set("X-Flclash-Response-Signature", sign(req.Header.Get("X-Flclash-Timestamp")+"."+config))
					return &http.Response{StatusCode: 200, Header: header, Body: io.NopCloser(strings.NewReader(string(data)))}, nil
				})}
			}
			urls := []string{"https://oix.test"}
			if directResult == "spare" {
				urls = append(urls, "https://spare.test")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			config, err := fetchFromClients(ctx, "private-token", urls, []*http.Client{client(false), client(true)})
			if err != nil || config == nil || string(config.data) != string(encrypted) {
				t.Fatalf("config=%v error=%v", config, err)
			}
			wantProxy := int32(1)
			if directResult == "valid" || directResult == "spare" {
				wantProxy = 0
			}
			wantDirect := int32(1)
			if directResult == "spare" {
				wantDirect = 2
			}
			if directCalls.Load() != wantDirect {
				t.Fatalf("direct calls=%d want=%d", directCalls.Load(), wantDirect)
			}
			if proxyCalls.Load() != wantProxy {
				t.Fatalf("proxy calls=%d want=%d", proxyCalls.Load(), wantProxy)
			}
		})
	}
}

func TestFetchFromClientsAuthenticationDoesNotTryProxy(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			setupSignedFetchTest(t)
			rejected := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
			})}
			proxy := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				t.Error("authentication rejection retried through proxy")
				return nil, errors.New("unexpected proxy")
			})}
			_, err := fetchFromClients(context.Background(), "token", []string{"https://oix.test"}, []*http.Client{rejected, proxy})
			if !IsAuthError(err) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestFetchFromClientsCancellationDoesNotTryProxy(t *testing.T) {
	setupSignedFetchTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		cancel()
		return nil, req.Context().Err()
	})}
	_, err := fetchFromClients(ctx, "token", []string{"https://oix.test"}, []*http.Client{client, client})
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("calls=%d error=%v", calls.Load(), err)
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
	entered := make(chan struct{}, 2)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := fetchFromClients(ctx, "token", []string{"https://oix.test"}, []*http.Client{client, client})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("route did not start before the shared deadline")
		}
	}
}
