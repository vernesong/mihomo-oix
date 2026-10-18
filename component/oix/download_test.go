package oix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestManagedDirectBudgetIsFiveSeconds(t *testing.T) {
	for _, count := range []int{1, 2} {
		calls := 0
		clients := make([]*http.Client, count)
		for i := range clients {
			clients[i] = http.DefaultClient
		}
		_, _ = fetchConfigRoutes(context.Background(), clients, func(ctx context.Context) (*fetchedConfig, error) {
			deadline, _ := ctx.Deadline()
			if calls == 0 && (time.Until(deadline) > 5*time.Second || time.Until(deadline) < 4*time.Second) {
				t.Fatalf("unexpected direct deadline: %s", time.Until(deadline))
			}
			calls++
			return nil, errors.New("fixture connection failed")
		})
		if calls != count {
			t.Fatalf("calls=%d want=%d", calls, count)
		}
	}
}

func TestFullConfigDownloadValidatesBeforeFallback(t *testing.T) {
	for _, body := range []string{"proxies: []", "proxy-providers: {}", "<html>private</html>", "[invalid"} {
		t.Run(body, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				expectedRoute := "direct"
				if calls > 1 {
					expectedRoute = "proxy-fallback"
				}
				if r.Header.Get("X-oixCloud-Subscription-Route") != expectedRoute {
					t.Error("incorrect subscription route")
				}
				if r.UserAgent() != "clash" {
					t.Error("lost subscription user agent")
				}
				if calls == 1 {
					_, _ = w.Write([]byte(body))
				} else {
					_, _ = w.Write([]byte("proxies: []"))
				}
			}))
			defer server.Close()
			result, err := fetchConfigRoutes(context.Background(), []*http.Client{server.Client(), server.Client()}, func(ctx context.Context) (*fetchedConfig, error) {
				return fetchConfigURL(ctx, server.URL)
			})
			if err != nil || result == nil {
				t.Fatalf("download failed: %v", err)
			}
			valid := strings.HasPrefix(body, "prox")
			if (calls == 1) != valid {
				t.Fatalf("calls=%d valid=%v", calls, valid)
			}
		})
	}
}

func TestDownloadConfigCLIRejectsInvalidInputWithoutOutput(t *testing.T) {
	for _, input := range []string{`{}`, `{"url":"http://private.invalid/token"}`, `{"url":"https://private.invalid/token","proxy":"http://remote.invalid:8080"}`} {
		var output strings.Builder
		if CLI([]string{"download-config"}, strings.NewReader(input), &output) == exitOK || output.Len() != 0 {
			t.Fatal("invalid input accepted or exposed")
		}
	}
}

func TestDownloadConfigCapabilityCheckIsOffline(t *testing.T) {
	var output strings.Builder
	if CLI([]string{"download-config", "--check"}, nil, &output) != exitOK || output.Len() != 0 {
		t.Fatal("capability check failed or wrote output")
	}
	if CLI([]string{"download-config", "--unknown"}, nil, &output) == exitOK || output.Len() != 0 {
		t.Fatal("unknown argument accepted or wrote output")
	}
}
