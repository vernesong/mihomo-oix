package oix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func setupPanelTest(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())
	oldAPIDomains, oldSpareDomain := ApiDomains, SpareApiDomain
	ApiDomains, SpareApiDomain = server.URL, ""
	t.Cleanup(func() { ApiDomains, SpareApiDomain = oldAPIDomains, oldSpareDomain })
	setClientForTest(t, "oixclash")
	return server
}

func writePanelJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func runCLI(t *testing.T, command string, input any) (int, cliOutput) {
	t.Helper()
	request, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	status := CLI([]string{command}, bytes.NewReader(request), &stdout)
	var out cliOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("CLI output %q is not JSON: %v", stdout.String(), err)
	}
	return status, out
}

func TestLoginWithPasswordSignsInAsTheClient(t *testing.T) {
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != loginPath {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("X-oixCloud-Client"); got != "oixclash" {
			t.Errorf("X-oixCloud-Client = %q", got)
		}
		if got := r.Header.Get("User-Agent"); got != "oixClash" {
			t.Errorf("User-Agent = %q", got)
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("sign-in must not send a token")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.PostForm.Get("email") != "user@example.com" || r.PostForm.Get("passwd") != "p@ss word" || r.PostForm.Get("token_expire") != "365" {
			t.Errorf("form = %v", r.PostForm)
		}
		writePanelJSON(w, map[string]any{"ret": 200, "msg": "ok", "data": map[string]any{
			"token": " signed-in ", "plan": "Pro", "plan_rank": "20", "plan_time": "2026-12-31 00:00:00",
			"used": "1.5 GB", "traffic": "100 GB", "unused": "98.5 GB", "today_used": 0, "token_client": "oixclash",
		}})
	}))

	status, out := runCLI(t, "login", map[string]string{"email": " user@example.com ", "password": "p@ss word"})
	if status != ExitOK || out.Token != "signed-in" {
		t.Fatalf("login = %d %+v", status, out)
	}
	want := Account{Plan: "Pro", PlanTime: "2026-12-31 00:00:00", PlanRank: 20, Used: "1.5 GB", Traffic: "100 GB", Unused: "98.5 GB", TodayUsed: "0", TokenClient: "oixclash"}
	if out.Account == nil || *out.Account != want {
		t.Fatalf("account = %+v, want %+v", out.Account, want)
	}
}

func TestLoginReportsThePanelVerdict(t *testing.T) {
	cases := []struct {
		name       string
		body       map[string]any
		wantStatus int
		wantCode   string
		wantErr    error
		wantMsg    string
	}{
		{"wrong password", map[string]any{"ret": 403, "msg": "邮箱或者密码错误"}, ExitRejected, "rejected", ErrAuthFailed, "邮箱或者密码错误"},
		{"invalid input", map[string]any{"ret": "400", "msg": "邮箱格式不正确"}, ExitRejected, "rejected", nil, "邮箱格式不正确"},
		{"throttled", map[string]any{"ret": 429, "msg": "请稍后再试"}, ExitThrottled, "rate_limited", ErrRateLimited, "请稍后再试"},
		{"locked with retry", map[string]any{"ret": 403, "msg": "10 分钟后再试", "data": map[string]any{"retry_after": 600}}, ExitThrottled, "rate_limited", ErrRateLimited, "10 分钟后再试"},
		{"server failure", map[string]any{"ret": 500, "msg": "internal"}, ExitFailed, "server", ErrPanelServer, "the oixCloud panel failed to answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writePanelJSON(w, tc.body)
			}))
			_, _, err := LoginWithPassword(context.Background(), "user@example.com", "secret")
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("LoginWithPassword error = %v, want %v", err, tc.wantErr)
			}
			status, out := runCLI(t, "login", map[string]string{"email": "user@example.com", "password": "secret"})
			if status != tc.wantStatus || out.Code != tc.wantCode || out.Error != tc.wantMsg || out.Token != "" {
				t.Fatalf("CLI = %d %+v", status, out)
			}
		})
	}
}

func TestAccountRequestsTryTheSpareDomainOnlyWithoutAnAnswer(t *testing.T) {
	var spareRequests atomic.Int32
	spare := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		spareRequests.Add(1)
		writePanelJSON(w, map[string]any{"ret": 200, "data": map[string]any{"token": "from-spare"}})
	}))
	t.Cleanup(spare.Close)

	for _, primaryStatus := range []int{http.StatusBadGateway, http.StatusOK} {
		spareRequests.Store(0)
		setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if primaryStatus != http.StatusOK {
				w.WriteHeader(primaryStatus)
				return
			}
			writePanelJSON(w, map[string]any{"ret": 403, "msg": "denied"})
		}))
		// Both test servers trust the same httptest certificate.
		SpareApiDomain = spare.URL

		token, _, err := LoginWithPassword(context.Background(), "user@example.com", "secret")
		if primaryStatus == http.StatusOK {
			if err == nil || spareRequests.Load() != 0 {
				t.Fatalf("a JSON verdict must be final: token=%q err=%v spare=%d", token, err, spareRequests.Load())
			}
			continue
		}
		if err != nil || token != "from-spare" || spareRequests.Load() != 1 {
			t.Fatalf("HTTP %d: token=%q err=%v spare=%d", primaryStatus, token, err, spareRequests.Load())
		}
	}
}

func TestAccountTakesOverTokensOfOtherClients(t *testing.T) {
	cases := []struct {
		name        string
		tokenClient any
		rebind      map[string]any
		wantToken   string
		wantRebound bool
		wantRebinds int32
	}{
		{"other official client", "flclash", map[string]any{"ret": 200, "data": map[string]any{"token": "own", "token_client": "oixclash", "rebound": true}}, "own", true, 1},
		{"already ours", "oixclash", nil, "pasted", false, 0},
		{"website token", nil, nil, "pasted", false, 0},
		{"rebind refused", "flclash", map[string]any{"ret": 403, "msg": "不能转换"}, "pasted", false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rebinds atomic.Int32
			setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer pasted" {
					t.Errorf("%s Authorization = %q", r.URL.Path, got)
				}
				switch r.URL.Path {
				case informationPath:
					writePanelJSON(w, map[string]any{"ret": 200, "data": map[string]any{"plan": "Pro", "token_client": tc.tokenClient}})
				case rebindPath:
					rebinds.Add(1)
					writePanelJSON(w, tc.rebind)
				default:
					http.NotFound(w, r)
				}
			}))

			status, out := runCLI(t, "account", map[string]string{"token": " Bearer pasted "})
			if status != ExitOK || out.Token != tc.wantToken || out.Rebound != tc.wantRebound || rebinds.Load() != tc.wantRebinds {
				t.Fatalf("account = %d %+v, rebinds %d", status, out, rebinds.Load())
			}
			if out.Account == nil || out.Account.Plan != "Pro" {
				t.Fatalf("account info = %+v", out.Account)
			}
		})
	}
}

func TestAccountRejectsAnInvalidToken(t *testing.T) {
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writePanelJSON(w, map[string]any{"ret": 401, "msg": "登录已失效"})
	}))
	status, out := runCLI(t, "account", map[string]string{"token": "expired"})
	if status != ExitRejected || out.Code != "rejected" || out.Error != "登录已失效" || out.Token != "" {
		t.Fatalf("account = %d %+v", status, out)
	}
}

func TestCLIKeepsThePanelAddressOutOfErrors(t *testing.T) {
	server := setupPanelTest(t, http.NotFoundHandler())
	address := strings.TrimPrefix(server.URL, "https://")
	server.Close()

	status, out := runCLI(t, "account", map[string]string{"token": "token"})
	if status != ExitFailed || out.Code != "network" {
		t.Fatalf("account = %d %+v", status, out)
	}
	host := address[:strings.LastIndex(address, ":")]
	if strings.Contains(out.Error, address) || strings.Contains(out.Error, host) {
		t.Fatalf("error %q reveals the panel address", out.Error)
	}
}

func TestCLIValidatesTheRequest(t *testing.T) {
	cases := []struct {
		args  []string
		input string
	}{
		{[]string{}, `{}`},
		{[]string{"logout"}, `{}`},
		{[]string{"login"}, `not json`},
		{[]string{"login"}, `{"email":"user@example.com"}`},
		{[]string{"account"}, `{"token":"  "}`},
	}
	for _, tc := range cases {
		var stdout bytes.Buffer
		status := CLI(tc.args, strings.NewReader(tc.input), &stdout)
		var out cliOutput
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || status != ExitFailed || out.Code != "usage" {
			t.Fatalf("CLI(%v, %q) = %d %q", tc.args, tc.input, status, stdout.String())
		}
	}
}
