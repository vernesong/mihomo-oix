package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	P "github.com/metacubex/mihomo/adapter/provider"
	A "github.com/metacubex/mihomo/component/age"
	R "github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	D "github.com/miekg/dns"
)

type staticResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *staticResolver) LookupIP(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	return r.addresses, r.err
}

func (r *staticResolver) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *staticResolver) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupIP(ctx, host)
}

func (r *staticResolver) ResolveECH(context.Context, string) ([]byte, error) { return nil, r.err }
func (r *staticResolver) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, r.err
}
func (r *staticResolver) Invalid() bool    { return true }
func (r *staticResolver) ClearCache()      {}
func (r *staticResolver) ResetConnection() {}

func intPointer(value int) *int {
	return &value
}

func setOixHTTPClientForTest(t *testing.T, client *http.Client) {
	previous := oixHTTPClient
	oixHTTPClient = client
	t.Cleanup(func() {
		oixHTTPClient = previous
	})
}

func TestOixHTTPClientUsesDirectResolver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	proxyResolver := &staticResolver{err: errors.New("proxy DNS unavailable")}
	directResolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	oldProxyResolver := R.ProxyServerHostResolver
	oldDirectResolver := R.DirectHostResolver
	R.ProxyServerHostResolver = proxyResolver
	R.DirectHostResolver = directResolver
	t.Cleanup(func() {
		R.ProxyServerHostResolver = oldProxyResolver
		R.DirectHostResolver = oldDirectResolver
	})

	client := newOixHTTPClient()
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get("http://oix.test:" + port)
	if err != nil {
		t.Fatalf("direct request failed: %v", err)
	}
	_ = response.Body.Close()
	if proxyResolver.calls != 0 || directResolver.calls != 1 {
		t.Fatalf("resolver calls: proxy=%d direct=%d", proxyResolver.calls, directResolver.calls)
	}
}

func TestPlanDefaultParams(t *testing.T) {
	tests := []struct {
		name string
		plan planIdentity
		want string
	}{
		{name: "no plan", plan: planIdentity{Code: "no_plan", Rank: intPointer(0)}, want: ""},
		{name: "iron", plan: planIdentity{Code: "iron", Rank: intPointer(10)}, want: ""},
		{name: "alu", plan: planIdentity{Code: "alu", Rank: intPointer(20)}, want: "&lv=2"},
		{name: "bronze", plan: planIdentity{Code: "bronze", Rank: intPointer(30)}, want: "&type=love"},
		{name: "silver", plan: planIdentity{Code: "silver", Rank: intPointer(40)}, want: "&type=love"},
		{name: "gold", plan: planIdentity{Code: "gold", Rank: intPointer(50)}, want: "&type=love"},
		{name: "stable rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(30)}, want: "&type=love"},
		{name: "explicit zero rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(0)}, want: ""},
		{name: "code fallback iron", plan: planIdentity{Code: "iron"}, want: ""},
		{name: "code fallback alu", plan: planIdentity{Code: "alu"}, want: "&lv=2"},
		{name: "code fallback silver", plan: planIdentity{Code: "silver"}, want: "&type=love"},
		{name: "code fallback gold", plan: planIdentity{Code: "gold"}, want: "&type=love"},
		{name: "legacy no plan", plan: planIdentity{Name: "no plan"}, want: ""},
		{name: "legacy iron", plan: planIdentity{Name: "Pass Iron"}, want: ""},
		{name: "legacy alu", plan: planIdentity{Name: "Pass Alu"}, want: "&lv=2"},
		{name: "legacy bronze", plan: planIdentity{Name: "Pass Bronze"}, want: "&lv=2"},
		{name: "legacy silver", plan: planIdentity{Name: "Pass Silver"}, want: "&type=love"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := defaultParamsForPlan(test.plan).encode(); got != test.want {
				t.Fatalf("defaultParamsForPlan(%+v) = %q, want %q", test.plan, got, test.want)
			}
		})
	}
}

func TestPlanIdentityFromResponseRejectsMissingData(t *testing.T) {
	_, err := planIdentityFromResponse(informationResponse{Ret: http.StatusOK})
	if err == nil {
		t.Fatal("expected missing information data to be rejected")
	}
}

func TestFetchFromFallsBackWhenPlanIdentityUnavailable(t *testing.T) {
	t.Setenv("OIX_PARAMS", "")
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	if err := SetParams(homeDir, "&lv=1&tfo=false&area=hk"); err != nil {
		t.Fatal(err)
	}

	oldAppSecret := AppSecret
	oldSecretKey := ageSecretKey
	oldPublicKey := agePublicKey
	AppSecret = "test-secret"
	ageSecretKey = secretKey
	agePublicKey = publicKey
	t.Cleanup(func() {
		AppSecret = oldAppSecret
		ageSecretKey = oldSecretKey
		agePublicKey = oldPublicKey
	})

	managedCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/information":
			http.NotFound(w, r)
		case "/api/v1/managed/flclash/direct":
			managedCalls++
			if got := r.URL.Query().Get("lv"); got != "1" {
				t.Errorf("lv = %q, want 1", got)
			}
			if got := r.URL.Query().Get("tfo"); got != "false" {
				t.Errorf("tfo = %q, want false", got)
			}
			if got := r.URL.Query().Get("area"); got != "hk" {
				t.Errorf("area = %q, want hk", got)
			}
			config := base64.StdEncoding.EncodeToString([]byte("proxies: []"))
			timestamp := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
			_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	setOixHTTPClientForTest(t, server.Client())

	result, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
	if err != nil {
		t.Fatalf("fetchFrom() error = %v", err)
	}
	if managedCalls != 1 {
		t.Fatalf("managed endpoint calls = %d, want 1", managedCalls)
	}
	plaintext, err := A.DecryptBytes(result.Config, secretKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(plaintext)) != "proxies: []" {
		t.Fatalf("provider = %q", plaintext)
	}
}

func TestFetchFromFallsBackWhenAccountAuthenticationUnavailable(t *testing.T) {
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	homeDir := t.TempDir()
	oldHomeDir := C.Path.HomeDir()
	C.SetHomeDir(homeDir)
	oldAppSecret := AppSecret
	oldSecretKey := ageSecretKey
	oldPublicKey := agePublicKey
	AppSecret = "test-secret"
	ageSecretKey = secretKey
	agePublicKey = publicKey
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
		AppSecret = oldAppSecret
		ageSecretKey = oldSecretKey
		agePublicKey = oldPublicKey
	})
	providerPayload, err := A.EncryptBytes([]byte("proxies:\n  - name: simulated-node\n    type: direct\n"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := base64.StdEncoding.EncodeToString(providerPayload)

	managedCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		managedCalls++
		if got := r.Header.Get("X-Flclash-Age-Pubkey"); got != publicKey {
			t.Errorf("age public key = %q, want generated key", got)
		}
		timestamp := r.Header.Get("X-Flclash-Timestamp")
		w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
	}))
	t.Cleanup(server.Close)

	setOixHTTPClientForTest(t, server.Client())

	result, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
	if err != nil {
		t.Fatalf("fetchFrom() error = %v", err)
	}
	if managedCalls != 1 {
		t.Fatalf("managed endpoint calls = %d, want 1", managedCalls)
	}
	if !saveResult(defaultProviderDir, homeDir, result) {
		t.Fatal("saveResult() failed")
	}
	provider, err := P.ParseProxyProvider("oixCloud", map[string]any{
		"type":           "file",
		"path":           filepath.Join(homeDir, defaultProviderDir, ProviderFile()),
		"age-secret-key": secretKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Update(); err != nil {
		t.Fatal(err)
	}
	if closer, ok := provider.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	if provider.Count() != 1 || provider.Proxies()[0].Name() != "simulated-node" {
		t.Fatalf("parsed proxies = %v, want simulated-node", provider.Proxies())
	}
}

func TestFetchFromRejectsManagedAuthenticationFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/information":
			_ = json.NewEncoder(w).Encode(informationResponse{
				Ret:  http.StatusOK,
				Data: &informationData{PlanCode: "iron"},
			})
		case "/api/v1/managed/flclash/direct":
			_ = json.NewEncoder(w).Encode(apiResponse{
				Ret: http.StatusUnauthorized,
				Msg: "denied",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	setOixHTTPClientForTest(t, server.Client())

	_, err := fetchFrom(context.Background(), "invalid-token", server.URL, t.TempDir())
	if !IsAuthError(err) {
		t.Fatalf("fetchFrom() error = %v, want authentication failure", err)
	}
}

func TestPeriodicLifecycleConcurrent(t *testing.T) {
	oldDir, oldHomeDir := providerPaths()
	t.Cleanup(func() {
		StopPeriodicUpdate()
		SetProviderPaths(oldDir, oldHomeDir)
	})

	var waitGroup sync.WaitGroup
	for index := 0; index < 20; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			StartPeriodicUpdate("providers", t.TempDir())
			StopPeriodicUpdate()
		}()
	}
	waitGroup.Wait()
}

func TestSaveResultUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	homeDir := t.TempDir()
	oldProviderName := oixProviderName
	oixProviderName = "test-provider"
	t.Cleanup(func() {
		oixProviderName = oldProviderName
	})
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	oldSecretKey := ageSecretKey
	ageSecretKey = secretKey
	t.Cleanup(func() {
		ageSecretKey = oldSecretKey
	})

	if !saveResult("providers", homeDir, &Result{Provider: raw}) {
		t.Fatal("saveResult failed")
	}
	info, err := os.Stat(filepath.Join(homeDir, "providers", "test-provider"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o600); got != want {
		t.Fatalf("provider permissions = %o, want %o", got, want)
	}
}

func TestSaveResultRejectsUnencryptedProvider(t *testing.T) {
	homeDir := t.TempDir()
	oldProviderName := oixProviderName
	oixProviderName = "test-provider"
	t.Cleanup(func() {
		oixProviderName = oldProviderName
	})

	if saveResult("providers", homeDir, &Result{Provider: []byte("proxies: []")}) {
		t.Fatal("saveResult accepted an unencrypted provider")
	}
	if _, err := os.Stat(filepath.Join(homeDir, "providers", "test-provider")); !os.IsNotExist(err) {
		t.Fatalf("unencrypted provider was written: %v", err)
	}
}

func TestSaveResultRejectsInvalidAgeProvider(t *testing.T) {
	homeDir := t.TempDir()
	oldProviderName := oixProviderName
	oldSecretKey := ageSecretKey
	oixProviderName = "test-provider"
	ageSecretKey, _, _ = A.GenX25519KeyPair()
	t.Cleanup(func() {
		oixProviderName = oldProviderName
		ageSecretKey = oldSecretKey
	})

	raw := []byte("-----BEGIN AGE ENCRYPTED FILE-----\nproxies: []")
	if saveResult("providers", homeDir, &Result{Provider: raw}) {
		t.Fatal("saveResult accepted an invalid Age provider")
	}
	if _, err := os.Stat(filepath.Join(homeDir, "providers", "test-provider")); !os.IsNotExist(err) {
		t.Fatalf("invalid Age provider was written: %v", err)
	}
}
