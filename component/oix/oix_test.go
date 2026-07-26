package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	P "github.com/metacubex/mihomo/adapter/provider"
	A "github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	R "github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	D "github.com/miekg/dns"
)

type staticResolver struct {
	addresses           []netip.Addr
	err                 error
	calls               int
	delay               time.Duration
	waitForCancellation bool
}

func (r *staticResolver) LookupIP(ctx context.Context, _ string) ([]netip.Addr, error) {
	r.calls++
	if r.delay > 0 {
		timer := time.NewTimer(r.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if r.waitForCancellation {
		<-ctx.Done()
		return nil, ctx.Err()
	}
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

func TestProviderDirectory(t *testing.T) {
	homeDir := t.TempDir()
	preferredDir := filepath.Join(homeDir, "preferred")
	sharedDir := filepath.Join(homeDir, "shared")
	tests := []struct {
		name          string
		preferredPath string
		providerPaths []string
		want          string
	}{
		{
			name:          "preferred path wins",
			preferredPath: filepath.Join(preferredDir, "oixCloud"),
			providerPaths: []string{filepath.Join(sharedDir, "one.yaml")},
			want:          "preferred",
		},
		{
			name: "shared directory",
			providerPaths: []string{
				filepath.Join(sharedDir, "one.yaml"),
				filepath.Join(sharedDir, "two.yaml"),
			},
			want: "shared",
		},
		{
			name: "mixed directories",
			providerPaths: []string{
				filepath.Join(homeDir, "one", "one.yaml"),
				filepath.Join(homeDir, "two", "two.yaml"),
			},
			want: defaultProviderDir,
		},
		{name: "no paths", want: defaultProviderDir},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ProviderDirectory(homeDir, test.preferredPath, test.providerPaths); got != test.want {
				t.Fatalf("ProviderDirectory() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProviderNameConcurrentAccess(t *testing.T) {
	oldProviderName := oixProviderName
	t.Setenv("OIX_PROVIDER_NAME", "")
	t.Cleanup(func() { SetProviderName(oldProviderName) })

	var waitGroup sync.WaitGroup
	for range 20 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for range 100 {
				SetProviderName("provider-a")
				_ = ProviderFile()
				SetProviderName("provider-b")
			}
		}()
	}
	waitGroup.Wait()
}

func TestEnvironmentTokenIsNormalized(t *testing.T) {
	previousToken := CurrentToken()
	SetToken("")
	t.Cleanup(func() { SetToken(previousToken) })

	t.Setenv("OIX_TOKEN", "  Bearer environment-token  ")
	if got := getToken(); got != "environment-token" {
		t.Fatalf("environment token = %q, want environment-token", got)
	}

	t.Setenv("OIX_TOKEN", "   ")
	if HasToken() {
		t.Fatal("whitespace-only environment token was accepted")
	}
}

func setoixHTTPClientForTest(t *testing.T, client *http.Client) {
	previous := oixHTTPClient
	oixHTTPClient = client
	t.Cleanup(func() {
		oixHTTPClient = previous
	})
}

func Test_oixHTTPClientUsesDirectResolver(t *testing.T) {
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
	bootstrapResolver := &staticResolver{err: errors.New("bootstrap DNS should not be used")}
	oldProxyResolver := R.ProxyServerHostResolver
	oldDirectResolver := R.DirectHostResolver
	oldBootstrapResolver := oixBootstrapHostResolver
	R.ProxyServerHostResolver = proxyResolver
	R.DirectHostResolver = directResolver
	oixBootstrapHostResolver = bootstrapResolver
	t.Cleanup(func() {
		R.ProxyServerHostResolver = oldProxyResolver
		R.DirectHostResolver = oldDirectResolver
		oixBootstrapHostResolver = oldBootstrapResolver
	})

	client := newoixHTTPClient()
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get("http://oix.test:" + port)
	if err != nil {
		t.Fatalf("direct request failed: %v", err)
	}
	_ = response.Body.Close()
	if proxyResolver.calls != 0 || directResolver.calls != 1 || bootstrapResolver.calls != 0 {
		t.Fatalf("resolver calls: proxy=%d direct=%d bootstrap=%d", proxyResolver.calls, directResolver.calls, bootstrapResolver.calls)
	}
}

func Test_oixHTTPClientHedgesWithBootstrapResolver(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	proxyResolver := &staticResolver{err: errors.New("proxy DNS unavailable")}
	directResolver := &staticResolver{waitForCancellation: true}
	bootstrapResolver := &staticResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	oldProxyResolver := R.ProxyServerHostResolver
	oldDirectResolver := R.DirectHostResolver
	oldBootstrapResolver := oixBootstrapHostResolver
	R.ProxyServerHostResolver = proxyResolver
	R.DirectHostResolver = directResolver
	oixBootstrapHostResolver = bootstrapResolver
	t.Cleanup(func() {
		R.ProxyServerHostResolver = oldProxyResolver
		R.DirectHostResolver = oldDirectResolver
		oixBootstrapHostResolver = oldBootstrapResolver
	})

	client := newoixHTTPClient()
	t.Cleanup(client.CloseIdleConnections)
	requestCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, "http://oix.test:"+port, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("bootstrap request failed: %v", err)
	}
	_ = response.Body.Close()
	if proxyResolver.calls != 0 || bootstrapResolver.calls != 1 {
		t.Fatalf("resolver calls: proxy=%d bootstrap=%d", proxyResolver.calls, bootstrapResolver.calls)
	}
}

func Test_oixFallbackResolverRespectsManagedDomain(t *testing.T) {
	oldNodesDomain, oldDNSAddr := oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.NodesDomains = "fallback-nodes.example"
	oixdns.DNSAddr = "127.0.0.1:53"
	oixdns.ConfigureManagedDNS("cloud-nodes.example", "127.0.0.1:1053")
	t.Cleanup(func() {
		oixdns.NodesDomains, oixdns.DNSAddr = oldNodesDomain, oldDNSAddr
		oixdns.ResetManagedDNS()
	})

	privateAddress := netip.MustParseAddr("192.0.2.1")
	bootstrapAddress := netip.MustParseAddr("192.0.2.2")
	privateError := errors.New("private DNS unavailable")
	tests := []struct {
		name               string
		host               string
		primary            *staticResolver
		wantAddress        netip.Addr
		wantError          error
		wantBootstrapCalls int
	}{
		{
			name:        "slow private DNS wins",
			host:        "node.cloud-nodes.example",
			primary:     &staticResolver{addresses: []netip.Addr{privateAddress}, delay: 2 * hedgeDelay},
			wantAddress: privateAddress,
		},
		{
			name:      "private DNS failure stays private",
			host:      "node.cloud-nodes.example",
			primary:   &staticResolver{err: privateError},
			wantError: privateError,
		},
		{
			name:               "similar unmanaged domain can fall back",
			host:               "node.notcloud-nodes.example",
			primary:            &staticResolver{waitForCancellation: true},
			wantAddress:        bootstrapAddress,
			wantBootstrapCalls: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bootstrapResolver := &staticResolver{addresses: []netip.Addr{bootstrapAddress}}
			hostResolver := oixFallbackResolver{Resolver: test.primary, fallback: bootstrapResolver}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			addresses, err := hostResolver.LookupIPv4(ctx, test.host)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("lookup error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && (len(addresses) != 1 || addresses[0] != test.wantAddress) {
				t.Fatalf("lookup addresses = %v, want [%s]", addresses, test.wantAddress)
			}
			if test.primary.calls != 1 || bootstrapResolver.calls != test.wantBootstrapCalls {
				t.Fatalf("resolver calls: primary=%d bootstrap=%d", test.primary.calls, bootstrapResolver.calls)
			}
		})
	}
}

func Test_oixBootstrapResolverQueriesConfiguredServer(t *testing.T) {
	packetConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{
		PacketConn: packetConn,
		Handler: D.HandlerFunc(func(w D.ResponseWriter, request *D.Msg) {
			response := new(D.Msg)
			response.SetReply(request)
			response.Answer = append(response.Answer, &D.A{
				Hdr: D.RR_Header{Name: request.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 300},
				A:   net.IPv4(192, 0, 2, 10),
			})
			_ = w.WriteMsg(response)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	bootstrapResolver := &oixBootstrapResolver{servers: []string{packetConn.LocalAddr().String()}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := bootstrapResolver.LookupIPv4(ctx, "api.oix.test")
	if err != nil {
		t.Fatalf("bootstrap lookup failed: %v", err)
	}
	want := netip.MustParseAddr("192.0.2.10")
	if len(addresses) != 1 || addresses[0] != want {
		t.Fatalf("bootstrap lookup addresses = %v, want [%s]", addresses, want)
	}
}

func Test_oixBootstrapResolverRejectsEmptyServerList(t *testing.T) {
	_, err := (&oixBootstrapResolver{}).LookupIPv4(context.Background(), "api.oix.test")
	if !errors.Is(err, R.ErrIPNotFound) {
		t.Fatalf("empty bootstrap lookup error = %v, want ErrIPNotFound", err)
	}
}

func Test_oixHTTPDoReplaysRequestBody(t *testing.T) {
	var calls int
	var bodies []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
		calls++
		bodies = append(bodies, string(body))
		status := http.StatusNoContent
		if calls == 1 {
			status = http.StatusInternalServerError
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})
	setoixHTTPClientForTest(t, &http.Client{Transport: transport})

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://oix.test", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := oixHTTPDo(request)
	if err != nil {
		t.Fatalf("oixHTTPDo() error = %v", err)
	}
	_ = response.Body.Close()
	if calls != 2 {
		t.Fatalf("request calls = %d, want 2", calls)
	}
	for index, body := range bodies {
		if body != "payload" {
			t.Fatalf("request body %d = %q, want payload", index, body)
		}
	}
}

func Test_oixHTTPDoRejectsUnreplayableRequestBody(t *testing.T) {
	var calls int
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		_, _ = io.Copy(io.Discard, request.Body)
		calls++
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})
	setoixHTTPClientForTest(t, &http.Client{Transport: transport})

	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://oix.test", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = oixHTTPDo(request)
	if err == nil || !strings.Contains(err.Error(), "not replayable") {
		t.Fatalf("oixHTTPDo() error = %v, want not replayable", err)
	}
	if calls != 1 {
		t.Fatalf("request calls = %d, want 1", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestPlanDefaultParams(t *testing.T) {
	tests := []struct {
		name string
		plan planIdentity
		want string
	}{
		{name: "no plan", plan: planIdentity{Code: "no_plan", Rank: intPointer(0)}, want: ""},
		{name: "iron", plan: planIdentity{Code: "iron", Rank: intPointer(10)}, want: ""},
		{name: "alu", plan: planIdentity{Code: "alu", Rank: intPointer(20)}, want: "&mode=emergency"},
		{name: "bronze", plan: planIdentity{Code: "bronze", Rank: intPointer(30)}, want: "&mode=emergency"},
		{name: "silver", plan: planIdentity{Code: "silver", Rank: intPointer(40)}, want: "&type=love"},
		{name: "gold", plan: planIdentity{Code: "gold", Rank: intPointer(50)}, want: "&type=love"},
		{name: "stable rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(30)}, want: "&mode=emergency"},
		{name: "explicit zero rank wins", plan: planIdentity{Code: "iron", Rank: intPointer(0)}, want: ""},
		{name: "code fallback iron", plan: planIdentity{Code: "iron"}, want: ""},
		{name: "code fallback alu", plan: planIdentity{Code: "alu"}, want: "&mode=emergency"},
		{name: "code fallback silver", plan: planIdentity{Code: "silver"}, want: "&type=love"},
		{name: "code fallback gold", plan: planIdentity{Code: "gold"}, want: "&type=love"},
		{name: "legacy no plan", plan: planIdentity{Name: "no plan"}, want: ""},
		{name: "legacy iron", plan: planIdentity{Name: "Pass Iron"}, want: ""},
		{name: "legacy alu", plan: planIdentity{Name: "Pass Alu"}, want: "&mode=emergency"},
		{name: "legacy bronze", plan: planIdentity{Name: "Pass Bronze"}, want: "&mode=emergency"},
		{name: "node access overrides rank", plan: planIdentity{Code: "silver", Rank: intPointer(40), NodeAccess: []string{"edge", "cia", "ixp"}}, want: "&mode=emergency"},
		{name: "fusion access overrides rank", plan: planIdentity{Code: "bronze", Rank: intPointer(30), NodeAccess: []string{"edge", "fusion"}}, want: "&type=love"},
		{name: "edge access overrides rank", plan: planIdentity{Code: "silver", Rank: intPointer(40), NodeAccess: []string{"edge"}}, want: ""},
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
			if got := r.URL.Query().Get("mode"); got != "overseas" {
				t.Errorf("mode = %q, want overseas", got)
			}
			if got := r.URL.Query().Get("tfo"); got != "false" {
				t.Errorf("tfo = %q, want false", got)
			}
			if got := r.URL.Query().Get("area"); got != "hk" {
				t.Errorf("area = %q, want hk", got)
			}
			encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
			if err != nil {
				t.Error(err)
				return
			}
			config := base64.StdEncoding.EncodeToString(encrypted)
			timestamp := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
			_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	setoixHTTPClientForTest(t, server.Client())

	result, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
	if err != nil {
		t.Fatalf("fetchFrom() error = %v", err)
	}
	if managedCalls != 1 {
		t.Fatalf("managed endpoint calls = %d, want 1", managedCalls)
	}
	plaintext, err := A.DecryptBytes(result, secretKey)
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

	setoixHTTPClientForTest(t, server.Client())

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
	oldAppSecret := AppSecret
	oldSecretKey := ageSecretKey
	oldPublicKey := agePublicKey
	AppSecret = "test-secret"
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageSecretKey = secretKey
	agePublicKey = publicKey
	t.Cleanup(func() {
		AppSecret = oldAppSecret
		ageSecretKey = oldSecretKey
		agePublicKey = oldPublicKey
	})

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
	setoixHTTPClientForTest(t, server.Client())

	_, err = fetchFrom(context.Background(), "invalid-token", server.URL, t.TempDir())
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

func TestPeriodicUpdateUsesProviderUpdateLock(t *testing.T) {
	StopPeriodicUpdate()
	t.Setenv("OIX_TOKEN", "")
	t.Setenv("OIX_UPDATE_INTERVAL", "1")
	oldDir, oldHomeDir := providerPaths()
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	oldAppSecret, oldSecretKey, oldPublicKey := AppSecret, ageSecretKey, agePublicKey
	oldAPIDomains, oldSpareDomain := ApiDomains, SpareApiDomain
	oldToken := CurrentToken()
	AppSecret = "test-secret"
	ageSecretKey = secretKey
	agePublicKey = publicKey
	SetToken("test-token")
	t.Cleanup(func() {
		StopPeriodicUpdate()
		SetProviderPaths(oldDir, oldHomeDir)
		AppSecret, ageSecretKey, agePublicKey = oldAppSecret, oldSecretKey, oldPublicKey
		ApiDomains, SpareApiDomain = oldAPIDomains, oldSpareDomain
		SetToken(oldToken)
	})

	lockObserved := make(chan bool, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		locked := !providerUpdateMu.TryLock()
		if !locked {
			providerUpdateMu.Unlock()
		}
		lockObserved <- locked
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())
	ApiDomains = server.URL
	SpareApiDomain = ""

	StartPeriodicUpdate("providers", t.TempDir())
	locked := false
	select {
	case locked = <-lockObserved:
	case <-time.After(3 * time.Second):
		StopPeriodicUpdate()
		t.Fatal("periodic update did not reach the managed endpoint")
	}
	StopPeriodicUpdate()
	if !locked {
		t.Fatal("periodic update did not hold providerUpdateMu")
	}
}

func TestLogoutClearsManagedDNSAfterPeriodicUpdateStops(t *testing.T) {
	StopPeriodicUpdate()
	oldDir, oldHomeDir := providerPaths()
	oldToken := CurrentToken()
	oldNodesDomain, oldDNSAddr := oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.NodesDomains = "fallback.example"
	oixdns.DNSAddr = "127.0.0.1:53"
	oixdns.ConfigureManagedDNS("managed.example", "127.0.0.1:1053")
	t.Cleanup(func() {
		StopPeriodicUpdate()
		SetProviderPaths(oldDir, oldHomeDir)
		SetToken(oldToken)
		oixdns.NodesDomains, oixdns.DNSAddr = oldNodesDomain, oldDNSAddr
		oixdns.ResetManagedDNS()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	periodicMu.Lock()
	periodicCancel = cancel
	periodicDone = done
	periodicDir = "providers"
	periodicHome = t.TempDir()
	periodicMu.Unlock()
	go func() {
		<-ctx.Done()
		oixdns.ConfigureManagedDNS("stale.example", "127.0.0.1:2053")
		close(done)
	}()

	Logout()
	if got := oixdns.ManagedDNSAddr(); got != "127.0.0.1:53" {
		t.Fatalf("managed DNS address after logout = %q, want fallback", got)
	}
}

func TestLogoutWinsOverConcurrentForceUpdate(t *testing.T) {
	StopPeriodicUpdate()
	t.Setenv("OIX_TOKEN", "")
	homeDir := t.TempDir()
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	oldAppSecret, oldSecretKey, oldPublicKey := AppSecret, ageSecretKey, agePublicKey
	oldAPIDomains, oldSpareDomain := ApiDomains, SpareApiDomain
	oldDir, oldHomeDir := providerPaths()
	oldToken := CurrentToken()
	oldEnsured := oixdns.IsEnsured()
	AppSecret = "test-secret"
	ageSecretKey = secretKey
	agePublicKey = publicKey
	SetToken("test-token")
	SetProviderPaths("providers", homeDir)
	oixdns.ClearEnsured()
	t.Cleanup(func() {
		StopPeriodicUpdate()
		AppSecret, ageSecretKey, agePublicKey = oldAppSecret, oldSecretKey, oldPublicKey
		ApiDomains, SpareApiDomain = oldAPIDomains, oldSpareDomain
		SetProviderPaths(oldDir, oldHomeDir)
		SetToken(oldToken)
		if oldEnsured {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
	})

	managedStarted := make(chan struct{})
	releaseManaged := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/information":
			http.NotFound(w, r)
		case "/api/v1/managed/flclash/direct":
			close(managedStarted)
			<-releaseManaged
			encrypted, encryptErr := A.EncryptBytes([]byte("proxies: []"), publicKey)
			if encryptErr != nil {
				t.Error(encryptErr)
				return
			}
			config := base64.StdEncoding.EncodeToString(encrypted)
			timestamp := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
			_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())
	ApiDomains = server.URL
	SpareApiDomain = ""

	updateDone := make(chan error, 1)
	go func() {
		updateDone <- ForceUpdate()
	}()
	<-managedStarted
	logoutDone := make(chan struct{})
	go func() {
		Logout()
		close(logoutDone)
	}()
	deadline := time.Now().Add(time.Second)
	for CurrentToken() != "" && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if CurrentToken() != "" {
		t.Fatal("logout did not clear the token")
	}
	close(releaseManaged)
	if err := <-updateDone; err != nil {
		t.Fatalf("ForceUpdate() error = %v", err)
	}
	<-logoutDone

	if oixdns.IsEnsured() {
		t.Fatal("managed DNS was re-enabled after logout")
	}
	providerPath := filepath.Join(homeDir, "providers", ProviderFile())
	if _, err := os.Stat(providerPath); !os.IsNotExist(err) {
		t.Fatalf("provider remains after logout: %v", err)
	}
}

func TestDefaultUpdateInterval(t *testing.T) {
	if defaultUpdateInterval != 24*time.Hour {
		t.Fatalf("defaultUpdateInterval = %s, want 24h", defaultUpdateInterval)
	}
}

func TestStartPeriodicUpdateIgnoresOverflowingInterval(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("requires a 64-bit int")
	}
	t.Setenv("OIX_UPDATE_INTERVAL", "9223372037")
	oldDir, oldHomeDir := providerPaths()
	t.Cleanup(func() {
		StopPeriodicUpdate()
		SetProviderPaths(oldDir, oldHomeDir)
	})

	StartPeriodicUpdate("providers", t.TempDir())
	StopPeriodicUpdate()
}

func TestPersistTokenTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	homeDir := t.TempDir()
	path := tokenFilePath(homeDir)
	if err := os.WriteFile(path, []byte("old-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := persistToken(homeDir, "new-token"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token permissions = %o, want 600", got)
	}
}

func TestPersistTokenDoesNotFollowSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	homeDir := t.TempDir()
	victimPath := filepath.Join(homeDir, "victim")
	if err := os.WriteFile(victimPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenPath := tokenFilePath(homeDir)
	if err := os.Symlink(victimPath, tokenPath); err != nil {
		t.Fatal(err)
	}

	if err := persistToken(homeDir, "new-token"); err != nil {
		t.Fatal(err)
	}
	victim, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", victim)
	}
	info, err := os.Lstat(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("token path remained a symlink")
	}
}

func TestLoadPersistedTokenTightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	t.Setenv("OIX_TOKEN", "")
	previousToken := CurrentToken()
	SetToken("")
	t.Cleanup(func() { SetToken(previousToken) })

	homeDir := t.TempDir()
	path := tokenFilePath(homeDir)
	if err := os.WriteFile(path, []byte("persisted-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	LoadPersistedToken(homeDir)
	if got := CurrentToken(); got != "persisted-token" {
		t.Fatalf("loaded token = %q, want persisted-token", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token permissions = %o, want 600", got)
	}
}

func TestLoadPersistedTokenIgnoresSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	t.Setenv("OIX_TOKEN", "")
	previousToken := CurrentToken()
	SetToken("")
	t.Cleanup(func() { SetToken(previousToken) })

	homeDir := t.TempDir()
	victimPath := filepath.Join(homeDir, "victim")
	if err := os.WriteFile(victimPath, []byte("linked-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimPath, tokenFilePath(homeDir)); err != nil {
		t.Fatal(err)
	}

	LoadPersistedToken(homeDir)
	if got := CurrentToken(); got != "" {
		t.Fatalf("loaded token through symlink = %q", got)
	}
	info, err := os.Stat(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("symlink target permissions = %o, want 644", got)
	}
}

func TestSaveResultUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits are not portable on Windows")
	}
	homeDir := t.TempDir()
	oldProviderName := oixProviderName
	SetProviderName("test-provider")
	t.Cleanup(func() {
		SetProviderName(oldProviderName)
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

	if !saveResult("providers", homeDir, raw) {
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

func TestSaveResultDoesNotFollowProviderSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	homeDir := t.TempDir()
	providerDir := filepath.Join(homeDir, "providers")
	if err := os.MkdirAll(providerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	victimPath := filepath.Join(homeDir, "victim")
	if err := os.WriteFile(victimPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(providerDir, "test-provider")
	if err := os.Symlink(victimPath, providerPath); err != nil {
		t.Fatal(err)
	}

	oldProviderName := oixProviderName
	oldSecretKey := ageSecretKey
	SetProviderName("test-provider")
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageSecretKey = secretKey
	t.Cleanup(func() {
		SetProviderName(oldProviderName)
		ageSecretKey = oldSecretKey
	})
	raw, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !saveResult("providers", homeDir, raw) {
		t.Fatal("saveResult failed")
	}
	victim, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "keep" {
		t.Fatalf("symlink target was overwritten: %q", victim)
	}
	info, err := os.Lstat(providerPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("provider path remained a symlink")
	}
}

func TestSaveResultKeepsProviderInsideDirectory(t *testing.T) {
	rootDir := t.TempDir()
	homeDir := filepath.Join(rootDir, "home")
	if err := os.Mkdir(homeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	oldProviderName := oixProviderName
	oldSecretKey := ageSecretKey
	SetProviderName("../../escaped-provider")
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageSecretKey = secretKey
	t.Cleanup(func() {
		SetProviderName(oldProviderName)
		ageSecretKey = oldSecretKey
	})
	raw, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !saveResult("providers", homeDir, raw) {
		t.Fatal("saveResult failed")
	}
	if _, err := os.Stat(filepath.Join(rootDir, "escaped-provider")); !os.IsNotExist(err) {
		t.Fatalf("provider escaped its directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(homeDir, "providers", defaultProviderFile)); err != nil {
		t.Fatalf("default provider was not written: %v", err)
	}
}

func TestSaveResultRejectsUnencryptedProvider(t *testing.T) {
	homeDir := t.TempDir()
	oldProviderName := oixProviderName
	SetProviderName("test-provider")
	t.Cleanup(func() {
		SetProviderName(oldProviderName)
	})

	if saveResult("providers", homeDir, []byte("proxies: []")) {
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
	SetProviderName("test-provider")
	ageSecretKey, _, _ = A.GenX25519KeyPair()
	t.Cleanup(func() {
		SetProviderName(oldProviderName)
		ageSecretKey = oldSecretKey
	})

	raw := []byte("-----BEGIN AGE ENCRYPTED FILE-----\nproxies: []")
	if saveResult("providers", homeDir, raw) {
		t.Fatal("saveResult accepted an invalid Age provider")
	}
	if _, err := os.Stat(filepath.Join(homeDir, "providers", "test-provider")); !os.IsNotExist(err) {
		t.Fatalf("invalid Age provider was written: %v", err)
	}
}

type rewriteTransport struct {
	host string
}

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = rt.host
	return http.DefaultTransport.RoundTrip(clone)
}

func setupEnsureFetchFailure(t *testing.T, status int) (homeDir string) {
	t.Helper()
	homeDir = t.TempDir()
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	oldAppSecret, oldSecretKey, oldPublicKey := AppSecret, ageSecretKey, agePublicKey
	oldApiDomains, oldSpare := ApiDomains, SpareApiDomain
	oldHomeDir := C.Path.HomeDir()
	oldToken := CurrentToken()
	oldEnsured := oixdns.IsEnsured()
	AppSecret = "test-secret"
	ageSecretKey = secretKey
	agePublicKey = publicKey
	SpareApiDomain = ""
	C.SetHomeDir(homeDir)
	SetToken("test-token")
	oixdns.ClearEnsured()
	t.Cleanup(func() {
		AppSecret, ageSecretKey, agePublicKey = oldAppSecret, oldSecretKey, oldPublicKey
		ApiDomains, SpareApiDomain = oldApiDomains, oldSpare
		C.SetHomeDir(oldHomeDir)
		SetToken(oldToken)
		if oldEnsured {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	ApiDomains = "oix.test"
	setoixHTTPClientForTest(t, &http.Client{Transport: rewriteTransport{host: server.Listener.Addr().String()}})

	if err := os.MkdirAll(filepath.Join(homeDir, defaultProviderDir), 0o755); err != nil {
		t.Fatal(err)
	}
	provider, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(homeDir, defaultProviderDir, ProviderFile())
	if err := os.WriteFile(providerPath, provider, 0o600); err != nil {
		t.Fatal(err)
	}
	return homeDir
}

func TestEnsureKeepsManagedDNSWhenFetchFailsWithCachedProvider(t *testing.T) {
	homeDir := setupEnsureFetchFailure(t, http.StatusNotFound)

	if _, err := Ensure(defaultProviderDir, homeDir, true); err == nil {
		t.Fatal("Ensure() expected fetch error")
	}
	if !oixdns.IsEnsured() {
		t.Fatal("managed DNS not enabled despite cached provider on disk")
	}
}

func TestEnsureKeepsManagedDNSWhenAuthFailureIsNotUnanimous(t *testing.T) {
	homeDir := setupEnsureFetchFailure(t, http.StatusNotFound)
	ApiDomains = "auth.oix.test,unavailable.oix.test"
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		status := http.StatusNotFound
		if request.URL.Path != "/api/v1/information" {
			if request.URL.Host == "auth.oix.test" {
				status = http.StatusUnauthorized
			} else {
				status = http.StatusForbidden
			}
		}
		return &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    request,
		}, nil
	})
	setoixHTTPClientForTest(t, &http.Client{Transport: transport})

	_, err := Ensure(defaultProviderDir, homeDir, true)
	if err == nil || IsAuthError(err) {
		t.Fatalf("Ensure() error = %v, want non-auth failure", err)
	}
	if !oixdns.IsEnsured() {
		t.Fatal("managed DNS not enabled despite cached provider on disk")
	}
}

func TestEnsureRejectsInvalidCachedProvider(t *testing.T) {
	homeDir := setupEnsureFetchFailure(t, http.StatusNotFound)
	providerPath := filepath.Join(homeDir, defaultProviderDir, ProviderFile())
	if err := os.WriteFile(providerPath, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Ensure(defaultProviderDir, homeDir, true); err == nil {
		t.Fatal("Ensure() expected fetch error")
	}
	if oixdns.IsEnsured() {
		t.Fatal("managed DNS enabled with invalid cached provider")
	}
}

func TestEnsureSkipsManagedDNSOnAuthFailure(t *testing.T) {
	homeDir := setupEnsureFetchFailure(t, http.StatusUnauthorized)

	_, err := Ensure(defaultProviderDir, homeDir, true)
	if !IsAuthError(err) {
		t.Fatalf("Ensure() error = %v, want auth error", err)
	}
	if oixdns.IsEnsured() {
		t.Fatal("managed DNS enabled after auth failure")
	}
}

func TestApplyManagedDNSConfig(t *testing.T) {
	oldDomain, oldAddr := oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.NodesDomains = "cloud-nodes.example"
	oixdns.DNSAddr = "127.0.0.1:53"
	oixdns.ResetManagedDNS()
	t.Cleanup(func() {
		oixdns.NodesDomains, oixdns.DNSAddr = oldDomain, oldAddr
		oixdns.ResetManagedDNS()
	})

	applyManagedDNSConfig([]byte(`
dns:
  nameserver-policy:
    +.cloud-nodes.example:
      - udp://127.0.0.1:1053
      - tcp://127.0.0.1:1053
`))
	if got := oixdns.ManagedDNSAddr(); got != "127.0.0.1:1053" {
		t.Fatalf("managed DNS address = %q, want 127.0.0.1:1053", got)
	}

	applyManagedDNSConfig([]byte(`
dns:
  nameserver-policy:
    +.cloud-nodes.example: tcp://127.0.0.2:2053
`))
	if got := oixdns.ManagedDNSAddr(); got != "127.0.0.2:2053" {
		t.Fatalf("updated managed DNS address = %q, want 127.0.0.2:2053", got)
	}

	applyManagedDNSConfig([]byte(`
dns:
  nameserver-policy:
    +.cloud-nodes.example: https://invalid.example/dns-query
`))
	if got := oixdns.ManagedDNSAddr(); got != "127.0.0.2:2053" {
		t.Fatalf("managed DNS address = %q after invalid matching policy, want previous address", got)
	}

	applyManagedDNSConfig([]byte(`
dns:
  nameserver-policy:
    +.other.example: udp://127.0.0.3:3053
`))
	if got := oixdns.ManagedDNSAddr(); got != "127.0.0.1:53" {
		t.Fatalf("managed DNS address = %q after policy removal, want fallback", got)
	}
}

func TestApplyManagedDNSConfigPrefersExactDomain(t *testing.T) {
	oldDomain, oldAddr := oixdns.NodesDomains, oixdns.DNSAddr
	oixdns.NodesDomains = "cloud-nodes.example"
	oixdns.DNSAddr = "127.0.0.1:53"
	oixdns.ResetManagedDNS()
	t.Cleanup(func() {
		oixdns.NodesDomains, oixdns.DNSAddr = oldDomain, oldAddr
		oixdns.ResetManagedDNS()
	})

	config := []byte(`
dns:
  nameserver-policy:
    +.cloud-nodes.example: udp://127.0.0.2:1053
    cloud-nodes.example: udp://127.0.0.3:1053
`)
	for range 20 {
		applyManagedDNSConfig(config)
		if got := oixdns.ManagedDNSAddr(); got != "127.0.0.3:1053" {
			t.Fatalf("managed DNS address = %q, want exact-domain server", got)
		}
	}
}
