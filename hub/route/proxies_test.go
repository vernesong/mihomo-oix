package route

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

type staticProxyProvider struct {
	proxies []C.Proxy
}

func TestMain(m *testing.M) {
	homeDir, err := os.MkdirTemp("", "mihomo-route-test-*")
	if err != nil {
		panic(err)
	}
	previousHomeDir := C.Path.HomeDir()
	C.SetHomeDir(homeDir)

	code := m.Run()

	if cache := cachefile.Cache(); cache != nil && cache.DB != nil {
		_ = cache.Close()
	}
	C.SetHomeDir(previousHomeDir)
	_ = os.RemoveAll(homeDir)
	os.Exit(code)
}

func (p *staticProxyProvider) Name() string { return "static" }

func (p *staticProxyProvider) VehicleType() P.VehicleType { return P.Compatible }

func (p *staticProxyProvider) Type() P.ProviderType { return P.Proxy }

func (p *staticProxyProvider) Path() string { return "" }

func (p *staticProxyProvider) Initial() error { return nil }

func (p *staticProxyProvider) Update() error { return nil }

func (p *staticProxyProvider) Proxies() []C.Proxy { return p.proxies }

func (p *staticProxyProvider) Count() int { return len(p.proxies) }

func (p *staticProxyProvider) Touch() {}

func (p *staticProxyProvider) HealthCheck() {}

func (p *staticProxyProvider) Version() uint32 { return 1 }

func (p *staticProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}

func (p *staticProxyProvider) HealthCheckURL() string { return "" }

func TestProxyDelayUnfixesNonSelectorGroup(t *testing.T) {
	groupName, nodeName, groupProxy, delayServerURL := setupURLTestRoute(t)

	router := proxyRouter()
	fixProxySelection(t, router, groupName, nodeName)
	if got := fixedSelection(t, groupProxy); got != nodeName {
		t.Fatalf("fixed selection after PUT = %q, want %q", got, nodeName)
	}
	if got := cachedSelection(t, groupName); got != nodeName {
		t.Fatalf("cached selection after PUT = %q, want %q", got, nodeName)
	}

	delayPath := "/" + url.PathEscape(groupName) + "/delay?url=" + url.QueryEscape(delayServerURL) + "&timeout=1000&expected=204"
	delayReq := httptest.NewRequest(http.MethodGet, delayPath, nil)
	delayRes := httptest.NewRecorder()
	router.ServeHTTP(delayRes, delayReq)
	if delayRes.Code != http.StatusOK {
		t.Fatalf("GET proxy delay status = %d, body = %s", delayRes.Code, delayRes.Body.String())
	}
	if got := fixedSelection(t, groupProxy); got != "" {
		t.Fatalf("fixed selection after proxy delay = %q, want empty", got)
	}
	if got := cachedSelection(t, groupName); got != "" {
		t.Fatalf("cached selection after proxy delay = %q, want empty", got)
	}
}

func TestProxyDelayUnfixesNonSelectorGroupBeforeQueryValidation(t *testing.T) {
	groupName, nodeName, groupProxy, delayServerURL := setupURLTestRoute(t)

	router := proxyRouter()
	fixProxySelection(t, router, groupName, nodeName)

	delayPath := "/" + url.PathEscape(groupName) + "/delay?url=" + url.QueryEscape(delayServerURL) + "&timeout=bad&expected=204"
	delayReq := httptest.NewRequest(http.MethodGet, delayPath, nil)
	delayRes := httptest.NewRecorder()
	router.ServeHTTP(delayRes, delayReq)
	if delayRes.Code != http.StatusBadRequest {
		t.Fatalf("GET proxy delay invalid query status = %d, body = %s", delayRes.Code, delayRes.Body.String())
	}
	if got := fixedSelection(t, groupProxy); got != "" {
		t.Fatalf("fixed selection after invalid proxy delay = %q, want empty", got)
	}
	if got := cachedSelection(t, groupName); got != "" {
		t.Fatalf("cached selection after invalid proxy delay = %q, want empty", got)
	}
}

func setupURLTestRoute(t *testing.T) (groupName, nodeName string, groupProxy C.Proxy, delayServerURL string) {
	t.Helper()

	delayServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(delayServer.Close)

	groupName = "Auto - UrlTest"
	nodeName = "node-a"
	cachefile.Cache().SetSelected(groupName, "")

	node := adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: nodeName}))
	provider := &staticProxyProvider{proxies: []C.Proxy{node}}
	group, err := outboundgroup.NewURLTest(outboundgroup.GroupCommonOption{
		Name: groupName,
		URL:  delayServer.URL,
	}, outboundgroup.URLTestOption{}, adapter.NewProxy(outbound.NewCompatible()), []P.ProxyProvider{provider})
	if err != nil {
		t.Fatalf("create URLTest group: %v", err)
	}
	groupProxy = adapter.NewProxy(group)

	previousProxies := cloneProxyMap(tunnel.Proxies())
	previousProviders := cloneProviderMap(tunnel.Providers())
	tunnel.UpdateProxies(map[string]C.Proxy{
		groupName: groupProxy,
		nodeName:  node,
	}, map[string]P.ProxyProvider{
		provider.Name(): provider,
	})
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
	})

	return groupName, nodeName, groupProxy, delayServer.URL
}

func fixProxySelection(t *testing.T, router http.Handler, groupName, nodeName string) {
	t.Helper()

	putReq := httptest.NewRequest(http.MethodPut, "/"+url.PathEscape(groupName), strings.NewReader(`{"name":"`+nodeName+`"}`))
	putReq.Header.Set("Content-Type", "application/json")
	putRes := httptest.NewRecorder()
	router.ServeHTTP(putRes, putReq)
	if putRes.Code != http.StatusNoContent {
		t.Fatalf("PUT proxy fixed status = %d, body = %s", putRes.Code, putRes.Body.String())
	}
}

func fixedSelection(t *testing.T, proxy C.Proxy) string {
	t.Helper()

	raw, err := json.Marshal(proxy)
	if err != nil {
		t.Fatalf("marshal proxy: %v", err)
	}
	var payload struct {
		Fixed string `json:"fixed"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal proxy: %v", err)
	}
	return payload.Fixed
}

func cachedSelection(t *testing.T, group string) string {
	t.Helper()

	return cachefile.Cache().SelectedMap()[group]
}

func cloneProxyMap(src map[string]C.Proxy) map[string]C.Proxy {
	dst := make(map[string]C.Proxy, len(src))
	for name, proxy := range src {
		dst[name] = proxy
	}
	return dst
}

func cloneProviderMap(src map[string]P.ProxyProvider) map[string]P.ProxyProvider {
	dst := make(map[string]P.ProxyProvider, len(src))
	for name, provider := range src {
		dst[name] = provider
	}
	return dst
}
