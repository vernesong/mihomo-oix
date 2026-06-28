package route

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestProviderServerHostsReturnsOnlyUniqueHosts(t *testing.T) {
	proxies := []C.Proxy{
		mustRouteTestProxy(t, "a", "example.com", 443),
		mustRouteTestProxy(t, "b", "203.0.113.7", 8443),
		mustRouteTestProxy(t, "c", "example.com", 9443),
		mustRouteTestProxy(t, "d", "2001:db8::1", 443),
	}

	got := providerServerHosts(proxies)
	want := []string{"2001:db8::1", "203.0.113.7", "example.com"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("providerServerHosts() = %#v, want %#v", got, want)
	}
}

func TestGetProviderServersOnlySupportsOixProvider(t *testing.T) {
	provider := routeTestProvider{
		name: "oixCloud",
		proxies: []C.Proxy{
			mustRouteTestProxy(t, "a", "example.com", 443),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/providers/proxies/oixCloud/servers", nil)
	req = req.WithContext(contextWithProvider(req.Context(), "oixCloud", provider))
	rec := httptest.NewRecorder()

	getProviderServers(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var body struct {
		Servers []string `json:"servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !reflect.DeepEqual(body.Servers, []string{"example.com"}) {
		t.Fatalf("servers = %#v, want %#v", body.Servers, []string{"example.com"})
	}

	req = httptest.NewRequest(http.MethodGet, "/providers/proxies/other/servers", nil)
	req = req.WithContext(contextWithProvider(req.Context(), "other", provider))
	rec = httptest.NewRecorder()

	getProviderServers(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("non-OIX status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func mustRouteTestProxy(t *testing.T, name string, server string, port int) C.Proxy {
	t.Helper()

	proxy, err := adapter.ParseProxy(map[string]any{
		"name":   name,
		"type":   "socks5",
		"server": server,
		"port":   port,
	})
	if err != nil {
		t.Fatalf("ParseProxy(%s): %v", name, err)
	}

	return proxy
}

func contextWithProvider(ctx context.Context, name string, provider P.ProxyProvider) context.Context {
	ctx = context.WithValue(ctx, CtxKeyProviderName, name)
	return context.WithValue(ctx, CtxKeyProvider, provider)
}

type routeTestProvider struct {
	name    string
	proxies []C.Proxy
}

func (p routeTestProvider) Name() string { return p.name }
func (p routeTestProvider) VehicleType() P.VehicleType {
	return P.File
}
func (p routeTestProvider) Type() P.ProviderType { return P.Proxy }
func (p routeTestProvider) Path() string         { return "" }
func (p routeTestProvider) Initial() error       { return nil }
func (p routeTestProvider) Update() error        { return nil }
func (p routeTestProvider) Proxies() []C.Proxy   { return p.proxies }
func (p routeTestProvider) Count() int           { return len(p.proxies) }
func (p routeTestProvider) Touch()               {}
func (p routeTestProvider) HealthCheck()         {}
func (p routeTestProvider) Version() uint32      { return 0 }
func (p routeTestProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}
func (p routeTestProvider) HealthCheckURL() string { return "" }
