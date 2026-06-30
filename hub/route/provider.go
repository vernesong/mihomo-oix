package route

import (
	"context"
	"net"
	"sort"
	"strings"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/samber/lo"
)

func proxyProviderRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProviders)

	r.Route("/{providerName}", func(r chi.Router) {
		r.Use(parseProviderName, findProviderByName)
		r.Get("/", getProvider)
		r.Put("/", updateProvider)
		r.Get("/healthcheck", healthCheckProvider)
		r.Get("/servers", getProviderServers)
		r.Mount("/", proxyProviderProxyRouter())
	})
	return r
}

func proxyProviderProxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProviderProxyByName)
		r.Get("/", getProxy)
		r.Get("/healthcheck", getProxyDelay)
	})
	return r
}

func getProviders(w http.ResponseWriter, r *http.Request) {
	providers := tunnel.Providers()
	render.JSON(w, r, render.M{
		"providers": providers,
	})
}

func getProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.ProxyProvider)
	render.JSON(w, r, provider)
}

func updateProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.ProxyProvider)
	name := r.Context().Value(CtxKeyProviderName).(string)

	if oix.IsOixProvider(name) && provider.VehicleType() == P.File {
		if err := oix.ForceUpdate(); err != nil {
			render.Status(r, http.StatusServiceUnavailable)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
		return
	}

	if err := provider.Update(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func healthCheckProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.ProxyProvider)
	provider.HealthCheck()
	render.NoContent(w, r)
}

func getProviderServers(w http.ResponseWriter, r *http.Request) {
	name := r.Context().Value(CtxKeyProviderName).(string)
	provider := r.Context().Value(CtxKeyProvider).(P.ProxyProvider)
	if !oix.IsOixProvider(name) {
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, "servers")
		findProviderProxyByName(http.HandlerFunc(getProxy)).ServeHTTP(w, r.WithContext(ctx))
		return
	}

	render.JSON(w, r, render.M{
		"servers": providerServerHosts(provider.Proxies()),
	})
}

func providerServerHosts(proxies []C.Proxy) []string {
	serverSet := make(map[string]struct{}, len(proxies))
	for _, proxy := range proxies {
		if proxy == nil {
			continue
		}

		host := proxyServerHost(proxy.Addr())
		if host == "" {
			continue
		}

		serverSet[host] = struct{}{}
	}

	servers := make([]string, 0, len(serverSet))
	for server := range serverSet {
		servers = append(servers, server)
	}
	sort.Strings(servers)
	return servers
}

func proxyServerHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.Trim(addr, "[]")
	}

	return strings.Trim(host, "[]")
}

func parseProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "providerName")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProviderName).(string)
		providers := tunnel.Providers()
		provider, exist := providers[name]
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProviderProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var (
			name = r.Context().Value(CtxKeyProxyName).(string)
			pd   = r.Context().Value(CtxKeyProvider).(P.ProxyProvider)
		)
		proxy, exist := lo.Find(pd.Proxies(), func(proxy C.Proxy) bool {
			return proxy.Name() == name
		})

		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func ruleProviderRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getRuleProviders)
	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseRuleProviderName, findRuleProviderByName)
		r.Put("/", updateRuleProvider)
	})
	return r
}

func getRuleProviders(w http.ResponseWriter, r *http.Request) {
	ruleProviders := tunnel.RuleProviders()
	render.JSON(w, r, render.M{
		"providers": ruleProviders,
	})
}

func updateRuleProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.Context().Value(CtxKeyProvider).(P.RuleProvider)
	if err := provider.Update(); err != nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func parseRuleProviderName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProviderName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findRuleProviderByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProviderName).(string)
		providers := tunnel.RuleProviders()
		provider, exist := providers[name]
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProvider, provider)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
