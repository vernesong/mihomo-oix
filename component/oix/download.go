package oix

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/metacubex/mihomo/component/dialer"
	mihomoHttp "github.com/metacubex/mihomo/component/http"

	"gopkg.in/yaml.v3"
)

// OpenClash's initial and scheduled full-config downloads use the same protected
// transport and deadline as the managed provider. Credentials stay on stdin.
func downloadConfigCLI(stdin io.Reader, stdout io.Writer) int {
	var in struct {
		URL           string `json:"url"`
		Proxy         string `json:"proxy"`
		ProxyUsername string `json:"proxy_username"`
		ProxyPassword string `json:"proxy_password"`
		RoutingMark   int32  `json:"routing_mark"`
	}
	if json.NewDecoder(io.LimitReader(stdin, 64<<10)).Decode(&in) != nil {
		return exitFailed
	}
	target, err := url.Parse(in.URL)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || in.RoutingMark < 0 {
		return exitFailed
	}
	direct := newoixHTTPClient()
	defer direct.CloseIdleConnections()
	clients := []*http.Client{direct}
	if in.Proxy != "" {
		proxyURL, err := url.Parse(in.Proxy)
		if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() != "127.0.0.1" || proxyURL.Port() == "" {
			return exitFailed
		}
		if in.ProxyUsername != "" || in.ProxyPassword != "" {
			proxyURL.User = url.UserPassword(in.ProxyUsername, in.ProxyPassword)
		}
		proxy := newoixHTTPClient()
		defer proxy.CloseIdleConnections()
		proxy.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
		clients = append(clients, proxy)
	}
	// OpenClash exempts mark 6666 on systems without iptables owner matching.
	previous := dialer.DefaultRoutingMark.Swap(in.RoutingMark)
	defer dialer.DefaultRoutingMark.Store(previous)
	result, err := fetchConfigRoutes(context.Background(), clients, func(ctx context.Context) (*fetchedConfig, error) {
		return fetchConfigURL(ctx, target.String())
	})
	if err != nil {
		return exitFailed
	}
	if _, err = stdout.Write(result.data); err != nil {
		return exitFailed
	}
	return exitOK
}

func fetchConfigURL(ctx context.Context, address string) (*fetchedConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, mihomoHttp.RedactError(err)
	}
	req.Header.Set("User-Agent", "clash")
	resp, err := oixHTTPDo(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, managedStatusError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxManagedResponseBytes+1))
	if err != nil {
		return nil, mihomoHttp.RedactError(err)
	}
	if len(data) > maxManagedResponseBytes {
		return nil, errors.New("managed configuration is too large")
	}
	var config map[string]any
	if yaml.Unmarshal(data, &config) != nil || config == nil {
		return nil, errors.New("invalid managed configuration")
	}
	_, proxies := config["proxies"]
	_, providers := config["proxy-providers"]
	if !proxies && !providers {
		return nil, errors.New("empty managed configuration")
	}
	return &fetchedConfig{data: data}, nil
}
