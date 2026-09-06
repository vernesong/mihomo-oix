package config

import (
	"path/filepath"

	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

func parseOIXProvider(name string, base map[string]any, providers map[string]P.ProxyProvider) (P.ProxyProvider, error) {
	// Read only the source location here. The remaining options must be checked
	// after managed defaults have supplied the file vehicle and decryption key.
	var location struct {
		Type string `provider:"type,omitempty"`
		Path string `provider:"path,omitempty"`
		URL  string `provider:"url,omitempty"`
	}
	if base != nil {
		decoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
		if err := decoder.Decode(base, &location); err != nil {
			return nil, err
		}
	}

	preferredPath := ""
	if location.Path != "" {
		preferredPath = C.Path.Resolve(location.Path)
	} else if location.Type == "http" {
		preferredPath = C.Path.GetPathByHash("proxies", location.URL)
	}
	providerPaths := make([]string, 0, len(providers))
	for _, pv := range providers {
		if path := pv.Path(); path != "" {
			providerPaths = append(providerPaths, path)
		}
	}
	dir := oix.ProviderDirectory(C.Path.HomeDir(), preferredPath, providerPaths)
	mapping := oix.ProviderConfig(filepath.Join(dir, name), base)
	return provider.ParseProxyProvider(name, mapping, tunnel.Tunnel)
}
