package config

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
)

func TestParseProxiesKeepsConfiguredOIXProviderPath(t *testing.T) {
	homeDir := t.TempDir()
	oldHomeDir := C.Path.HomeDir()
	oldToken := oix.CurrentToken()
	C.SetHomeDir(homeDir)
	oix.SetToken("test-token")
	t.Setenv("OIX_TOKEN", "")
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
		oix.SetToken(oldToken)
	})

	providerName := oix.ProviderFile()
	wantPath := filepath.Join(homeDir, "managed", providerName)
	rawCfg := DefaultRawConfig()
	rawCfg.ProxyProvider = map[string]map[string]any{
		providerName: {
			"type": "file",
			"path": wantPath,
		},
	}
	for index := range 32 {
		name := fmt.Sprintf("other-%02d", index)
		rawCfg.ProxyProvider[name] = map[string]any{
			"type": "file",
			"path": filepath.Join(homeDir, name, "provider.yaml"),
		}
	}

	for range 20 {
		_, providers, err := parseProxies(rawCfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := providers[providerName].Path(); got != wantPath {
			t.Fatalf("OIX provider path = %q, want %q", got, wantPath)
		}
	}
}
