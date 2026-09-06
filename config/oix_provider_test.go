package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
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

func TestParseProxiesRejectsReservedOIXProviderName(t *testing.T) {
	oldName, oldToken := oix.ProviderFile(), oix.CurrentToken()
	oix.SetProviderName("default")
	oix.SetToken("test-token")
	t.Cleanup(func() {
		oix.SetProviderName(oldName)
		oix.SetToken(oldToken)
	})

	_, _, err := parseProxies(DefaultRawConfig())
	if err == nil || !strings.Contains(err.Error(), "reserved provider name") {
		t.Fatalf("parseProxies error = %v, want reserved OIX provider name error", err)
	}
}

func TestParseProxiesKeepsUnmanagedOIXProvider(t *testing.T) {
	oldHomeDir, oldToken := C.Path.HomeDir(), oix.CurrentToken()
	C.SetHomeDir(t.TempDir())
	oix.SetToken("")
	t.Setenv("OIX_TOKEN", "")
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
		oix.SetToken(oldToken)
	})
	rawCfg := DefaultRawConfig()
	name := oix.ProviderFile()
	rawCfg.ProxyProvider = map[string]map[string]any{
		name: {
			"type": "inline",
			"payload": []map[string]any{
				{"name": "local", "type": "direct"},
			},
		},
	}
	_, providers, err := parseProxies(rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := providers[name].VehicleType(); got != P.Inline {
		t.Fatalf("provider type without OIX token = %v, want inline", got)
	}
}

func TestParseProxiesAppliesOIXDefaultsBeforeValidation(t *testing.T) {
	homeDir := t.TempDir()
	oldHomeDir, oldToken := C.Path.HomeDir(), oix.CurrentToken()
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
			"path": wantPath,
			"health-check": map[string]any{
				"enable": false,
				"url":    "https://health.example/generate_204",
			},
		},
	}

	_, providers, err := parseProxies(rawCfg)
	if err != nil {
		t.Fatalf("parse OIX provider overrides: %v", err)
	}
	if got := providers[providerName].VehicleType(); got != P.File {
		t.Fatalf("OIX vehicle type = %v, want file", got)
	}
	if got := providers[providerName].Path(); got != wantPath {
		t.Fatalf("OIX provider path = %q, want %q", got, wantPath)
	}
	if got := providers[providerName].HealthCheckURL(); got != "https://health.example/generate_204" {
		t.Fatalf("OIX health check URL = %q", got)
	}
	if _, changed := rawCfg.ProxyProvider[providerName]["type"]; changed {
		t.Fatal("parsing mutated the original provider configuration")
	}
}
