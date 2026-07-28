package outbound

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/ech"
)

func TestSnellECHTLSUsesRawTLSWithoutPath(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}

	adapter, err := NewSnell(SnellOption{
		Name:    "snell",
		Server:  "origin.example.com",
		Port:    443,
		Psk:     "password",
		Version: 4,
		ObfsOpts: map[string]any{
			"mode":       "ech-tls",
			"ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatalf("NewSnell() error = %v", err)
	}
	defer adapter.Close()

	if adapter.echTLS == nil || adapter.echTLS.ECH == nil {
		t.Fatal("ECH TLS config was not initialized")
	}
	if adapter.echTLS.ClientSessionCache == nil || adapter.echTLS.UClientSessionCache == nil {
		t.Fatal("ECH TLS session caches were not initialized")
	}
	if len(adapter.echTLS.NextProtos) != 1 || adapter.echTLS.NextProtos[0] != snellECHTLSALPN {
		t.Fatalf("NextProtos = %q, want [%q]", adapter.echTLS.NextProtos, snellECHTLSALPN)
	}
}

func TestSnellECHTLSRejectsSkippedCertificateVerification(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "ech-config": echConfig, "skip-cert-verify": true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "requires certificate verification") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSLegacyFallbackMustBeExplicit(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"identity-version": 2, "legacy-fallback": true, "ech-config": echConfig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	if got := adapter.echTLS.NextProtos; len(got) != 2 || got[0] != snellECHTLSALPN || got[1] != snellECHTLSLegacyALPN {
		t.Fatalf("NextProtos = %q", got)
	}
}

func TestSnellECHTLSRejectsConflictingALPNAlias(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewSnell(SnellOption{
		Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
		ObfsOpts: map[string]any{
			"mode": "ech-tls", "alpn": snellECHTLSALPN,
			"protocol": "other/1", "ech-config": echConfig,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "values conflict") {
		t.Fatalf("NewSnell() error = %v", err)
	}
}

func TestSnellECHTLSAcceptsPreviousProtocolAlias(t *testing.T) {
	got, err := resolveSnellECHTLSALPN("", snellECHTLSPreviousALPN)
	if err != nil || got != snellECHTLSALPN {
		t.Fatalf("resolveSnellECHTLSALPN() = (%q, %v)", got, err)
	}
}
