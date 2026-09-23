package outbound

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"
)

func TestSnellReuseDialHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	adapter := &Snell{
		reuse: true,
		pool: snell.NewPool(func(factoryCtx context.Context) (*snell.Snell, error) {
			close(started)
			select {
			case <-factoryCtx.Done():
				return nil, factoryCtx.Err()
			case <-time.After(time.Second):
				return nil, errors.New("pool factory did not receive caller cancellation")
			}
		}),
	}
	result := make(chan error, 1)
	go func() {
		_, err := adapter.DialContext(ctx, &C.Metadata{})
		result <- err
	}()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("pooled dial remained blocked after cancellation")
	}
}

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

func TestSnellECHTLSReplacesNoneFingerprint(t *testing.T) {
	echConfig, _, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		obfs string
		top  string
		want string
	}{
		{name: "default", want: defaultSnellECHTLSClientFingerprint},
		{name: "obfs none", obfs: "none", want: defaultSnellECHTLSClientFingerprint},
		{name: "proxy none", top: "NONE", want: defaultSnellECHTLSClientFingerprint},
		{name: "explicit", obfs: "firefox", want: "firefox"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obfs := map[string]any{"mode": "ech-tls", "ech-config": echConfig}
			if tc.obfs != "" {
				obfs["client-fingerprint"] = tc.obfs
			}
			adapter, err := NewSnell(SnellOption{
				Name: "snell", Server: "origin.example.com", Port: 443, Psk: "password", Version: 4,
				ClientFingerprint: tc.top, ObfsOpts: obfs,
			})
			if err != nil {
				t.Fatalf("NewSnell() error = %v", err)
			}
			defer adapter.Close()
			if got := adapter.echTLS.ClientFingerprint; got != tc.want {
				t.Fatalf("ClientFingerprint = %q, want %q", got, tc.want)
			}
		})
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
