package oix

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/metacubex/mihomo/component/age"
)

func TestAgeKeyPairPersistsPerHomeDir(t *testing.T) {
	homeDir := t.TempDir()

	resetAgeKeyPairForTest()
	secretKey, publicKey := ageKeyPair(homeDir)
	if secretKey == "" || publicKey == "" {
		t.Fatal("ageKeyPair returned an empty key pair")
	}

	keyPath := filepath.Join(homeDir, ageSecretKeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat persisted key: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("persisted key mode = %o, want 600", got)
	}

	resetAgeKeyPairForTest()
	restoredSecretKey, restoredPublicKey := ageKeyPair(homeDir)
	if restoredSecretKey != secretKey || restoredPublicKey != publicKey {
		t.Fatalf("ageKeyPair did not restore persisted key")
	}
}

func TestProviderConfigReusesAgeSecretForCachedProvider(t *testing.T) {
	homeDir := t.TempDir()

	resetAgeKeyPairForTest()
	config := ProviderConfig(homeDir, "proxy_provider/oixCloud", nil)
	secretKey, ok := config["age-secret-key"].(string)
	if !ok || secretKey == "" {
		t.Fatal("ProviderConfig did not provide an age-secret-key")
	}
	_, publicKey := ageKeyPair(homeDir)

	providerPayload := []byte("proxies: []\n")
	encryptedProvider, err := age.EncryptBytes(providerPayload, publicKey)
	if err != nil {
		t.Fatalf("encrypt provider payload: %v", err)
	}

	resetAgeKeyPairForTest()
	restoredConfig := ProviderConfig(homeDir, "proxy_provider/oixCloud", nil)
	restoredSecretKey, ok := restoredConfig["age-secret-key"].(string)
	if !ok || restoredSecretKey == "" {
		t.Fatal("restored ProviderConfig did not provide an age-secret-key")
	}
	if restoredSecretKey != secretKey {
		t.Fatal("ProviderConfig generated a new age-secret-key instead of reusing the persisted one")
	}

	decryptedProvider, err := age.DecryptBytes(encryptedProvider, restoredSecretKey)
	if err != nil {
		t.Fatalf("decrypt cached provider payload: %v", err)
	}
	if !bytes.Equal(decryptedProvider, providerPayload) {
		t.Fatalf("decrypted provider = %q, want %q", decryptedProvider, providerPayload)
	}
}

func TestEnsureSavesProviderWithPersistentAgeSecret(t *testing.T) {
	homeDir := t.TempDir()
	providerPayload := []byte("proxies:\n  - name: fake\n    type: direct\n")
	const testAppSecret = "test-app-secret"

	resetOixPackageStateForTest()
	AppSecret = testAppSecret
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/managed/flclash/direct" {
			t.Fatalf("request path = %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("unexpected authorization header")
		}
		if r.Header.Get("X-Flclash-Age-Pubkey") == "" {
			t.Fatalf("missing age public key header")
		}

		ts := r.Header.Get("X-Flclash-Timestamp")
		configB64 := ""
		w.Header().Set("X-Flclash-Response-Signature", sign(ts+"."+configB64))
		_ = json.NewEncoder(w).Encode(apiResponse{
			Ret:      1,
			Provider: base64.StdEncoding.EncodeToString(providerPayload),
		})
	}))
	defer server.Close()

	oixHTTPClient = server.Client()
	oixHTTPOnce.Do(func() {})
	ApiDomains = server.URL
	t.Setenv("OIX_TOKEN", "test-token")
	t.Setenv("OIX_PROVIDER_NAME", "")

	ok, err := Ensure("proxy_provider", homeDir, false)
	if err != nil {
		t.Fatalf("Ensure returned error: %v", err)
	}
	if !ok {
		t.Fatal("Ensure returned ok=false")
	}

	providerPath := filepath.Join(homeDir, "proxy_provider", defaultProviderFile)
	encryptedProvider, err := os.ReadFile(providerPath)
	if err != nil {
		t.Fatalf("read saved provider: %v", err)
	}

	resetAgeKeyPairForTest()
	config := ProviderConfig(homeDir, "proxy_provider/oixCloud", nil)
	secretKey, ok := config["age-secret-key"].(string)
	if !ok || secretKey == "" {
		t.Fatal("ProviderConfig did not restore a persisted age-secret-key")
	}

	decryptedProvider, err := age.DecryptBytes(encryptedProvider, secretKey)
	if err != nil {
		t.Fatalf("decrypt saved provider: %v", err)
	}
	if !bytes.Equal(decryptedProvider, providerPayload) {
		t.Fatalf("decrypted provider = %q, want %q", decryptedProvider, providerPayload)
	}
}

func resetAgeKeyPairForTest() {
	ageSecretKey = ""
	agePublicKey = ""
	ageKeyInitOnce = sync.Once{}
}

func resetOixPackageStateForTest() {
	resetAgeKeyPairForTest()
	AppSecret = ""
	ApiDomains = ""
	ProfileKey = ""
	oixProviderName = ""
	periodicCancel = nil
	periodicDir = ""
	periodicHome = ""
	oixHTTPClient = nil
	oixHTTPOnce = sync.Once{}
}
