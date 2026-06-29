package oix

import (
	"bytes"
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

func resetAgeKeyPairForTest() {
	ageSecretKey = ""
	agePublicKey = ""
	ageKeyInitOnce = sync.Once{}
}
