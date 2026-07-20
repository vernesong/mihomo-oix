package oix

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	A "github.com/metacubex/mihomo/component/age"
)

func TestFetchFromSignatureMatchesServerContract(t *testing.T) {
	t.Run("empty pubkey fails fast without request", func(t *testing.T) {
		t.Setenv("OIX_PARAMS", "lv=1")
		homeDir := t.TempDir()

		oldAppSecret := AppSecret
		oldSecretKey := ageSecretKey
		oldPublicKey := agePublicKey
		AppSecret = "test-secret"
		ageSecretKey = ""
		agePublicKey = ""
		t.Cleanup(func() {
			AppSecret = oldAppSecret
			ageSecretKey = oldSecretKey
			agePublicKey = oldPublicKey
		})

		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
			http.NotFound(w, r)
		}))
		t.Cleanup(server.Close)

		setOixHTTPClientForTest(t, server.Client())

		_, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
		if err == nil {
			t.Fatal("expected error")
		}
		if IsAuthError(err) {
			t.Fatalf("age key failure must not be an auth error, got %v", err)
		}
		if requests != 0 {
			t.Fatalf("expected no requests, got %d", requests)
		}
	})

	t.Run("pubkey signs timestamp dot pubkey", func(t *testing.T) {
		t.Setenv("OIX_PARAMS", "lv=1")
		homeDir := t.TempDir()

		oldAppSecret := AppSecret
		oldSecretKey := ageSecretKey
		oldPublicKey := agePublicKey
		AppSecret = "test-secret"
		secretKey, publicKey, err := A.GenX25519KeyPair()
		if err != nil {
			t.Fatal(err)
		}
		ageSecretKey = secretKey
		agePublicKey = publicKey
		t.Cleanup(func() {
			AppSecret = oldAppSecret
			ageSecretKey = oldSecretKey
			agePublicKey = oldPublicKey
		})

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/information":
				http.NotFound(w, r)
			case "/api/v1/managed/flclash/direct":
				timestamp := r.Header.Get("X-Flclash-Timestamp")
				signature := r.Header.Get("X-Flclash-Signature")
				pubkey := r.Header.Get("X-Flclash-Age-Pubkey")
				if pubkey == "" {
					t.Error("missing X-Flclash-Age-Pubkey header")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if !hmac.Equal([]byte(sign(timestamp+"."+pubkey)), []byte(signature)) {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("forbidden"))
					return
				}
				encrypted, err := A.EncryptBytes([]byte("proxies: []"), pubkey)
				if err != nil {
					t.Error(err)
					return
				}
				config := base64.StdEncoding.EncodeToString(encrypted)
				w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
				_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)

		setOixHTTPClientForTest(t, server.Client())

		result, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
		if err != nil {
			t.Fatalf("fetchFrom() error = %v", err)
		}
		if len(result) == 0 {
			t.Fatal("config is empty")
		}
	})
}

func TestFetchFromForbiddenIsNotAuthError(t *testing.T) {
	t.Setenv("OIX_PARAMS", "lv=1")
	homeDir := t.TempDir()

	oldAppSecret := AppSecret
	oldSecretKey := ageSecretKey
	oldPublicKey := agePublicKey
	AppSecret = "test-secret"
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageSecretKey = secretKey
	agePublicKey = publicKey
	t.Cleanup(func() {
		AppSecret = oldAppSecret
		ageSecretKey = oldSecretKey
		agePublicKey = oldPublicKey
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/information":
			http.NotFound(w, r)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("forbidden"))
		}
	}))
	t.Cleanup(server.Close)

	setOixHTTPClientForTest(t, server.Client())

	_, err = fetchFrom(context.Background(), "token", server.URL, homeDir)
	if err == nil {
		t.Fatal("expected error")
	}
	if IsAuthError(err) {
		t.Fatalf("HTTP 403 must not be treated as auth error, got %v", err)
	}
}

func TestAPIResponseForbiddenIsNotAuthError(t *testing.T) {
	err := apiResponseError("managed config", http.StatusForbidden, "forbidden")
	if IsAuthError(err) {
		t.Fatalf("ret=403 must not be treated as auth error, got %v", err)
	}
}

func TestFetchBestWaitsForNonEmptyConfig(t *testing.T) {
	t.Setenv("OIX_PARAMS", "lv=1")

	oldAppSecret := AppSecret
	oldSecretKey := ageSecretKey
	oldPublicKey := agePublicKey
	AppSecret = "test-secret"
	secretKey, publicKey, err := A.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ageSecretKey = secretKey
	agePublicKey = publicKey
	t.Cleanup(func() {
		AppSecret = oldAppSecret
		ageSecretKey = oldSecretKey
		agePublicKey = oldPublicKey
	})

	emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		timestamp := r.Header.Get("X-Flclash-Timestamp")
		w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK})
	}))
	t.Cleanup(emptyServer.Close)

	validServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		encrypted, encryptErr := A.EncryptBytes([]byte("proxies: []"), publicKey)
		if encryptErr != nil {
			t.Error(encryptErr)
			return
		}
		config := base64.StdEncoding.EncodeToString(encrypted)
		timestamp := r.Header.Get("X-Flclash-Timestamp")
		w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
	}))
	t.Cleanup(validServer.Close)

	setOixHTTPClientForTest(t, &http.Client{})
	config, err := fetchBest(context.Background(), "token", []string{emptyServer.URL, validServer.URL}, t.TempDir())
	if err != nil {
		t.Fatalf("fetchBest() error = %v", err)
	}
	if len(config) == 0 {
		t.Fatal("empty response won over valid fallback response")
	}
}
