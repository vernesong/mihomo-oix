package oix

import (
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	A "github.com/metacubex/mihomo/component/age"
)

func setupSignedFetchTest(t *testing.T) string {
	t.Helper()
	t.Setenv("OIX_PARAMS", "mode=overseas")

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
	return publicKey
}

func TestFetchFromSignatureMatchesServerContract(t *testing.T) {
	t.Run("empty pubkey fails fast without request", func(t *testing.T) {
		t.Setenv("OIX_PARAMS", "mode=overseas")
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

		setoixHTTPClientForTest(t, server.Client())

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
		homeDir := t.TempDir()
		setupSignedFetchTest(t)

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

		setoixHTTPClientForTest(t, server.Client())

		result, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
		if err != nil {
			t.Fatalf("fetchFrom() error = %v", err)
		}
		if result == nil {
			t.Fatal("config is empty")
		}
	})
}

func TestFetchFromForbiddenIsAuthError(t *testing.T) {
	homeDir := t.TempDir()
	setupSignedFetchTest(t)

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

	setoixHTTPClientForTest(t, server.Client())

	_, err := fetchFrom(context.Background(), "token", server.URL, homeDir)
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsAuthError(err) {
		t.Fatalf("HTTP 403 must be treated as auth error, got %v", err)
	}
}

func TestFetchBestAcceptsAPIBaseURLTrailingSlash(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/information":
			http.NotFound(w, r)
		case "/api/v1/managed/flclash/direct":
			encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
			if err != nil {
				t.Error(err)
				return
			}
			config := base64.StdEncoding.EncodeToString(encrypted)
			timestamp := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
			_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())

	oldAPIDomains, oldSpareDomain := ApiDomains, SpareApiDomain
	ApiDomains = server.URL + "/"
	SpareApiDomain = ""
	t.Cleanup(func() {
		ApiDomains, SpareApiDomain = oldAPIDomains, oldSpareDomain
	})

	config, err := fetchBest(context.Background(), "token", apiBaseURLs(), t.TempDir())
	if err != nil {
		t.Fatalf("fetchBest() error = %v", err)
	}
	if config == nil {
		t.Fatal("config is empty")
	}
}

func TestFetchFromRejectsTrailingJSONValue(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
		if err != nil {
			t.Error(err)
			return
		}
		config := base64.StdEncoding.EncodeToString(encrypted)
		timestamp := r.Header.Get("X-Flclash-Timestamp")
		w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."+config))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())

	if _, err := fetchFrom(context.Background(), "token", server.URL, t.TempDir()); err == nil {
		t.Fatal("fetchFrom() accepted a trailing JSON value")
	}
}

func TestDecodeJSONResponseEnforcesSizeLimit(t *testing.T) {
	payload := `{"ret":200}`
	var response apiResponse
	if err := decodeJSONResponse(strings.NewReader(payload), int64(len(payload)), &response); err != nil {
		t.Fatalf("exact-limit response failed: %v", err)
	}
	oversized := payload + strings.Repeat(" ", 2)
	if err := decodeJSONResponse(strings.NewReader(oversized), int64(len(payload)+1), &response); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

func TestAPIResponseForbiddenIsAuthError(t *testing.T) {
	err := apiResponseError("managed config", http.StatusForbidden, "forbidden")
	if !IsAuthError(err) {
		t.Fatalf("ret=403 must be treated as auth error, got %v", err)
	}
}

func TestFetchBestWaitsForNonEmptyConfig(t *testing.T) {
	publicKey := setupSignedFetchTest(t)

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

	setoixHTTPClientForTest(t, &http.Client{})
	config, err := fetchBest(context.Background(), "token", []string{emptyServer.URL, validServer.URL}, t.TempDir())
	if err != nil {
		t.Fatalf("fetchBest() error = %v", err)
	}
	if config == nil {
		t.Fatal("empty response won over valid fallback response")
	}
}

func TestFetchBestTreatsAuthenticationAsAuthoritative(t *testing.T) {
	setupSignedFetchTest(t)

	newServer := func(status int) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/information" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(status)
		}))
		t.Cleanup(server.Close)
		return server
	}
	authServer := newServer(http.StatusUnauthorized)
	authServer2 := newServer(http.StatusUnauthorized)
	nonAuthServer := newServer(http.StatusNotFound)

	setoixHTTPClientForTest(t, &http.Client{})
	_, err := fetchBest(context.Background(), "token", []string{authServer.URL, nonAuthServer.URL}, t.TempDir())
	if !IsAuthError(err) {
		t.Fatalf("mixed endpoint errors = %v, want auth failure", err)
	}

	_, err = fetchBest(context.Background(), "token", []string{authServer.URL, authServer2.URL}, t.TempDir())
	if !IsAuthError(err) {
		t.Fatalf("unanimous endpoint errors = %v, want auth failure", err)
	}
}

func TestFetchBestOnlyPersistsWinningProviderOptions(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	t.Setenv("OIX_PARAMS", "")
	homeDir := t.TempDir()
	if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "alu"}); err != nil {
		t.Fatal(err)
	}
	before, err := GetParamsState(homeDir)
	if err != nil {
		t.Fatal(err)
	}
	loserStarted := make(chan struct{})
	loser := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			_ = json.NewEncoder(w).Encode(informationResponse{Ret: http.StatusOK, Data: &informationData{PlanCode: "iron"}})
			return
		}
		close(loserStarted)
		<-r.Context().Done()
	}))
	t.Cleanup(loser.Close)
	winner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			<-loserStarted
			_ = json.NewEncoder(w).Encode(informationResponse{Ret: http.StatusOK, Data: &informationData{PlanCode: "silver"}})
			return
		}
		writeSignedConfig(t, w, r, publicKey)
	}))
	t.Cleanup(winner.Close)
	setoixHTTPClientForTest(t, &http.Client{})

	config, err := fetchBest(context.Background(), "token", []string{loser.URL, winner.URL}, homeDir)
	if err != nil || config == nil {
		t.Fatalf("fetchBest() = %v, %v", config, err)
	}
	if state, err := GetParamsState(homeDir); err != nil || state != before {
		t.Fatalf("fetch changed options before provider was saved: %+v, %v, want %+v", state, err, before)
	}
	if !saveResult(defaultProviderDir, homeDir, config.data) {
		t.Fatal("save failed")
	}
	config.params.persist(homeDir)
	state, err := GetParamsState(homeDir)
	if err != nil || state.Params != "&mode=premium&tfo=true" || state.DefaultParams != "&mode=premium" {
		t.Fatalf("winning provider options = %+v, %v", state, err)
	}
}
