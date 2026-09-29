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

		_, err := fetchFrom(context.Background(), "token", server.URL)
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
		setupSignedFetchTest(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case managedConfigPath:
				timestamp := r.Header.Get("X-Flclash-Timestamp")
				signature := r.Header.Get("X-Flclash-Signature")
				pubkey := r.Header.Get("X-Flclash-Age-Pubkey")
				if pubkey == "" {
					t.Error("missing X-Flclash-Age-Pubkey header")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if got := r.Header.Get("X-oixCloud-Client"); got != "openclash" {
					t.Errorf("X-oixCloud-Client = %q, want openclash", got)
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

		result, err := fetchFrom(context.Background(), "token", server.URL)
		if err != nil {
			t.Fatalf("fetchFrom() error = %v", err)
		}
		if result == nil {
			t.Fatal("config is empty")
		}
	})
}

func TestFetchBestAcceptsAPIBaseURLTrailingSlash(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case managedConfigPath:
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

	config, err := fetchBest(context.Background(), "token", apiBaseURLs())
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

	if _, err := fetchFrom(context.Background(), "token", server.URL); err == nil {
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
		timestamp := r.Header.Get("X-Flclash-Timestamp")
		w.Header().Set("X-Flclash-Response-Signature", sign(timestamp+"."))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK})
	}))
	t.Cleanup(emptyServer.Close)

	validServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	config, err := fetchBest(context.Background(), "token", []string{emptyServer.URL, validServer.URL})
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}))
		t.Cleanup(server.Close)
		return server
	}
	authServer := newServer(http.StatusUnauthorized)
	authServer2 := newServer(http.StatusUnauthorized)
	nonAuthServer := newServer(http.StatusNotFound)

	setoixHTTPClientForTest(t, &http.Client{})
	_, err := fetchBest(context.Background(), "token", []string{authServer.URL, nonAuthServer.URL})
	if !IsAuthError(err) {
		t.Fatalf("mixed endpoint errors = %v, want auth failure", err)
	}

	_, err = fetchBest(context.Background(), "token", []string{authServer.URL, authServer2.URL})
	if !IsAuthError(err) {
		t.Fatalf("unanimous endpoint errors = %v, want auth failure", err)
	}
}

func setClientForTest(t *testing.T, id string) {
	t.Helper()
	clientMu.Lock()
	previous := clientID
	clientID = id
	clientMu.Unlock()
	t.Cleanup(func() {
		clientMu.Lock()
		clientID = previous
		clientMu.Unlock()
	})
}

func TestFetchFromDeclaresConfiguredClient(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T)
		wantID  string
		wantUA  string
		wantErr bool
	}{
		{name: "default", setup: func(t *testing.T) { setClientForTest(t, "") }, wantID: "openclash", wantUA: "OpenClash for oixCloud"},
		{name: "set", setup: func(t *testing.T) {
			setClientForTest(t, "")
			if err := SetClient(" OixClash "); err != nil {
				t.Fatal(err)
			}
		}, wantID: "oixclash", wantUA: "oixClash"},
		{name: "environment", setup: func(t *testing.T) {
			setClientForTest(t, "")
			t.Setenv("OIX_CLIENT", "oixclash")
		}, wantID: "oixclash", wantUA: "oixClash"},
		{name: "unknown environment falls back", setup: func(t *testing.T) {
			setClientForTest(t, "")
			t.Setenv("OIX_CLIENT", "someone-else")
		}, wantID: "openclash", wantUA: "OpenClash for oixCloud"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupSignedFetchTest(t)
			tc.setup(t)

			var gotID, gotUA string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotID = r.Header.Get("X-oixCloud-Client")
				gotUA = r.Header.Get("User-Agent")
				w.WriteHeader(http.StatusForbidden)
			}))
			t.Cleanup(server.Close)
			setoixHTTPClientForTest(t, server.Client())

			_, _ = fetchFrom(context.Background(), "token", server.URL)
			if gotID != tc.wantID || gotUA != tc.wantUA {
				t.Fatalf("client = %q / %q, want %q / %q", gotID, gotUA, tc.wantID, tc.wantUA)
			}
		})
	}
}

func TestSetClientRejectsUnknownClient(t *testing.T) {
	setClientForTest(t, "oixclash")
	if err := SetClient("anywhere"); err == nil {
		t.Fatal("SetClient accepted a client the panel does not know")
	}
	if id, _ := currentClient(); id != "oixclash" {
		t.Fatalf("rejected SetClient changed the client to %q", id)
	}
}
