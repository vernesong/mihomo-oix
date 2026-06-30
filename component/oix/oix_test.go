package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

const testAgePayload = "-----BEGIN AGE ENCRYPTED FILE-----\nmock\n-----END AGE ENCRYPTED FILE-----\n"

func withOIXTestState(t *testing.T, fn func()) {
	t.Helper()

	oldAppSecret := AppSecret
	oldAgePublicKey := agePublicKey
	oldHTTPClient := oixHTTPClient
	oldHTTPOnce := oixHTTPOnce

	AppSecret = "test-secret"
	agePublicKey = "test-age-public-key"
	oixHTTPClient = http.DefaultClient
	oixHTTPOnce = sync.Once{}
	oixHTTPOnce.Do(func() {})

	t.Cleanup(func() {
		AppSecret = oldAppSecret
		agePublicKey = oldAgePublicKey
		oixHTTPClient = oldHTTPClient
		oixHTTPOnce = oldHTTPOnce
	})

	fn()
}

func TestFetchFromRequiresSignatureToCoverProviderPayload(t *testing.T) {
	withOIXTestState(t, func() {
		providerB64 := base64.StdEncoding.EncodeToString([]byte(testAgePayload))

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ts := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(ts+"."+"" /* legacy config-only signature */))
			_ = json.NewEncoder(w).Encode(apiResponse{Provider: providerB64})
		}))
		defer server.Close()

		if _, err := fetchFrom(context.Background(), "token", server.URL); err == nil {
			t.Fatal("expected provider payload not covered by response signature to be rejected")
		}
	})
}

func TestFetchFromRequiresSignatureForProviderAgePayload(t *testing.T) {
	withOIXTestState(t, func() {
		providerB64 := base64.StdEncoding.EncodeToString([]byte(testAgePayload))

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(apiResponse{Provider: providerB64})
		}))
		defer server.Close()

		if _, err := fetchFrom(context.Background(), "token", server.URL); err == nil {
			t.Fatal("expected unsigned age-armored provider payload to be rejected")
		}
	})
}

func TestFetchFromReadsBodyAfterHeadersAreFlushed(t *testing.T) {
	withOIXTestState(t, func() {
		providerB64 := base64.StdEncoding.EncodeToString([]byte(testAgePayload))

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ts := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(ts+"."+""+"."+providerB64))
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(25 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(apiResponse{Provider: providerB64})
		}))
		defer server.Close()

		result, err := fetchFrom(context.Background(), "token", server.URL)
		if err != nil {
			t.Fatalf("fetchFrom returned error after delayed body: %v", err)
		}
		if string(result.Provider) != testAgePayload {
			t.Fatalf("expected provider payload, got %q", string(result.Provider))
		}
	})
}

func TestFetchBestSkipsEmptyResultForSpareDomain(t *testing.T) {
	withOIXTestState(t, func() {
		emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(apiResponse{})
		}))
		defer emptyServer.Close()

		providerB64 := base64.StdEncoding.EncodeToString([]byte(testAgePayload))
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ts := r.Header.Get("X-Flclash-Timestamp")
			w.Header().Set("X-Flclash-Response-Signature", sign(ts+"."+""+"."+providerB64))
			_ = json.NewEncoder(w).Encode(apiResponse{Provider: providerB64})
		}))
		defer providerServer.Close()

		result, err := fetchBest("token", []string{emptyServer.URL, providerServer.URL})
		if err != nil {
			t.Fatalf("fetchBest returned error: %v", err)
		}
		if string(result.Provider) != testAgePayload {
			t.Fatalf("expected provider from spare domain, got %q", string(result.Provider))
		}
	})
}

func TestFetchFromRejectsNonZeroAPIRet(t *testing.T) {
	withOIXTestState(t, func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(apiResponse{
				Ret: 1,
				Msg: "token expired",
			})
		}))
		defer server.Close()

		result, err := fetchFrom(context.Background(), "token", server.URL)
		if err == nil {
			t.Fatalf("expected non-zero API ret to fail, got result %#v", result)
		}
	})
}

func TestFetchBestPreservesAuthErrorAcrossRacedFailures(t *testing.T) {
	withOIXTestState(t, func() {
		authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "denied", http.StatusUnauthorized)
		}))
		defer authServer.Close()

		notFoundServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer notFoundServer.Close()

		_, err := fetchBest("token", []string{authServer.URL, notFoundServer.URL})
		if !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("expected auth failure to dominate raced errors, got %v", err)
		}
	})
}
