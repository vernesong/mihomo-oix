package oix

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func setupAccountTest(t *testing.T, handler http.Handler) string {
	t.Helper()
	StopPeriodicUpdate()
	t.Setenv("OIX_TOKEN", "")
	t.Setenv("OIX_PARAMS", "")
	t.Setenv("OIX_UPDATE_INTERVAL", "86400")
	homeDir := t.TempDir()
	oldDir, oldHome := providerPaths()
	oldToken := CurrentToken()
	oldEnsured := oixdns.IsEnsured()
	oldAPIDomains, oldSpareDomain := ApiDomains, SpareApiDomain
	SetProviderPaths(defaultProviderDir, homeDir)
	SetToken("previous-account")
	t.Cleanup(func() {
		StopPeriodicUpdate()
		SetProviderPaths(oldDir, oldHome)
		SetToken(oldToken)
		ApiDomains, SpareApiDomain = oldAPIDomains, oldSpareDomain
		if oldEnsured {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
	})

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())
	ApiDomains, SpareApiDomain = server.URL, ""
	return homeDir
}

func writeSignedConfig(t *testing.T, w http.ResponseWriter, r *http.Request, publicKey string) {
	t.Helper()
	encrypted, err := A.EncryptBytes([]byte("proxies: []"), publicKey)
	if err != nil {
		t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	config := base64.StdEncoding.EncodeToString(encrypted)
	w.Header().Set("X-Flclash-Response-Signature", sign(r.Header.Get("X-Flclash-Timestamp")+"."+config))
	_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
}

func TestFailedLoginPreservesActiveAccount(t *testing.T) {
	for _, failure := range []string{"authentication", "provider write"} {
		t.Run(failure, func(t *testing.T) {
			publicKey := setupSignedFetchTest(t)
			homeDir := setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/information" {
					_ = json.NewEncoder(w).Encode(informationResponse{Ret: http.StatusOK, Data: &informationData{PlanCode: "iron"}})
					return
				}
				if failure == "authentication" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				writeSignedConfig(t, w, r, publicKey)
			}))
			if failure == "provider write" {
				if err := os.WriteFile(filepath.Join(homeDir, defaultProviderDir), []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := effectiveParamsForPlan(homeDir, planIdentity{Code: "silver"}); err != nil {
				t.Fatal(err)
			}
			before, err := GetParamsState(homeDir)
			if err != nil {
				t.Fatal(err)
			}
			oldDomain, oldAddress := oixdns.ManagedNodesDomain(), oixdns.ManagedDNSAddr()
			oixdns.ConfigureManagedDNS("account.example", "127.0.0.1:1053")
			t.Cleanup(func() { oixdns.ConfigureManagedDNS(oldDomain, oldAddress) })
			oixdns.SetEnsured()

			if ok, err := Login("candidate-account"); ok || err == nil {
				t.Fatalf("Login() = %v, %v, want %s failure", ok, err, failure)
			}
			if got := CurrentToken(); got != "previous-account" {
				t.Fatalf("active token = %q, want previous-account", got)
			}
			if !oixdns.IsEnsured() || oixdns.ManagedDNSAddr() != "127.0.0.1:1053" {
				t.Fatal("failed candidate login changed the active account's DNS")
			}
			if after, err := GetParamsState(homeDir); err != nil || after != before {
				t.Fatalf("options after failed login = %+v, %v, want %+v", after, err, before)
			}
		})
	}
}

func TestLoginPublishesTokenOnlyAfterProviderIsSaved(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	started := make(chan struct{})
	release := make(chan struct{})
	homeDir := setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer new-account" {
			t.Errorf("request token = %q, want candidate token", got)
		}
		close(started)
		<-release
		writeSignedConfig(t, w, r, publicKey)
	}))
	// Release the request on assertion failures before closing the test server.
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	finished := make(chan error, 1)
	go func() {
		ok, err := Login("new-account")
		if err == nil && !ok {
			err = ErrNoSubscription
		}
		finished <- err
	}()
	<-started
	if got := CurrentToken(); got != "previous-account" {
		t.Errorf("pending login exposed token %q", got)
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if got := CurrentToken(); got != "new-account" {
		t.Fatalf("successful login token = %q", got)
	}
	if token, err := os.ReadFile(tokenFilePath(homeDir)); err != nil || string(token) != "new-account" {
		t.Fatalf("persisted token = %q, %v", token, err)
	}
	if _, err := os.Stat(filepath.Join(homeDir, defaultProviderDir, ProviderFile())); err != nil {
		t.Fatalf("successful login has no provider: %v", err)
	}
}

func TestLogoutSuppressesAutomaticTokenReload(t *testing.T) {
	for _, source := range []string{"environment", "disk"} {
		t.Run(source, func(t *testing.T) {
			homeDir := setupAccountTest(t, http.NotFoundHandler())
			if source == "environment" {
				t.Setenv("OIX_TOKEN", "environment-account")
			}
			Logout()
			if source == "disk" {
				// A configuration reload must not restore a leftover credential when
				// logout could not remove it or an older process recreated it.
				if err := persistToken(homeDir, "previous-account"); err != nil {
					t.Fatal(err)
				}
			}
			LoadPersistedToken(homeDir)
			if HasToken() || CurrentToken() != "" {
				t.Fatalf("logout restored the %s token", source)
			}
			SetToken("explicit-account")
			if got := getToken(); got != "explicit-account" {
				t.Fatalf("explicit login token = %q", got)
			}
		})
	}
}

func TestForceUpdateRejectsEmptySubscription(t *testing.T) {
	setupSignedFetchTest(t)
	setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Flclash-Response-Signature", sign(r.Header.Get("X-Flclash-Timestamp")+"."))
		_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK})
	}))
	if err := ForceUpdate(); !errors.Is(err, ErrNoSubscription) {
		t.Fatalf("ForceUpdate() = %v, want ErrNoSubscription", err)
	}
}

func TestPeriodicUpdateReportsProviderWriteFailure(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	homeDir := setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		writeSignedConfig(t, w, r, publicKey)
	}))
	if err := os.WriteFile(filepath.Join(homeDir, defaultProviderDir), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPeriodicUpdate(context.Background(), defaultProviderDir, homeDir); err == nil {
		t.Fatal("periodic update reported success without saving the provider")
	}
}

func TestLogoutDuringLoginLeavesNoAccountState(t *testing.T) {
	publicKey := setupSignedFetchTest(t)
	started := make(chan struct{})
	release := make(chan struct{})
	homeDir := setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/information" {
			http.NotFound(w, r)
			return
		}
		close(started)
		<-release
		writeSignedConfig(t, w, r, publicKey)
	}))
	loginDone := make(chan error, 1)
	go func() {
		_, err := Login("new-account")
		loginDone <- err
	}()
	<-started
	logoutStarted := make(chan struct{})
	logoutDone := make(chan struct{})
	go func() {
		close(logoutStarted)
		Logout()
		close(logoutDone)
	}()
	<-logoutStarted
	// The network response is blocked, so logout must wait for the candidate
	// transaction instead of clearing state that the candidate could recreate.
	select {
	case <-logoutDone:
		t.Error("logout completed before the pending login transaction")
	case <-time.After(50 * time.Millisecond):
	}
	if got := CurrentToken(); got != "previous-account" {
		t.Errorf("concurrent logout changed the pending transaction's token: %q", got)
	}
	close(release)
	if err := <-loginDone; err != nil {
		t.Fatal(err)
	}
	<-logoutDone
	if HasToken() || oixdns.IsEnsured() {
		t.Fatal("login restored account state after logout")
	}
	for _, path := range []string{tokenFilePath(homeDir), filepath.Join(homeDir, defaultProviderDir, ProviderFile())} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("account file remains after logout: %s: %v", path, err)
		}
	}
	periodicMu.RLock()
	running := periodicCancel != nil
	periodicMu.RUnlock()
	if running {
		t.Fatal("login restarted periodic updates after logout")
	}
}
