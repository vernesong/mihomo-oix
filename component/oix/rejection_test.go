package oix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func TestFetchFromSeparatesRequestRejectionsFromTokenFailures(t *testing.T) {
	cases := []struct {
		status    int
		reason    string
		wantAuth  bool
		wantClock bool
	}{
		{http.StatusForbidden, "timestamp_expired", false, true},
		{http.StatusForbidden, "timestamp_invalid", false, true},
		{http.StatusForbidden, "signature_mismatch", false, false},
		{http.StatusForbidden, "age_pubkey_invalid", false, false},
		{http.StatusForbidden, "server_unconfigured", false, false},
		{http.StatusForbidden, "dedicated_token_required", true, false},
		{http.StatusForbidden, "", true, false},
		{http.StatusUnauthorized, "timestamp_expired", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			setupSignedFetchTest(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.reason != "" {
					w.Header().Set("X-Managed-Auth-Error", tc.reason)
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(server.Close)
			setoixHTTPClientForTest(t, server.Client())

			_, err := fetchFrom(context.Background(), "token", server.URL)
			if IsAuthError(err) != tc.wantAuth || IsClockSkew(err) != tc.wantClock {
				t.Fatalf("HTTP %d %q: error = %v, auth=%v clock=%v", tc.status, tc.reason, err, IsAuthError(err), IsClockSkew(err))
			}
			if !tc.wantAuth && !errors.Is(err, ErrRequestRejected) {
				t.Fatalf("error = %v, want a request rejection", err)
			}
			if tc.wantClock && !strings.Contains(err.Error(), "check the device clock") {
				t.Fatalf("error %q does not point at the clock", err)
			}
		})
	}
}

// A router that boots before NTP has synced must keep its nodes and retry
// instead of treating the panel's timestamp check as a revoked token.
func TestEnsureKeepsTheProviderWhenTheClockIsOff(t *testing.T) {
	homeDir := setupEnsureFetchFailure(t, http.StatusForbidden, "timestamp_expired")

	_, err := Ensure(defaultProviderDir, homeDir, true)
	if IsAuthError(err) || !IsClockSkew(err) {
		t.Fatalf("Ensure() error = %v, want a clock rejection", err)
	}
	if !oixdns.IsEnsured() {
		t.Fatal("the cached provider was dropped because of the clock")
	}
}

func TestComposeProfileSurvivesTheClockBeingOff(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	panel.status.Store(http.StatusForbidden)
	panel.rejection.Store("timestamp_expired")

	if _, err := ComposeProfile([]byte(testOverlay)); IsAuthError(err) || !IsClockSkew(err) {
		t.Fatalf("no saved copy: error = %v, want a clock rejection", err)
	}

	panel.status.Store(http.StatusOK)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	ageProfile(t, homeDir)
	panel.status.Store(http.StatusForbidden)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatalf("saved copy: error = %v, want the saved copy", err)
	}
	if !oixdns.IsEnsured() {
		t.Fatal("managed node DNS was switched off because of the clock")
	}
}
