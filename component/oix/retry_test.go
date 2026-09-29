package oix

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setRetryDelaysForTest(t *testing.T, delays ...time.Duration) {
	t.Helper()
	oldDelays, oldEvery := retryDelays, retryEvery
	retryDelays, retryEvery = delays, time.Hour
	t.Cleanup(func() {
		retryDelays, retryEvery = oldDelays, oldEvery
		ensureRetry.Store(false)
		profileRetry.Store(false)
	})
}

func TestRetryDelayBacksOffThenSettlesHourly(t *testing.T) {
	day := 24 * time.Hour
	for failures, want := range []time.Duration{day, time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour} {
		if got := retryDelay(day, failures); got != want {
			t.Errorf("retryDelay(24h, %d) = %v, want %v", failures, got, want)
		}
	}
	if got := retryDelay(30*time.Second, 1); got != 30*time.Second {
		t.Errorf("a retry must not wait longer than the regular interval, got %v", got)
	}
}

func TestTemporaryFailuresExcludeTheAccount(t *testing.T) {
	for _, err := range []error{ErrAuthFailed, ErrNoToken, ErrNoDomains, ErrNoSubscription, nil} {
		if isTemporary(err) {
			t.Errorf("%v must not be retried early", err)
		}
	}
	for _, err := range []error{&RejectedError{Reason: "timestamp_expired"}, errProfileStale, os.ErrDeadlineExceeded} {
		if !isTemporary(err) {
			t.Errorf("%v must be retried early", err)
		}
	}
}

func rejectingPanel(t *testing.T, rejection string) (*atomic.Bool, *atomic.Int32, string) {
	t.Helper()
	publicKey := setupSignedFetchTest(t)
	var rejecting atomic.Bool
	var requests atomic.Int32
	rejecting.Store(true)
	homeDir := setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if rejecting.Load() {
			if strings.HasPrefix(rejection, "timestamp_") {
				w.Header().Set("X-Managed-Auth-Error", rejection)
				w.WriteHeader(http.StatusForbidden)
			} else {
				w.WriteHeader(http.StatusUnauthorized)
			}
			return
		}
		writeSignedConfig(t, w, r, publicKey)
	}))
	return &rejecting, &requests, homeDir
}

func waitFor(t *testing.T, condition func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return condition()
}

func TestPeriodicUpdateRetriesSoonAfterATemporaryFailure(t *testing.T) {
	rejecting, _, homeDir := rejectingPanel(t, "timestamp_expired")
	setRetryDelaysForTest(t, 20*time.Millisecond)

	if _, err := Ensure(defaultProviderDir, homeDir, false); !IsClockSkew(err) {
		t.Fatalf("Ensure() error = %v, want a clock rejection", err)
	}
	rejecting.Store(false)
	StartPeriodicUpdate(defaultProviderDir, homeDir)

	provider := filepath.Join(homeDir, defaultProviderDir, ProviderFile())
	if !waitFor(t, func() bool { _, err := os.Stat(provider); return err == nil }) {
		t.Fatal("the provider was not fetched soon after the clock recovered")
	}
}

func TestPeriodicUpdateKeepsItsPaceAfterARejectedToken(t *testing.T) {
	_, requests, homeDir := rejectingPanel(t, "")
	setRetryDelaysForTest(t, 20*time.Millisecond)

	if _, err := Ensure(defaultProviderDir, homeDir, false); !IsAuthError(err) {
		t.Fatalf("Ensure() error = %v, want an auth failure", err)
	}
	before := requests.Load()
	StartPeriodicUpdate(defaultProviderDir, homeDir)
	time.Sleep(200 * time.Millisecond)
	if got := requests.Load(); got != before {
		t.Fatalf("a refused token was retried %d times; retrying cannot fix it", got-before)
	}
}

func TestProfileUpdatesRetrySoonAfterFallingBack(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	setRetryDelaysForTest(t, 20*time.Millisecond)
	t.Setenv("OIX_UPDATE_INTERVAL", "86400")
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	ageProfile(t, homeDir)
	panel.status.Store(http.StatusForbidden)
	panel.rejection.Store("timestamp_expired")
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatalf("ComposeProfile() = %v, want the saved copy", err)
	}

	reloads := make(chan struct{}, 8)
	SetProfileReloader(func() { reloads <- struct{}{} })
	t.Cleanup(func() { SetProfileReloader(nil) })
	t.Cleanup(StopProfileUpdates)
	panel.status.Store(http.StatusOK)
	panel.content.Store(strings.Replace(testProfile, "mixed-port: 7777", "mixed-port: 7778", 1))
	StartProfileUpdates()

	select {
	case <-reloads:
	case <-time.After(3 * time.Second):
		t.Fatal("the profile was not refreshed soon after the clock recovered")
	}
}
