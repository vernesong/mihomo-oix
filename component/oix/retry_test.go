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
		StopPeriodicUpdate()
		StopProfileUpdates()
		retryDelays, retryEvery = oldDelays, oldEvery
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
	for _, err := range []error{&rejectedError{Reason: "timestamp_expired"}, errProfileStale, os.ErrDeadlineExceeded} {
		if !isTemporary(err) {
			t.Errorf("%v must be retried early", err)
		}
	}
}

// rejectingPanel answers with status and reason until switched to serving a
// signed config.
func rejectingPanel(t *testing.T, status int, reason string) (rejecting *atomic.Bool, requests *atomic.Int32, homeDir string) {
	t.Helper()
	publicKey := setupSignedFetchTest(t)
	rejecting, requests = new(atomic.Bool), new(atomic.Int32)
	rejecting.Store(true)
	homeDir = setupAccountTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if rejecting.Load() {
			if reason != "" {
				w.Header().Set("X-Managed-Auth-Error", reason)
			}
			w.WriteHeader(status)
			return
		}
		writeSignedConfig(t, w, r, publicKey)
	}))
	return rejecting, requests, homeDir
}

func waitFor(condition func() bool) bool {
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
	rejecting, _, homeDir := rejectingPanel(t, http.StatusForbidden, "timestamp_expired")
	setRetryDelaysForTest(t, 20*time.Millisecond)

	_, err := Ensure(defaultProviderDir, homeDir, false)
	if !isClockSkew(err) {
		t.Fatalf("Ensure() error = %v, want a clock rejection", err)
	}
	rejecting.Store(false)
	StartPeriodicUpdate(defaultProviderDir, homeDir, err)

	provider := filepath.Join(homeDir, defaultProviderDir, ProviderFile())
	if !waitFor(func() bool { _, err := os.Stat(provider); return err == nil }) {
		t.Fatal("the provider was not fetched soon after the clock recovered")
	}
}

func TestPeriodicUpdateKeepsItsPaceAfterARejectedToken(t *testing.T) {
	_, requests, homeDir := rejectingPanel(t, http.StatusUnauthorized, "")
	setRetryDelaysForTest(t, 20*time.Millisecond)

	_, err := Ensure(defaultProviderDir, homeDir, false)
	if !IsAuthError(err) {
		t.Fatalf("Ensure() error = %v, want an auth failure", err)
	}
	before := requests.Load()
	StartPeriodicUpdate(defaultProviderDir, homeDir, err)
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
	panel.status.Store(http.StatusOK)
	panel.content.Store(strings.Replace(testProfile, "mixed-port: 7777", "mixed-port: 7778", 1))
	StartProfileUpdates()

	select {
	case <-reloads:
	case <-time.After(3 * time.Second):
		t.Fatal("the profile was not refreshed soon after the clock recovered")
	}
}
