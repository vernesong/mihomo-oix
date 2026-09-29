package oix

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/oix/oixdns"
	C "github.com/metacubex/mihomo/constant"

	"gopkg.in/yaml.v3"
)

const testProfile = `proxies:
  - {name: node-a, type: direct}
proxy-groups:
  - {name: select, type: select, proxies: [node-a]}
rules:
  - MATCH,select
mixed-port: 7777
tun: {enable: true, stack: system}
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver: [223.5.5.5]
  nameserver-policy:
    '+.nodes.example': 127.0.0.1:5353
`

const testOverlay = `mixed-port: 7890
tun: {enable: false}
dns:
  listen: 0.0.0.0:7874
  enhanced-mode: redir-host
  nameserver-policy:
    '+.lan': 127.0.0.1:53
`

type profilePanel struct {
	requests  atomic.Int32
	status    atomic.Int32
	rejection atomic.Value
	content   atomic.Value
}

func (p *profilePanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	if status := int(p.status.Load()); status != http.StatusOK {
		if reason, _ := p.rejection.Load().(string); reason != "" {
			w.Header().Set("X-Managed-Auth-Error", reason)
		}
		w.WriteHeader(status)
		return
	}
	var config string
	if content := p.content.Load().(string); content != "" {
		encrypted, err := A.EncryptBytes([]byte(content), r.Header.Get("X-Flclash-Age-Pubkey"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		config = base64.StdEncoding.EncodeToString(encrypted)
	}
	w.Header().Set("X-Flclash-Response-Signature", sign(r.Header.Get("X-Flclash-Timestamp")+"."+config))
	_ = json.NewEncoder(w).Encode(apiResponse{Ret: http.StatusOK, Config: config})
}

func setupProfileTest(t *testing.T) (*profilePanel, string) {
	t.Helper()
	setupSignedFetchTest(t)
	homeDir := t.TempDir()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(homeDir)
	t.Setenv("OIX_TOKEN", "")
	oldToken := CurrentToken()
	SetToken("profile-token")
	oldNodesDomain := oixdns.NodesDomains
	oixdns.NodesDomains = "nodes.example"
	oldEnsured := oixdns.IsEnsured()
	SetProfileMode(true)
	t.Cleanup(func() {
		removeProfile()
		SetProfileMode(false)
		C.SetHomeDir(oldHome)
		SetToken(oldToken)
		oixdns.NodesDomains = oldNodesDomain
		oixdns.ResetManagedDNS()
		if oldEnsured {
			oixdns.SetEnsured()
		} else {
			oixdns.ClearEnsured()
		}
	})

	panel := &profilePanel{}
	panel.status.Store(http.StatusOK)
	panel.content.Store(testProfile)
	servePanelForTest(t, panel)
	return panel, homeDir
}

func ageProfile(t *testing.T, homeDir string) {
	t.Helper()
	old := time.Now().Add(-2 * profileFreshness)
	if err := os.Chtimes(filepath.Join(homeDir, profileFileName), old, old); err != nil {
		t.Fatal(err)
	}
}

func TestComposeProfileAppliesLocalOverrides(t *testing.T) {
	_, homeDir := setupProfileTest(t)

	composed, err := ComposeProfile([]byte(testOverlay))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(composed, &got); err != nil {
		t.Fatal(err)
	}
	dns := got["dns"].(map[string]any)
	policy := dns["nameserver-policy"].(map[string]any)
	tun := got["tun"].(map[string]any)
	switch {
	case got["mixed-port"] != 7890:
		t.Errorf("mixed-port = %v, want the local 7890", got["mixed-port"])
	case tun["enable"] != false || tun["stack"] != "system":
		t.Errorf("tun = %v, want enable overridden and stack kept", tun)
	case dns["enhanced-mode"] != "redir-host" || dns["listen"] != "0.0.0.0:7874" || dns["enable"] != true:
		t.Errorf("dns = %v, want local listener and mode over the managed DNS", dns)
	case policy["+.nodes.example"] != "127.0.0.1:5353" || policy["+.lan"] != "127.0.0.1:53":
		t.Errorf("nameserver-policy = %v, want both entries", policy)
	case len(got["rules"].([]any)) != 1 || len(got["proxies"].([]any)) != 1:
		t.Errorf("managed nodes and rules were not kept: %v", got)
	}

	saved, err := os.ReadFile(filepath.Join(homeDir, profileFileName))
	if err != nil {
		t.Fatal(err)
	}
	data, owned := bytes.CutPrefix(saved, profileHeader("profile-token"))
	if !owned || !isAgeArmored(data) || bytes.Contains(saved, []byte("node-a")) || bytes.Contains(saved, []byte("profile-token")) {
		t.Fatal("the saved profile must stay encrypted and name its token only by a digest")
	}
	if info, _ := os.Stat(filepath.Join(homeDir, profileFileName)); info.Mode().Perm() != 0o600 {
		t.Fatalf("profile permissions = %v", info.Mode().Perm())
	}
	if !oixdns.IsEnsured() || oixdns.ManagedDNSAddr() != "127.0.0.1:5353" {
		t.Fatal("managed node DNS was not taken from the profile")
	}
}

func TestComposeProfileReusesAFreshCopy(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	for range 2 {
		if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
			t.Fatal(err)
		}
	}
	if got := panel.requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1 while the saved copy is fresh", got)
	}
	ageProfile(t, homeDir)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	if got := panel.requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want a fetch once the copy is stale", got)
	}
}

func TestSavedProfileServesOnlyItsOwnToken(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	SetToken("another-account")
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	if got := panel.requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want a fetch for the other account", got)
	}

	ageProfile(t, homeDir)
	SetToken("third-account")
	panel.status.Store(http.StatusForbidden)
	panel.rejection.Store("timestamp_expired")
	if _, err := ComposeProfile([]byte(testOverlay)); !isClockSkew(err) {
		t.Fatalf("error = %v, want the rejection rather than another account's copy", err)
	}
}

func TestProfileSavedInTheFutureIsStale(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filepath.Join(homeDir, profileFileName), future, future); err != nil {
		t.Fatal(err)
	}
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	if got := panel.requests.Load(); got != 2 {
		t.Fatalf("requests = %d, want a fetch when the clock went back", got)
	}
}

func TestComposeProfileTakesThePanelVerdictOnTheToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		panel, homeDir := setupProfileTest(t)
		if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
			t.Fatal(err)
		}
		ageProfile(t, homeDir)
		panel.status.Store(int32(status))

		if _, err := ComposeProfile([]byte(testOverlay)); !IsAuthError(err) {
			t.Fatalf("HTTP %d: error = %v, want an auth error despite the saved copy", status, err)
		}
		if oixdns.IsEnsured() {
			t.Fatalf("HTTP %d: managed node DNS stayed on for a revoked token", status)
		}
	}
}

func TestComposeProfileNeedsAPlanAndAToken(t *testing.T) {
	panel, _ := setupProfileTest(t)
	panel.content.Store("")
	if _, err := ComposeProfile([]byte(testOverlay)); !errors.Is(err, ErrNoSubscription) {
		t.Fatalf("no plan: error = %v", err)
	}

	SetToken("")
	if _, err := ComposeProfile([]byte(testOverlay)); !errors.Is(err, ErrNoToken) {
		t.Fatalf("no token: error = %v", err)
	}
}

func TestComposeProfileRejectsAnInvalidOverlay(t *testing.T) {
	setupProfileTest(t)
	if _, err := ComposeProfile([]byte("mixed-port: [")); err == nil || !strings.Contains(err.Error(), "local config") {
		t.Fatalf("error = %v, want a local config error", err)
	}
}

func TestRefreshProfileReportsChanges(t *testing.T) {
	panel, _ := setupProfileTest(t)
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	if changed, err := refreshProfile(t.Context()); err != nil || changed {
		t.Fatalf("same content: changed=%v err=%v", changed, err)
	}
	panel.content.Store(strings.Replace(testProfile, "mixed-port: 7777", "mixed-port: 7778", 1))
	if changed, err := refreshProfile(t.Context()); err != nil || !changed {
		t.Fatalf("new content: changed=%v err=%v", changed, err)
	}
}

func TestProfileLoginSwitchesAccountsOnlyAfterFetching(t *testing.T) {
	panel, homeDir := setupProfileTest(t)
	SetToken("previous-account")

	panel.status.Store(http.StatusUnauthorized)
	if ok, err := Login("candidate"); ok || !IsAuthError(err) {
		t.Fatalf("Login() = %v, %v", ok, err)
	}
	if CurrentToken() != "previous-account" {
		t.Fatal("a refused candidate replaced the active account")
	}

	panel.status.Store(http.StatusOK)
	if ok, err := Login("candidate"); !ok || err != nil {
		t.Fatalf("Login() = %v, %v", ok, err)
	}
	if CurrentToken() != "candidate" {
		t.Fatal("the accepted candidate is not active")
	}
	if saved, err := os.ReadFile(filepath.Join(homeDir, ".oix_token")); err != nil || string(saved) != "candidate" {
		t.Fatalf("persisted token = %q, %v", saved, err)
	}

	Logout()
	for _, name := range []string{profileFileName, ".oix_token"} {
		if _, err := os.Stat(filepath.Join(homeDir, name)); !os.IsNotExist(err) {
			t.Fatalf("logout left %s behind", name)
		}
	}
	composed, err := ComposeProfile([]byte(testOverlay))
	if err != nil || string(composed) != testOverlay {
		t.Fatalf("after logout: %q, %v; want the local config alone", composed, err)
	}
}

func TestStoppingDuringAReloadStartsNoOtherUpdater(t *testing.T) {
	panel, _ := setupProfileTest(t)
	t.Setenv("OIX_UPDATE_INTERVAL", "1")
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	reloading, release := make(chan struct{}), make(chan struct{})
	SetProfileReloader(func() {
		close(reloading)
		<-release
		StartProfileUpdates() // what applying the reloaded config does
	})
	t.Cleanup(func() { SetProfileReloader(nil) })
	panel.content.Store(strings.Replace(testProfile, "mixed-port: 7777", "mixed-port: 7778", 1))
	StartProfileUpdates()

	select {
	case <-reloading:
	case <-time.After(5 * time.Second):
		t.Fatal("the changed profile was not reloaded")
	}
	time.AfterFunc(50*time.Millisecond, func() { close(release) })
	StopProfileUpdates()
	profileUpdaterMu.Lock()
	running := profileCancel != nil
	profileUpdaterMu.Unlock()
	if running {
		t.Fatal("the reload restarted the updater that was being stopped")
	}
}

func TestProfileUpdatesReloadOnlyWhenTheProfileChanges(t *testing.T) {
	panel, _ := setupProfileTest(t)
	t.Setenv("OIX_UPDATE_INTERVAL", "1")
	if _, err := ComposeProfile([]byte(testOverlay)); err != nil {
		t.Fatal(err)
	}
	reloads := make(chan struct{}, 8)
	SetProfileReloader(func() { reloads <- struct{}{} })
	t.Cleanup(func() { SetProfileReloader(nil) })
	StartProfileUpdates()
	StartProfileUpdates() // a reload restarts nothing

	select {
	case <-reloads:
		t.Fatal("reloaded although the profile did not change")
	case <-time.After(1500 * time.Millisecond):
	}
	panel.content.Store(strings.Replace(testProfile, "mixed-port: 7777", "mixed-port: 7778", 1))
	select {
	case <-reloads:
	case <-time.After(5 * time.Second):
		t.Fatal("a changed profile was not reloaded")
	}
	StopProfileUpdates()
	if requests := panel.requests.Load(); requests < 3 {
		t.Fatalf("requests = %d, want periodic fetches", requests)
	}
}
