package oix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

// Requests made by any test may generate a device ID; keep it out of the real home directory.
func TestMain(m *testing.M) {
	homeDir, err := os.MkdirTemp("", "oix-test-home-")
	if err != nil {
		panic(err)
	}
	C.SetHomeDir(homeDir)
	code := m.Run()
	_ = os.RemoveAll(homeDir)
	os.Exit(code)
}

// resetDeviceForTest forgets the declared and kept identifiers and points the home directory at homeDir.
func resetDeviceForTest(t *testing.T, homeDir string) {
	t.Helper()
	t.Setenv("OIX_DEVICE", "")
	oldHomeDir := C.Path.HomeDir()
	deviceMu.Lock()
	oldDeclared, oldHome, oldStored := declaredDevice, storedHome, storedDevice
	declaredDevice, storedHome, storedDevice = "", "", ""
	deviceMu.Unlock()
	C.SetHomeDir(homeDir)
	t.Cleanup(func() {
		C.SetHomeDir(oldHomeDir)
		deviceMu.Lock()
		declaredDevice, storedHome, storedDevice = oldDeclared, oldHome, oldStored
		deviceMu.Unlock()
	})
}

func TestSetDeviceAcceptsOnlyUUIDv4(t *testing.T) {
	resetDeviceForTest(t, t.TempDir())
	for _, bad := range []string{
		"", "not-a-uuid",
		"3f2b8c1e-9a4d-1e7b-8c21-5d6f0a9b1c3e", // version 1
		"3f2b8c1e-9a4d-4e7b-7c21-5d6f0a9b1c3e", // wrong variant
		"3f2b8c1e-9a4d-4e7b-8c21-5d6f0a9b1c3e, 3f2b8c1e-9a4d-4e7b-8c21-5d6f0a9b1c3e",
	} {
		if err := SetDevice(bad); err == nil {
			t.Errorf("SetDevice(%q) accepted", bad)
		}
	}
	if err := SetDevice(" 3F2B8C1E-9A4D-4E7B-8C21-5D6F0A9B1C3E "); err != nil {
		t.Fatal(err)
	}
	if got := currentDevice(); got != "3f2b8c1e-9a4d-4e7b-8c21-5d6f0a9b1c3e" {
		t.Fatalf("currentDevice() = %q", got)
	}
}

func TestNewDeviceIDsAreDistinctUUIDv4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newDeviceID()
		if err != nil {
			t.Fatal(err)
		}
		if !deviceIDPattern.MatchString(id) || seen[id] {
			t.Fatalf("newDeviceID() = %q", id)
		}
		seen[id] = true
	}
}

func TestDeviceIsKeptInTheHomeDirectory(t *testing.T) {
	homeDir := t.TempDir()
	resetDeviceForTest(t, homeDir)

	id := currentDevice()
	if !deviceIDPattern.MatchString(id) {
		t.Fatalf("currentDevice() = %q", id)
	}
	path := filepath.Join(homeDir, ".oix_device_id")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("device ID file mode = %v", info.Mode().Perm())
	}

	// a later run reads the same identifier back
	deviceMu.Lock()
	storedHome, storedDevice = "", ""
	deviceMu.Unlock()
	if got := currentDevice(); got != id {
		t.Fatalf("second run = %q, want %q", got, id)
	}

	// a damaged file is replaced
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	deviceMu.Lock()
	storedHome, storedDevice = "", ""
	deviceMu.Unlock()
	replaced := currentDevice()
	if !deviceIDPattern.MatchString(replaced) || replaced == id {
		t.Fatalf("after damage = %q", replaced)
	}
	data, _ := os.ReadFile(path)
	if strings.TrimSpace(string(data)) != replaced {
		t.Fatalf("file holds %q, want %q", data, replaced)
	}
}

func TestDeclaredDeviceWinsOverTheEnvironmentAndTheHomeDirectory(t *testing.T) {
	homeDir := t.TempDir()
	resetDeviceForTest(t, homeDir)
	t.Setenv("OIX_DEVICE", "1a2b3c4d-1111-4222-9333-444455556666")
	if got := currentDevice(); got != "1a2b3c4d-1111-4222-9333-444455556666" {
		t.Fatalf("from environment = %q", got)
	}
	if err := SetDevice("5a2b3c4d-1111-4222-b333-444455556668"); err != nil {
		t.Fatal(err)
	}
	if got := currentDevice(); got != "5a2b3c4d-1111-4222-b333-444455556668" {
		t.Fatalf("declared = %q", got)
	}
	if _, err := os.Stat(filepath.Join(homeDir, ".oix_device_id")); !os.IsNotExist(err) {
		t.Fatalf("a declared or environment ID must not create a file, stat = %v", err)
	}
}

func TestNoDeviceWithoutAPlaceToKeepIt(t *testing.T) {
	resetDeviceForTest(t, filepath.Join(t.TempDir(), "missing"))
	if got := currentDevice(); got != "" {
		t.Fatalf("currentDevice() = %q, want none", got)
	}
	// the failure is remembered instead of retried on every request
	deviceMu.Lock()
	remembered := storedHome != "" && storedDevice == ""
	deviceMu.Unlock()
	if !remembered {
		t.Fatal("failed home directory not remembered")
	}

	req := httptest.NewRequest(http.MethodGet, "https://panel.example/", nil)
	setDeviceHeader(req)
	if _, ok := req.Header[http.CanonicalHeaderKey(oixDeviceHeader)]; ok {
		t.Fatal("header sent without an identifier")
	}
}

func TestAccountRequestsSendTheDeviceFromTheEnvironment(t *testing.T) {
	resetDeviceForTest(t, t.TempDir())
	t.Setenv("OIX_DEVICE", "1A2B3C4D-1111-4222-9333-444455556666")
	setupPanelTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(oixDeviceHeader); got != "1a2b3c4d-1111-4222-9333-444455556666" {
			t.Errorf("%s %s = %q", r.URL.Path, oixDeviceHeader, got)
		}
		writePanelJSON(w, map[string]any{"ret": 200, "data": map[string]any{"plan": "Pro", "token_client": "oixclash"}})
	}))

	if status, out := runCLI(t, "account", map[string]string{"token": "pasted"}); status != exitOK {
		t.Fatalf("account = %d %+v", status, out)
	}
}

func TestManagedFetchSendsTheKeptDevice(t *testing.T) {
	homeDir := t.TempDir()
	resetDeviceForTest(t, homeDir)
	setupSignedFetchTest(t)
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(oixDeviceHeader)
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	setoixHTTPClientForTest(t, server.Client())

	_, _ = fetchFrom(context.Background(), "token", server.URL)
	data, err := os.ReadFile(filepath.Join(homeDir, ".oix_device_id"))
	if err != nil {
		t.Fatal(err)
	}
	if got == "" || got != strings.TrimSpace(string(data)) {
		t.Fatalf("%s = %q, kept %q", oixDeviceHeader, got, data)
	}
}
