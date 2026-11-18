package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreBaseName(t *testing.T) {
	fmt.Println("Core base name =", DefaultCoreUpdater.CoreBaseName())
}

// nonOKHandler serves an error-page body with a non-200 status. Such a body must
// never be treated as valid content (version string, update package, ...).
func nonOKHandler(status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte("<html><body>error page from gateway</body></html>"))
	})
}

func okHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	})
}

// TestGetLatestVersion_NonOKStatus ensures a non-200 response from the version
// endpoint is surfaced as an error instead of being returned as the "version".
func TestGetLatestVersion_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(nonOKHandler(http.StatusBadGateway))
	defer srv.Close()

	if _, err := DefaultCoreUpdater.getLatestVersion(srv.URL); err == nil {
		t.Fatalf("getLatestVersion: expected error for non-200 status, got nil")
	}
}

func TestGetLatestVersion_OK(t *testing.T) {
	srv := httptest.NewServer(okHandler("v1.2.3"))
	defer srv.Close()

	got, err := DefaultCoreUpdater.getLatestVersion(srv.URL)
	if err != nil {
		t.Fatalf("getLatestVersion: unexpected error: %v", err)
	}
	if got != "v1.2.3" {
		t.Fatalf("getLatestVersion: got %q, want %q", got, "v1.2.3")
	}
}

// TestDownload_NonOKStatus ensures a non-200 response from the package endpoint
// is surfaced as an error and does not create the package file on disk.
func TestDownload_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(nonOKHandler(http.StatusNotFound))
	defer srv.Close()

	updateDir := filepath.Join(t.TempDir(), "meta-update")
	pkgPath := filepath.Join(updateDir, "pkg.gz")

	if err := DefaultCoreUpdater.download(updateDir, pkgPath, srv.URL); err == nil {
		t.Fatalf("download: expected error for non-200 status, got nil")
	}
	if _, statErr := os.Stat(pkgPath); statErr == nil {
		t.Fatalf("download: package file must not be created on non-200 status")
	}
}

// TestDownloadForBytes_NonOKStatus ensures a non-200 response is surfaced as an
// error instead of returning the error-page body as if it were valid content.
func TestDownloadForBytes_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(nonOKHandler(http.StatusBadGateway))
	defer srv.Close()

	if data, err := downloadForBytes(srv.URL); err == nil {
		t.Fatalf("downloadForBytes: expected error for non-200 status, got %q", string(data))
	}
}

func TestDownloadForBytes_OK(t *testing.T) {
	srv := httptest.NewServer(okHandler("hello"))
	defer srv.Close()

	got, err := downloadForBytes(srv.URL)
	if err != nil {
		t.Fatalf("downloadForBytes: unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("downloadForBytes: got %q, want %q", string(got), "hello")
	}
}
