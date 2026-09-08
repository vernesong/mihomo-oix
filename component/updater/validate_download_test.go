package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreArchiveFormatAndChecksum(t *testing.T) {
	var zipped, gzipped bytes.Buffer
	zipWriter := zip.NewWriter(&zipped)
	file, _ := zipWriter.Create("core")
	_, _ = file.Write([]byte("binary"))
	_ = zipWriter.Close()
	gzipWriter := gzip.NewWriter(&gzipped)
	_, _ = gzipWriter.Write([]byte("binary"))
	_ = gzipWriter.Close()
	if err := validateCoreArchive(zipped.Bytes(), "core.zip"); err != nil {
		t.Fatal(err)
	}
	if err := validateCoreArchive(gzipped.Bytes(), "core.gz"); err != nil {
		t.Fatal(err)
	}
	if err := validateCoreArchive(zipped.Bytes(), "core.gz"); err == nil {
		t.Fatal("ZIP won a gzip download")
	}
	corrupt := append([]byte{}, gzipped.Bytes()...)
	corrupt[len(corrupt)-8] ^= 1
	if err := validateCoreArchive(corrupt, "core.gz"); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
}

func TestCoreDownloadRejectsHTMLWithoutReplacingFile(t *testing.T) {
	server := httptest.NewServer(okHandler("<html>challenge</html>"))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "core.gz")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DefaultCoreUpdater.download(dir, path, server.URL); err == nil {
		t.Fatal("HTML accepted")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "previous" {
		t.Fatalf("file=%q", data)
	}
	if _, err := DefaultCoreUpdater.getLatestVersion(server.URL); err == nil {
		t.Fatal("HTML accepted as version")
	}
}

func makeTestGzip(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := gzip.NewWriter(&data)
	writer.Name = name
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestArchiveRejectsEmptyOrEscapingTargets(t *testing.T) {
	for _, name := range []string{"../escaped", `..\escaped`, "/escaped", "C:escaped"} {
		data := makeTestGzip(t, name, []byte("binary"))
		if err := validateCoreArchive(data, "core.gz"); err == nil {
			t.Errorf("unsafe gzip filename accepted: %q", name)
		}
		dir := t.TempDir()
		archive := filepath.Join(dir, "core.gz")
		_ = os.WriteFile(archive, data, 0o600)
		if _, err := DefaultCoreUpdater.gzFileUnpack(archive, dir, 0o600); err == nil {
			t.Errorf("unsafe gzip filename extracted: %q", name)
		}
	}
	if err := validateCoreArchive(makeTestGzip(t, "core", nil), "core.gz"); err == nil {
		t.Fatal("empty gzip accepted")
	}
	for _, name := range []string{"folder/", "empty", "../escaped", `..\escaped`} {
		var data bytes.Buffer
		writer := zip.NewWriter(&data)
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if name != "folder/" && name != "empty" {
			_, _ = file.Write([]byte("content"))
		}
		_ = writer.Close()
		if err := validateCoreArchive(data.Bytes(), "core.zip"); err == nil {
			t.Errorf("bad core zip accepted: %q", name)
		}
		if err := validateArchive(data.Bytes(), true); err == nil {
			t.Errorf("bad UI zip accepted: %q", name)
		}
	}
}

func TestUIArchiveRequiresNonEmptyRegularContent(t *testing.T) {
	for _, kind := range []string{"directory", "empty", "symlink", "escape", "valid"} {
		t.Run(kind, func(t *testing.T) {
			var raw bytes.Buffer
			writer := tar.NewWriter(&raw)
			header := &tar.Header{Name: "index.html", Mode: 0o644, Typeflag: tar.TypeReg, Size: 7}
			switch kind {
			case "directory":
				header.Name = "assets/"
				header.Typeflag = tar.TypeDir
				header.Size = 0
			case "empty":
				header.Size = 0
			case "symlink":
				header.Typeflag = tar.TypeSymlink
				header.Linkname = "outside"
				header.Size = 0
			case "escape":
				header.Name = "../index.html"
			}
			if err := writer.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			if header.Size > 0 {
				_, _ = writer.Write([]byte("content"))
			}
			_ = writer.Close()
			err := validateArchive(makeTestGzip(t, "", raw.Bytes()), true)
			if kind == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatalf("invalid %s UI archive accepted", kind)
			}
		})
	}
	var raw bytes.Buffer
	writer := zip.NewWriter(&raw)
	header := &zip.FileHeader{Name: "index.html"}
	header.SetMode(os.ModeSymlink | 0o777)
	file, err := writer.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write([]byte("elsewhere"))
	_ = writer.Close()
	if err := validateArchive(raw.Bytes(), true); err == nil {
		t.Fatal("symlink-only UI ZIP accepted")
	}
}

func TestCoreArchivesUseActualInstallTarget(t *testing.T) {
	for _, headerName := range []string{"", "unexpected-safe-name"} {
		dir := t.TempDir()
		archive := filepath.Join(dir, "download-version.gz")
		if err := os.WriteFile(archive, makeTestGzip(t, headerName, []byte("binary")), 0o600); err != nil {
			t.Fatal(err)
		}
		path, err := DefaultCoreUpdater.gzFileUnpack(archive, dir, 0o600, "actual-core")
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(dir, "actual-core") {
			t.Fatalf("extracted target=%q", path)
		}
	}
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	file, _ := writer.Create("README")
	_, _ = file.Write([]byte("not the core"))
	_ = writer.Close()
	if err := validateCoreArchive(data.Bytes(), "core.zip", "actual-core"); err == nil {
		t.Fatal("wrong ZIP first file accepted as core")
	}
}
