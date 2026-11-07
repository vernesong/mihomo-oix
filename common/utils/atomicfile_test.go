package utils

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicPreservesOldFileOnCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(path, []byte("original longer value"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteFileAtomic(ctx, path, []byte("new"), 0o644); !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "original longer value" {
		t.Fatalf("old data=%q", data)
	}
	if err := WriteFileAtomic(context.Background(), path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if string(data) != "new" {
		t.Fatalf("replacement=%q", data)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("mode=%v", info.Mode())
	}
	files, _ := os.ReadDir(filepath.Dir(path))
	if len(files) != 1 {
		t.Fatalf("temporary files remain: %v", files)
	}
}
