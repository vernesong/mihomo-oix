package utils

import (
	"context"
	"os"
	"path/filepath"
)

// WriteFileAtomic keeps the existing file intact until a complete replacement
// has been written, synced and closed in the same directory.
func WriteFileAtomic(ctx context.Context, path string, data []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
