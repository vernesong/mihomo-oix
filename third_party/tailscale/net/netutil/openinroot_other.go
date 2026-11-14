// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !linux

package netutil

import (
	"fmt"
	"os"
	"path/filepath"
)

func openInRoot(root, name string) (*os.File, error) {
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("path %q is not local", name)
	}
	return os.Open(filepath.Join(root, name))
}
