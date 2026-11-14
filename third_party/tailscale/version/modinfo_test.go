// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package version_test

import (
	"flag"
	"testing"

	"github.com/metacubex/tailscale/version"
)

var (
	findModuleInfo = version.ExportFindModuleInfo
	cmdName        = version.ExportCmdName
)

var findModuleInfoName = flag.String("module-info-file", "", "if non-empty, test findModuleInfo against this filename")

func TestFindModuleInfoManual(t *testing.T) {
	exe := *findModuleInfoName
	if exe == "" {
		t.Skip("skipping without --module-info-file filename")
	}
	cmd := cmdName(exe)
	mod, err := findModuleInfo(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Got %q from: %s", cmd, mod)
}
