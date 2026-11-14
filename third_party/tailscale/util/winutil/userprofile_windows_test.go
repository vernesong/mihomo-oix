// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package winutil

import (
	"testing"

	"github.com/metacubex/tailscale/util/winutil/winenv"
	"golang.org/x/sys/windows"
)

func TestGetRoamingProfilePath(t *testing.T) {
	if !winenv.IsDomainJoined() {
		t.Skip("requires a domain-joined Windows machine")
	}

	token := windows.GetCurrentProcessToken()
	computerName, userName, err := getComputerAndUserName(token, nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := getRoamingProfilePath(t.Logf, token, computerName, userName); err != nil {
		t.Error(err)
	}

	// TODO(aaron): Flesh out better once can run tests under domain accounts.
}
