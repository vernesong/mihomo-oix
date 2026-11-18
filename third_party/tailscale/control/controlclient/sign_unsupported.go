// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (!windows && !(darwin && cgo)) || ios

package controlclient

import (
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/key"
	"github.com/metacubex/tailscale/util/syspolicy/policyclient"
)

// signRegisterRequest on non-supported platforms always returns errNoCertStore.
func signRegisterRequest(polc policyclient.Client, req *tailcfg.RegisterRequest, serverURL string, serverPubKey, machinePubKey key.MachinePublic) error {
	return errNoCertStore
}
