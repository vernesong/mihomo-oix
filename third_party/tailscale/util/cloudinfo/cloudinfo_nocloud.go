// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || js

package cloudinfo

import (
	"context"
	"net/netip"

	"github.com/metacubex/tailscale/net/netx"
	"github.com/metacubex/tailscale/types/logger"
)

// CloudInfo is not available in mobile and JS targets.
type CloudInfo struct{}

// New construct a no-op CloudInfo stub.
func New(_ logger.Logf, _ netx.DialFunc) *CloudInfo {
	return &CloudInfo{}
}

// GetPublicIPs always returns nil slice and error.
func (ci *CloudInfo) GetPublicIPs(_ context.Context) ([]netip.Addr, error) {
	return nil, nil
}
