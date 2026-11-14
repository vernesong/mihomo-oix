// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"context"
	"net/netip"
)

// LookupHookFunc resolves host through an embedding application's resolver.
type LookupHookFunc func(ctx context.Context, host string) ([]netip.Addr, error)
