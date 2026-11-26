// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package netlog registers support for network flow logging when logtail is
// enabled and netlog is not disabled via the ts_omit_netlog build tag.
// It is pulled out separately from the main condregister package so
// that tsnet can link it without linking every conditional feature.
package netlog
