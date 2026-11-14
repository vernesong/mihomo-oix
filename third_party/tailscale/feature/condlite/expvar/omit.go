// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ts_enable_debug && !ts_enable_clientmetrics && !ts_enable_usermetrics

package expvar

type Int int64

func (*Int) Add(int64) {}
