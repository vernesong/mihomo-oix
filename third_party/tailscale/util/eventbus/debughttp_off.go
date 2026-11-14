// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios || android || !ts_enable_debugeventbus

package eventbus

type tswebDebugHandler = any // actually *tsweb.DebugHandler; any to avoid importing tsweb when debug eventbus support is disabled

func (*Debugger) RegisterHTTP(td tswebDebugHandler) {}
