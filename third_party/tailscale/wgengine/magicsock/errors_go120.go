// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !go1.21

package magicsock

import "errors"

// ErrUnsupported is errors.ErrUnsupported on Go versions that provide it.
var ErrUnsupported = errors.New("unsupported operation")
