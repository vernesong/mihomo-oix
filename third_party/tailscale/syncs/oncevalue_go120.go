// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package syncs

import "sync"

// OnceValue returns a function that invokes f only once and returns the cached value.
func OnceValue[T any](f func() T) func() T {
	var once sync.Once
	var v T
	return func() T {
		once.Do(func() { v = f() })
		return v
	}
}
