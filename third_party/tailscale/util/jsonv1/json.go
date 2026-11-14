// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// Package jsonv1 provides encoding/json v1 semantics with support for the
// omitzero struct tag on every supported Go version.
package jsonv1

// Marshaler is implemented by types that can marshal themselves into JSON.
type Marshaler interface {
	MarshalJSON() ([]byte, error)
}

// Unmarshaler is implemented by types that can unmarshal a JSON value.
type Unmarshaler interface {
	UnmarshalJSON([]byte) error
}
