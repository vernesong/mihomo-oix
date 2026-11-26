// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !go1.24

package jsonv1

import (
	"io"

	jsonv2 "github.com/metacubex/jsonv2"
	jsonv1 "github.com/metacubex/jsonv2/v1"
)

// Marshal returns the JSON encoding of v.
func Marshal(v any) ([]byte, error) {
	return jsonv2.Marshal(v, jsonv1.DefaultOptionsV1())
}

// Unmarshal parses data into v.
func Unmarshal(data []byte, v any) error {
	return jsonv2.Unmarshal(data, v, jsonv1.DefaultOptionsV1())
}

// MarshalWrite writes the JSON encoding of v to w.
func MarshalWrite(w io.Writer, v any) error {
	return jsonv2.MarshalWrite(w, v, jsonv1.DefaultOptionsV1())
}
