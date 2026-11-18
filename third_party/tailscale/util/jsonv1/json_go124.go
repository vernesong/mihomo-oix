// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build go1.24

package jsonv1

import (
	"encoding/json"
	"io"
)

// Marshal returns the JSON encoding of v.
func Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

// Unmarshal parses data into v.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

// MarshalWrite writes the JSON encoding of v to w.
func MarshalWrite(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	n, err := w.Write(b)
	if n != len(b) && err == nil {
		return io.ErrShortWrite
	}
	return err
}
