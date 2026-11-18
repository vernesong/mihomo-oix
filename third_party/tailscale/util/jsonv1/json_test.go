// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package jsonv1

import (
	"bytes"
	"testing"
)

type zeroValue struct {
	value int
}

func (v zeroValue) IsZero() bool {
	return v.value == 0
}

type testValue struct {
	Keep int       `json:"keep"`
	Omit zeroValue `json:"omit,omitzero"`
}

func TestMarshal(t *testing.T) {
	const want = `{"keep":1}`
	v := testValue{Keep: 1}

	b, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != want {
		t.Fatalf("Marshal: got %q, want %q", got, want)
	}

	var buf bytes.Buffer
	if err := MarshalWrite(&buf, v); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != want {
		t.Fatalf("MarshalWrite: got %q, want %q", got, want)
	}
}

func TestUnmarshal(t *testing.T) {
	var got testValue
	if err := Unmarshal([]byte(`{"keep":2}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Keep != 2 {
		t.Fatalf("Keep: got %d, want 2", got.Keep)
	}
}
