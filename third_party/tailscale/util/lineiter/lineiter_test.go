// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package lineiter

import (
	"github.com/metacubex/tailscale/util/go120/slices"
	"strings"
	"testing"
)

func TestBytesLines(t *testing.T) {
	var got []string
	for _, line := range slices.Collect(Bytes([]byte("foo\n\nbar\nbaz"))) {
		got = append(got, string(line))
	}
	want := []string{"foo", "", "bar", "baz"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}

func TestReader(t *testing.T) {
	var got []string
	for _, line := range slices.Collect(Reader(strings.NewReader("foo\n\nbar\nbaz"))) {
		got = append(got, string(line.MustValue()))
	}
	want := []string{"foo", "", "bar", "baz"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q; want %q", got, want)
	}
}
