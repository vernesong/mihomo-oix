// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_acme

package tsnet

import (
	"errors"
	"testing"
)

func TestOmitACME(t *testing.T) {
	s := new(Server)
	if _, err := s.ListenTLS("tcp", ":443"); !errors.Is(err, errACMEUnavailable) {
		t.Fatalf("ListenTLS error = %v, want %v", err, errACMEUnavailable)
	}
	if _, err := s.ListenFunnel("tcp", ":443"); !errors.Is(err, errACMEUnavailable) {
		t.Fatalf("ListenFunnel error = %v, want %v", err, errACMEUnavailable)
	}
}
