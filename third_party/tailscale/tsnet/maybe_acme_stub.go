// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build js || ts_omit_acme

package tsnet

import (
	"github.com/metacubex/tailscale/client/local"
	"github.com/metacubex/tls"
)

func getLocalClientCertificate(*local.Client, *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errACMEUnavailable
}
