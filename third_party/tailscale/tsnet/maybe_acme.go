// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !js && !ts_omit_acme

package tsnet

// Link in the ACME/TLS-cert feature so [Server.CertDomains],
// [Server.ListenTLS], and related cert-fetch paths work out of the box.
// Build with the ts_omit_acme tag to omit it.

import (
	"github.com/metacubex/tailscale/client/local"
	_ "github.com/metacubex/tailscale/feature/acme"
	"github.com/metacubex/tls"
)

func getLocalClientCertificate(lc *local.Client, hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return lc.GetCertificate(hi)
}
