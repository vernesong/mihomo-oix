// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package appc

import (
	"fmt"
	"github.com/metacubex/tailscale/util/go120/cmp"
	"github.com/metacubex/tailscale/util/go120/slices"
	"strings"

	"github.com/metacubex/tailscale/ipn/ipnext"
	"github.com/metacubex/tailscale/tailcfg"
	"github.com/metacubex/tailscale/types/appctype"
	"github.com/metacubex/tailscale/types/dnstype"
	"github.com/metacubex/tailscale/util/set"
)

const AppConnectorsExperimentalAttrName = "tailscale.com/app-connectors-experimental"

func isPeerEligibleConnector(peer tailcfg.NodeView) bool {
	if !peer.Valid() || !peer.Hostinfo().Valid() {
		return false
	}
	isConn, _ := peer.Hostinfo().AppConnector().Get()
	return isConn
}

func sortByPreference(ns []tailcfg.NodeView) {
	// The ordering of the nodes is semantic (callers use the first node they can
	// get a peer api url for). We don't (currently 2026-02-27) have any
	// preference over which node is chosen as long as it's consistent.  In the
	// future we anticipate integrating with traffic steering.
	slices.SortFunc(ns, func(a, b tailcfg.NodeView) int {
		return cmp.Compare(a.ID(), b.ID())
	})
}

// PickConnector returns peers the backend knows about that match the app, in order of preference to use as
// a connector.
func PickConnector(nb ipnext.NodeBackend, app appctype.Conn25Attr) []tailcfg.NodeView {
	appTagsSet := set.SetOf(app.Connectors)
	matches := nb.AppendMatchingPeers(nil, func(n tailcfg.NodeView) bool {
		if !isPeerEligibleConnector(n) {
			return false
		}
		matched := false
		n.Tags().All()(func(_ int, t string) bool {
			if appTagsSet.Contains(t) {
				matched = true
				return false
			}
			return true
		})
		return matched
	})
	sortByPreference(matches)
	return matches
}

// DNSAddrScheme is the custom URI scheme used for conn25-managed split DNS
// entries to determine the destination at query time rather than configuration
// time.
const DNSAddrScheme = "tailscale-app"

func AppDNSRoutes(hasCap func(c tailcfg.NodeCapability) bool, self tailcfg.NodeView) map[string][]*dnstype.Resolver {
	if !hasCap(AppConnectorsExperimentalAttrName) {
		return nil
	}
	apps, err := tailcfg.UnmarshalNodeCapViewJSON[appctype.AppConnectorAttr](self.CapMap(), AppConnectorsExperimentalAttrName)
	if err != nil {
		return nil
	}
	appNamesByDomain := map[string]string{}
	for _, app := range apps {
		for _, domain := range app.Domains {
			domain, _ = strings.CutPrefix(domain, "*.")
			domain = strings.ToLower(domain)
			// in the case of multiple apps specifying the same domain (which is misconfiguration
			// that should be validated at point of input) last write wins.
			appNamesByDomain[domain] = app.Name
		}
	}
	m := make(map[string][]*dnstype.Resolver, len(appNamesByDomain))
	for domain, appName := range appNamesByDomain {
		m[domain] = []*dnstype.Resolver{{Addr: fmt.Sprintf("%s:%s", DNSAddrScheme, appName)}}
	}
	return m
}
