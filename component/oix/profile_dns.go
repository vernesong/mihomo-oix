package oix

import (
	"crypto/sha256"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/metacubex/mihomo/component/oix/oixdns"

	"gopkg.in/yaml.v3"
)

// ProfileDNSSummary exposes only the panel's ordinary upstreams, before local
// overrides. Node resolvers, domain policies and the full profile stay private.
type ProfileDNSSummary struct {
	Nameserver       []string `yaml:"nameserver" json:"nameserver"`
	DirectNameserver []string `yaml:"direct-nameserver" json:"direct-nameserver"`
	Fallback         []string `yaml:"fallback" json:"fallback"`
	Stale            bool     `yaml:"-" json:"stale"`
}

type profileDNSState struct {
	owner [sha256.Size]byte
	dns   ProfileDNSSummary
}

var profileDNS atomic.Pointer[profileDNSState]

func rememberProfileDNS(plain []byte) {
	var config struct {
		DNS ProfileDNSSummary `yaml:"dns"`
	}
	if err := yaml.Unmarshal(plain, &config); err != nil {
		profileDNS.Store(nil)
		return
	}
	for _, servers := range [][]string{config.DNS.Nameserver, config.DNS.DirectNameserver, config.DNS.Fallback} {
		for i, server := range servers {
			// DNS URLs may themselves contain a managed host. Apply the same
			// masking rule as other controller output, without exporting policies.
			address := server
			if !strings.Contains(address, "://") {
				address = "udp://" + address
			}
			if parsed, err := url.Parse(address); err == nil && parsed.Hostname() != "" {
				host := parsed.Hostname()
				if masked := oixdns.Mask(host); masked != host {
					servers[i] = masked
				}
			}
		}
	}
	profileDNS.Store(&profileDNSState{owner: sha256.Sum256([]byte(getToken())), dns: config.DNS})
}

// GetProfileDNS is a read-only snapshot: it performs no fetch, decryption or
// configuration reload, and never returns a previous account's values.
func GetProfileDNS() (ProfileDNSSummary, bool) {
	state := profileDNS.Load()
	token := getToken()
	if !ProfileMode() || token == "" || state == nil || state.owner != sha256.Sum256([]byte(token)) {
		return ProfileDNSSummary{}, false
	}
	return ProfileDNSSummary{
		Nameserver:       append([]string{}, state.dns.Nameserver...),
		DirectNameserver: append([]string{}, state.dns.DirectNameserver...),
		Fallback:         append([]string{}, state.dns.Fallback...),
		Stale:            profileRetry.Load(),
	}, true
}
