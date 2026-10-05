package oix

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func TestProfileDNSSummaryBeforeOverridesAndAccountIsolation(t *testing.T) {
	panel, _ := setupProfileTest(t)
	panel.content.Store(testProfile + `  direct-nameserver: [119.29.29.29]
  fallback: ['https://fallback.example/dns-query']
  proxy-server-nameserver: [192.0.2.123]
  proxy-server-nameserver-policy: {'private-node.example': 192.0.2.124}
`)
	if _, ok := GetProfileDNS(); ok {
		t.Fatal("unloaded profile exposed a snapshot")
	}
	if _, err := ComposeProfile([]byte("dns:\n  nameserver: [8.8.8.8]\n  direct-nameserver: [1.1.1.1]\n")); err != nil {
		t.Fatal(err)
	}
	got, ok := GetProfileDNS()
	if !ok || len(got.Nameserver) != 1 || got.Nameserver[0] != "223.5.5.5" || got.DirectNameserver[0] != "119.29.29.29" {
		t.Fatalf("panel snapshot = %+v, available = %v", got, ok)
	}
	encoded, _ := json.Marshal(got)
	for _, private := range []string{"node-a", "nodes.example", "proxy-server-nameserver", "192.0.2.123", "private-node.example", "192.0.2.124"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("summary exposed private profile field %q", private)
		}
	}
	got.Nameserver[0] = "changed"
	again, _ := GetProfileDNS()
	if again.Nameserver[0] != "223.5.5.5" {
		t.Fatal("caller mutated the snapshot")
	}
	requests := panel.requests.Load()
	profileRetry.Store(true)
	if cached, _ := GetProfileDNS(); !cached.Stale || panel.requests.Load() != requests {
		t.Fatal("snapshot read did not preserve cache status or performed a request")
	}
	SetToken("different-account")
	if _, ok := GetProfileDNS(); ok {
		t.Fatal("another account saw the previous DNS")
	}
	SetToken("profile-token")
	removeProfile()
	if _, ok := GetProfileDNS(); ok {
		t.Fatal("logout retained DNS")
	}
}

func TestProfileDNSMasksManagedHostsAndClearsInvalidSnapshots(t *testing.T) {
	_, _ = setupProfileTest(t)
	rememberProfileDNS([]byte("dns:\n  nameserver: ['https://a.nodes.example/dns-query', '119.29.29.29']\n"))
	got, ok := GetProfileDNS()
	if !ok || got.Nameserver[0] != oixdns.Mask("a.nodes.example") || got.Nameserver[1] != "119.29.29.29" {
		t.Fatalf("masked DNS = %+v", got)
	}
	rememberProfileDNS([]byte("dns: [invalid"))
	if _, ok := GetProfileDNS(); ok {
		t.Fatal("invalid profile retained old DNS")
	}
}
