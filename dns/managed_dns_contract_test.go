package dns

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type dnsContractCase struct {
	Name      string  `json:"name"`
	Query     string  `json:"query"`
	Response  string  `json:"response"`
	Verdict   string  `json:"verdict"`
	TTL       *uint32 `json:"ttl"`
	Addresses int     `json:"addresses"`
}

func dnsContractCases(t *testing.T) []dnsContractCase {
	t.Helper()
	data, err := os.ReadFile("testdata/managed_dns_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []dnsContractCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Cases
}

func contractMessage(t *testing.T, wire string) (*D.Msg, error) {
	t.Helper()
	data, err := hex.DecodeString(wire)
	if err != nil {
		t.Fatal(err)
	}
	m := new(D.Msg)
	return m, m.Unpack(data)
}

func TestManagedDNSCacheContract(t *testing.T) {
	for _, vector := range dnsContractCases(t) {
		t.Run(vector.Name, func(t *testing.T) {
			if vector.Verdict == "failure" {
				return
			}
			query, err := contractMessage(t, vector.Query)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := contractMessage(t, vector.Response)
			if err != nil {
				t.Fatal(err)
			}
			cache := Config{}.newCache()
			putMsgToCache(cache, query.Question[0], reply, 300)
			_, expiry, hit := getMsgFromCache(cache, query.Question[0])
			if vector.TTL == nil || *vector.TTL == 0 {
				if hit {
					t.Fatal("response without a cacheable lifetime was cached")
				}
			} else if !hit || time.Until(expiry) > time.Duration(min(*vector.TTL, 300))*time.Second || time.Until(expiry) < time.Duration(min(*vector.TTL, 300))*time.Second-time.Second {
				t.Fatal("cache lifetime differs from shared DNS contract")
			}
		})
	}
}
