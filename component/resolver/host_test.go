package resolver

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/trie"
)

func TestHostsBypassLeavesANameToTheResolver(t *testing.T) {
	tree := trie.New[HostValue]()
	value, err := NewHostValue([]string{"192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{"a.bypassed.example", "+.example"} {
		if err := tree.Insert(pattern, value); err != nil {
			t.Fatal(err)
		}
	}
	hosts := NewHosts(tree)
	previous, previousSystem := HostsBypass, UseSystemHosts
	t.Cleanup(func() { HostsBypass, UseSystemHosts = previous, previousSystem })

	HostsBypass = nil
	if _, ok := hosts.Search("a.bypassed.example", false); !ok {
		t.Fatal("no bypass lost an entry")
	}

	HostsBypass = func(host string) bool {
		return strings.HasSuffix(strings.ToLower(host), "bypassed.example") || host == "localhost"
	}
	for _, host := range []string{"a.bypassed.example", "b.bypassed.example", "A.Bypassed.Example"} {
		for _, isDomain := range []bool{false, true} {
			if node, _ := hosts.Search(host, isDomain); node != nil {
				t.Errorf("%s isDomain=%v answered %v", host, isDomain, node)
			}
		}
	}
	if node, ok := hosts.Search("public.example", false); !ok || len(node.IPs) != 1 {
		t.Errorf("public.example = %v, %v", node, ok)
	}

	// the system's hosts file is left out the same way
	UseSystemHosts = true
	if node, _ := hosts.Search("localhost", false); node != nil {
		t.Errorf("localhost answered %v", node)
	}
}
