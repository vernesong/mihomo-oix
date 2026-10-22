package oix

import (
	"reflect"
	"testing"

	"github.com/metacubex/mihomo/common/orderedmap"

	"go.yaml.in/yaml/v3"
)

func TestProfileMergePreservesYAMLSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, managed, overlay, want string
	}{
		{
			name:    "recursive maps and replacement values",
			managed: "dns: {enable: true, nameserver: [1.1.1.1], nameserver-policy: {a: 1.1.1.1}}\nrules: [MATCH,DIRECT]\ntun: {enable: true}\n",
			overlay: "dns: {cache-max-size: 1024, nameserver: [], nameserver-policy: {b: 8.8.8.8}}\nrules: []\ntun: null\n",
			want:    "dns: {enable: true, cache-max-size: 1024, nameserver: [], nameserver-policy: {a: 1.1.1.1, b: 8.8.8.8}}\nrules: []\ntun: null\n",
		},
		{
			name:    "aliases remain independent under local overrides",
			managed: "shared: &dns {enable: true, nameserver: [1.1.1.1]}\ndns: *dns\n",
			overlay: "dns: {enable: false}\n",
			want:    "shared: {enable: true, nameserver: [1.1.1.1]}\ndns: {enable: false, nameserver: [1.1.1.1]}\n",
		},
		{
			name:    "YAML merge keys and local aliases",
			managed: "shared: &dns {enable: true, nameserver: [1.1.1.1]}\ndns: {<<: *dns, nameserver: [8.8.8.8]}\n",
			overlay: "local: &dns {cache-max-size: 1024}\ndns: {<<: *dns, nameserver: [9.9.9.9]}\n",
			want:    "shared: {enable: true, nameserver: [1.1.1.1]}\nlocal: {cache-max-size: 1024}\ndns: {enable: true, cache-max-size: 1024, nameserver: [9.9.9.9]}\n",
		},
		{name: "empty overlay", managed: "mixed-port: 7890\n", want: "mixed-port: 7890\n"},
		{name: "null overlay", managed: "mixed-port: 7890\n", overlay: "null", want: "mixed-port: 7890\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			document, err := (&fetchedConfig{plain: []byte(tc.managed)}).profileDocument()
			if err != nil {
				t.Fatal(err)
			}
			merged, err := mergeProfile(document, []byte(tc.overlay))
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			if err := merged.Decode(&got); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal([]byte(tc.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("merged = %#v, want %#v", got, want)
			}
		})
	}
}

func TestProfileMergeRejectsInvalidMappingsBeforeOverrides(t *testing.T) {
	for _, tc := range []struct{ managed, overlay string }{
		{"dns: {enable: true, enable: false}", "dns: null"},
		{"dns: {}", "dns: {enable: true, enable: false}"},
		{"dns: {}", "[invalid]"},
		{"dns: {}", "dns: ["},
		{"shared: &loop {nested: *loop}\ndns: {}", "dns: {}"},
	} {
		document, err := (&fetchedConfig{plain: []byte(tc.managed)}).profileDocument()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mergeProfile(document, []byte(tc.overlay)); err == nil {
			t.Fatalf("accepted invalid managed %q / overlay %q", tc.managed, tc.overlay)
		}
	}
}

func TestProfileMergePreservesScalarStringConversions(t *testing.T) {
	for value, want := range map[string]string{"0xFF": "255", "TRUE": "true", "2026-10-23": "2026-10-23T00:00:00Z"} {
		document, err := (&fetchedConfig{plain: []byte("secret: " + value)}).profileDocument()
		if err != nil {
			t.Fatal(err)
		}
		merged, err := mergeProfile(document, []byte("mixed-port: 7890"))
		if err != nil {
			t.Fatal(err)
		}
		var config struct{ Secret string }
		if err := merged.Decode(&config); err != nil || config.Secret != want {
			t.Fatalf("secret %s decoded as %q, error %v; want %q", value, config.Secret, err, want)
		}
	}
}

func TestProfileMergeDecodesOrderedDNSPolicies(t *testing.T) {
	document, err := (&fetchedConfig{plain: []byte("dns:\n  nameserver-policy: {host10.test: 1.1.1.1, host2.test: 8.8.8.8}\n  proxy-server-nameserver-policy: {node10.test: 1.1.1.1, node2.test: 8.8.8.8}\n")}).profileDocument()
	if err != nil {
		t.Fatal(err)
	}
	merged, err := mergeProfile(document, []byte("dns:\n  nameserver-policy: {'+.lan': 127.0.0.1:53}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		DNS struct {
			Policy      *orderedmap.OrderedMap[string, any] `yaml:"nameserver-policy"`
			ProxyPolicy *orderedmap.OrderedMap[string, any] `yaml:"proxy-server-nameserver-policy"`
		} `yaml:"dns"`
	}
	if err := merged.Decode(&config); err != nil {
		t.Fatal(err)
	}
	if config.DNS.Policy.Len() != 3 || config.DNS.ProxyPolicy.Len() != 2 {
		t.Fatal("YAML decoding lost the policy maps")
	}
	if config.DNS.Policy.Value("+.lan") != "127.0.0.1:53" || config.DNS.Policy.Value("host10.test") != "1.1.1.1" {
		t.Fatal("local and managed DNS policies did not survive the merge")
	}
	var names []string
	for pair := config.DNS.Policy.Oldest(); pair != nil; pair = pair.Next() {
		names = append(names, pair.Key)
	}
	if !reflect.DeepEqual(names, []string{"+.lan", "host2.test", "host10.test"}) || config.DNS.ProxyPolicy.Oldest().Key != "node2.test" {
		t.Fatalf("DNS policy order changed: %v", names)
	}
}
