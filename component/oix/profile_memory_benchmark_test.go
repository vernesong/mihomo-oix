package oix

import (
	"fmt"
	"strings"
	"testing"
)

func BenchmarkProfilePreparation(b *testing.B) {
	var text strings.Builder
	text.WriteString("dns:\n  nameserver: [223.5.5.5]\n  nameserver-policy: {'+.example.test': 127.0.0.1:5353}\nproxies:\n")
	for i := range 256 {
		fmt.Fprintf(&text, "  - {name: node-%d, type: ss, server: node-%d.example.test, port: 443, cipher: aes-128-gcm, password: fixture}\n", i, i)
	}
	text.WriteString("rules:\n")
	for i := range 2048 {
		fmt.Fprintf(&text, "  - DOMAIN-SUFFIX,domain-%d.example.test,DIRECT\n", i)
	}
	managed := []byte(text.String())
	overlay := []byte("mixed-port: 7890\ndns:\n  cache-max-size: 1024\n  nameserver-policy: {'+.lan': 127.0.0.1:53}\n")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		document, err := (&fetchedConfig{plain: managed}).profileDocument()
		if err != nil {
			b.Fatal(err)
		}
		useProfile(managed, document)
		composed, err := mergeProfile(document, overlay)
		if err != nil {
			b.Fatal(err)
		}
		var config struct {
			Proxies   []map[string]any `yaml:"proxies"`
			Rules     []string         `yaml:"rules"`
			DNS       map[string]any   `yaml:"dns"`
			MixedPort int              `yaml:"mixed-port"`
		}
		if err := composed.Decode(&config); err != nil {
			b.Fatal(err)
		}
	}
}
