package config

import "testing"

func TestFirewallBackendConfig(t *testing.T) {
	for _, value := range []string{"", "auto", "iptables", "nftables", "nft", "AUTO"} {
		t.Run(value, func(t *testing.T) {
			raw, err := UnmarshalRawConfig([]byte("iptables:\n  enable: true\n  backend: '" + value + "'\n  inbound-interface: br-lan\n"))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := parseIPTables(raw)
			valid := value == "" || value == "auto" || value == "iptables" || value == "nftables"
			if !valid {
				if err == nil {
					t.Fatal("accepted unsupported backend")
				}
				return
			}
			if value == "" {
				value = "auto"
			}
			if err != nil || cfg.Backend != value || !cfg.Enable || cfg.InboundInterface != "br-lan" || !cfg.DnsRedirect {
				t.Fatalf("unexpected config: %+v, %v", cfg, err)
			}
		})
	}
	raw := DefaultRawConfig()
	if raw.IPTables.Backend != "auto" || raw.IPTables.Enable {
		t.Fatal("wrong firewall defaults")
	}
}

func TestOldFirewallYAMLWithoutBackend(t *testing.T) {
	for i, input := range []string{
		"iptables:\n  enable: true\n",
		"iptables:\n  enable: true\n  inbound-interface: eth0\n  dns-redirect: false\n  bypass: [100.1.0.0/16]\n",
	} {
		raw, err := UnmarshalRawConfig([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := parseIPTables(raw)
		if err != nil || cfg.Backend != "auto" || !cfg.Enable {
			t.Fatalf("old YAML: %+v, %v", cfg, err)
		}
		if i == 0 {
			if cfg.InboundInterface != "lo" || !cfg.DnsRedirect || len(cfg.Bypass) != 0 {
				t.Fatalf("legacy defaults changed: %+v", cfg)
			}
		} else if cfg.InboundInterface != "eth0" || cfg.DnsRedirect || len(cfg.Bypass) != 1 || cfg.Bypass[0] != "100.1.0.0/16" {
			t.Fatalf("legacy explicit fields changed: %+v", cfg)
		}
	}
}
