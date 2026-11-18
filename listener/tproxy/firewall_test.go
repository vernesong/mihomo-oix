package tproxy

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/dialer"
)

func TestSelectFirewallBackend(t *testing.T) {
	for _, tc := range []struct {
		name, requested string
		env             firewallEnvironment
		want            string
	}{
		{"legacy", "auto", firewallEnvironment{iptables: true}, "iptables"},
		{"native", "auto", firewallEnvironment{nft: true}, "nftables"},
		{"both", "", firewallEnvironment{nft: true, iptables: true}, "nftables"},
		{"fw4", "auto", firewallEnvironment{nft: true, iptables: true, fw4: true, legacyIPTables: true}, "nftables"},
		{"broken fw4 must not use legacy", "auto", firewallEnvironment{fw4: true, iptables: true}, ""},
		{"explicit legacy", "iptables", firewallEnvironment{nft: true, iptables: true}, "iptables"},
		{"missing requested nft", "nftables", firewallEnvironment{iptables: true}, ""},
		{"missing requested legacy", "iptables", firewallEnvironment{nft: true}, ""},
		{"neither", "auto", firewallEnvironment{}, ""},
		{"invalid", "other", firewallEnvironment{nft: true, iptables: true}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectFirewallBackend(tc.requested, tc.env)
			if got != tc.want || (err != nil) != (tc.want == "") {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func testNFTFirewall(t *testing.T) *nftFirewall {
	t.Helper()
	return &nftFirewall{
		run:    func(string, string, ...string) ([]byte, error) { return []byte("1"), nil },
		ifname: "br-lan", tport: 9898, dnsredir: true, dport: 1053, mark: 2158,
	}
}

func TestNFTRejectsInvalidConfigurationBeforeCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*nftFirewall)
	}{
		{"interface injection", func(f *nftFirewall) { f.ifname = "lo\";flush" }},
		{"interface wildcard", func(f *nftFirewall) { f.ifname = "br*" }},
		{"empty interface", func(f *nftFirewall) { f.ifname = "" }},
		{"zero proxy port", func(f *nftFirewall) { f.tport = 0 }},
		{"zero dns port", func(f *nftFirewall) { f.dport = 0 }},
		{"zero bypass mark", func(f *nftFirewall) { f.mark = 0 }},
		{"looping mark", func(f *nftFirewall) { f.mark = 0x2d0 }},
		{"invalid cidr", func(f *nftFirewall) { f.bypass = []string{"1.2.3.4/33"} }},
		{"ipv6 cidr", func(f *nftFirewall) { f.bypass = []string{"::/0"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testNFTFirewall(t)
			tc.edit(f)
			f.run = func(string, string, ...string) ([]byte, error) {
				t.Fatal("ran command on invalid input")
				return []byte("1"), nil
			}
			if err := f.setup(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestNFTSetupFailureRollback(t *testing.T) {
	// Each setup step can fail. Rollback must remove only completed work and
	// leave no policy route or packet interception after a failed start.
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			f := testNFTFirewall(t)
			calls := 0
			f.run = func(input, name string, args ...string) ([]byte, error) {
				calls++
				if name == "iptables" {
					t.Fatal("unexpected backend fallback")
				}
				if calls == failAt {
					return nil, errors.New("injected failure")
				}
				return []byte("1"), nil
			}
			if err := f.setup(); err == nil {
				t.Fatal("setup should fail")
			}
			if err := f.cleanup(); err != nil {
				t.Fatal(err)
			}
			if f.tableApplied || f.routeAdded || f.ruleAdded {
				t.Fatal("rollback retained state")
			}
			before := calls
			if err := f.cleanup(); err != nil || calls != before {
				t.Fatal("cleanup was not idempotent")
			}
			if failAt == 1 && calls != 1 {
				t.Fatal("preflight failure mutated system")
			}
		})
	}
}

func TestNFTCleanupRetainsRetryState(t *testing.T) {
	f := testNFTFirewall(t)
	if err := f.setup(); err != nil {
		t.Fatal(err)
	}
	f.run = func(input, name string, args ...string) ([]byte, error) {
		if name != "nft" {
			t.Fatal("routes removed while interception may still be active")
		}
		return nil, errors.New("busy")
	}
	if err := f.cleanup(); err == nil || !f.tableApplied || !f.ruleAdded || !f.routeAdded {
		t.Fatal("failed cleanup lost state")
	}
	f.run = func(string, string, ...string) ([]byte, error) { return []byte("1"), nil }
	if err := f.cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTRulesNormalizeOverlappingBypass(t *testing.T) {
	f := testNFTFirewall(t)
	f.bypass = []string{"10.1.2.3/24", "10.0.0.0/8", "198.18.0.123/24", "198.18.0.0/25"}
	rules, err := f.rules()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rules, "10.1.2") || strings.Count(rules, "10.0.0.0/8") != 1 || !strings.Contains(rules, "198.18.0.0/24") || strings.Contains(rules, "/25") {
		t.Fatal("overlapping or noncanonical prefixes in nft set")
	}
	f.dnsredir = false
	f.dport = 0
	rules, err = f.rules()
	if err != nil || strings.Contains(rules, "dport 53") || strings.Contains(rules, "redirect to") {
		t.Fatal("disabled DNS redirect still captures DNS")
	}
}

func TestIPTablesFailureRemovesOnlyInstalledRules(t *testing.T) {
	oldRun := runIPTablesCommand
	t.Cleanup(func() { runIPTablesCommand = oldRun; iptablesCleanup = nil })
	// Fail before the first chain is created, and later after DNS interception.
	for _, failure := range []string{"iptables -t mangle -N mihomo_divert", "iptables -t mangle -N mihomo_output"} {
		var installed, removed []string
		runIPTablesCommand = func(command string) (string, error) {
			if command == failure {
				return "", errors.New("injected failure")
			}
			if strings.Contains(command, " -D ") || strings.Contains(command, " -X ") || strings.Contains(command, " del ") {
				removed = append(removed, command)
			} else if undo := undoIPTablesCommand(command); undo != "" {
				installed = append(installed, undo)
			}
			return "", nil
		}
		if err := SetTProxyIPTables("lo", nil, 9898, true, 1053); err == nil {
			t.Fatal("setup reported success")
		}
		if len(installed) != len(removed) || len(iptablesCleanup) != 0 {
			t.Fatalf("incomplete rollback: %v, %v", installed, removed)
		}
		for i := range installed {
			if installed[i] != removed[len(removed)-1-i] {
				t.Fatal("rollback did not reverse successful operations")
			}
		}
	}
}

func TestIPTablesCleanupRetriesFailure(t *testing.T) {
	oldRun := runIPTablesCommand
	t.Cleanup(func() { runIPTablesCommand = oldRun; iptablesCleanup = nil })
	iptablesCleanup = []string{"ip -f inet rule del fwmark 0x2d0 lookup 0x2d0"}
	runIPTablesCommand = func(string) (string, error) { return "", errors.New("busy") }
	if err := CleanupTProxyIPTables(); err == nil || len(iptablesCleanup) != 1 {
		t.Fatal("failed cleanup forgot its rules")
	}
	runIPTablesCommand = func(string) (string, error) { return "", nil }
	if err := CleanupTProxyIPTables(); err != nil || len(iptablesCleanup) != 0 {
		t.Fatal("cleanup retry failed")
	}
}

func TestIPTablesFallbackOnlyBeforeMutationOnUnusedNFTables(t *testing.T) {
	for _, tc := range []struct {
		name, requested, tables string
		env                     firewallEnvironment
		setupErr, probeErr      error
		want                    bool
	}{
		{"unused nft", "auto", "", firewallEnvironment{nft: true, iptables: true}, errNFTPreflight, nil, true},
		{"active nft", "auto", "table inet filter\n", firewallEnvironment{nft: true, iptables: true}, errNFTPreflight, nil, false},
		{"fw4", "auto", "", firewallEnvironment{nft: true, iptables: true, fw4: true}, errNFTPreflight, nil, false},
		{"permission denied", "auto", "", firewallEnvironment{nft: true, iptables: true}, errNFTPreflight, os.ErrPermission, false},
		{"explicit nft", "nftables", "", firewallEnvironment{nft: true, iptables: true}, errNFTPreflight, nil, false},
		{"partial setup", "auto", "", firewallEnvironment{nft: true, iptables: true}, errors.New("apply failed"), nil, false},
		{"no legacy", "auto", "", firewallEnvironment{nft: true}, errNFTPreflight, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := func(string, string, ...string) ([]byte, error) { return []byte(tc.tables), tc.probeErr }
			if got := canFallbackToIPTables(tc.requested, tc.env, run, tc.setupErr); got != tc.want {
				t.Fatalf("fallback = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNFTRouteConflictDoesNotTouchOtherState(t *testing.T) {
	f := testNFTFirewall(t)
	f.run = func(input, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return nil, errors.New("route already exists")
		}
		if name == "nft" && args[0] != "-c" {
			t.Fatal("must not change an existing instance's rules")
		}
		return []byte("1"), nil
	}
	if err := f.setup(); err == nil {
		t.Fatal("route conflict was ignored")
	}
	if err := f.cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTLegacyInterfaceSemantics(t *testing.T) {
	for _, ifname := range []string{"lo", "eth0"} {
		f := testNFTFirewall(t)
		f.ifname = ifname
		rules, err := f.rules()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(rules, "iifname") {
			t.Fatal("legacy PREROUTING must not become LAN-interface scoped")
		}
		if !strings.Contains(rules, "oifname != \""+ifname+"\" return") {
			t.Fatal("legacy local output interface constraint was lost")
		}
		if strings.Contains(rules, "masquerade") != (ifname != "lo") {
			t.Fatal("legacy gateway NAT condition changed")
		}
	}
}

func TestCleanupDoesNotResetNewRoutingMark(t *testing.T) {
	oldMark, oldCleanup := dialer.DefaultRoutingMark.Load(), firewallState.cleanup
	t.Cleanup(func() { dialer.DefaultRoutingMark.Store(oldMark); firewallState.cleanup = oldCleanup })
	dialer.DefaultRoutingMark.Store(2158) // explicitly configured by the incoming reload
	firewallState.cleanup = func() error { return nil }
	if err := CleanupTProxyFirewall(); err != nil {
		t.Fatal(err)
	}
	if dialer.DefaultRoutingMark.Load() != 2158 {
		t.Fatal("cleanup reset the new configuration's routing mark")
	}
}

func TestDetectFirewallEnvironmentKeepsLegacyUntilNativeIsActive(t *testing.T) {
	for _, tc := range []struct {
		name, tables, version, want string
		fw4, unreadable             bool
	}{
		{"old system with nft installed", "", "iptables v1.8.11 (legacy)", "iptables", false, false},
		{"active nft", "table inet filter\n", "iptables v1.8.11 (legacy)", "nftables", false, false},
		{"Firewall4", "", "iptables v1.8.11 (legacy)", "nftables", true, false},
		{"iptables nft wrapper", "", "iptables v1.8.11 (nf_tables)", "nftables", false, false},
		{"unknown native state", "", "iptables v1.8.11 (legacy)", "nftables", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			has := func(name string) bool { return name != "fw4" || tc.fw4 }
			run := func(input, name string, args ...string) ([]byte, error) {
				if name == "nft" {
					if tc.unreadable {
						return nil, os.ErrPermission
					}
					return []byte(tc.tables), nil
				}
				return []byte(tc.version), nil
			}
			backend, err := selectFirewallBackend("auto", detectFirewallEnvironment(has, run))
			if err != nil || backend != tc.want {
				t.Fatalf("backend: %q, %v", backend, err)
			}
		})
	}
}

func TestForwardingSkipsUnnecessaryWrite(t *testing.T) {
	for _, initial := range []string{"0", "1\n"} {
		writes := 0
		run := func(input, name string, args ...string) ([]byte, error) {
			if args[0] == "-n" {
				return []byte(initial), nil
			}
			writes++
			return nil, nil
		}
		if err := ensureIPv4Forwarding(run); err != nil {
			t.Fatal(err)
		}
		if (writes == 1) != (initial == "0") {
			t.Fatalf("initial %q caused %d writes", initial, writes)
		}
	}
}

func TestIPTablesRouteConflictDoesNotTouchOtherState(t *testing.T) {
	oldRun := runIPTablesCommand
	t.Cleanup(func() { runIPTablesCommand = oldRun; iptablesCleanup = nil })
	runIPTablesCommand = func(command string) (string, error) {
		switch command {
		case "iptables -V":
			return "iptables (legacy)", nil
		case "ip -f inet route add local default dev lo table 0x2d0":
			return "", errors.New("route already exists")
		default:
			t.Fatalf("route conflict must not touch existing rules: %s", command)
			return "", nil
		}
	}
	if err := SetTProxyIPTables("lo", nil, 9898, true, 1053); err == nil {
		t.Fatal("route conflict was ignored")
	}
	if len(iptablesCleanup) != 0 {
		t.Fatal("route conflict retained another instance's state")
	}
}
