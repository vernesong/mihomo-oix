package tproxy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
)

type firewallRunner func(input, name string, args ...string) ([]byte, error)

type firewallEnvironment struct {
	nft, iptables, fw4 bool
	legacyIPTables     bool
}

var tproxyIPv4Bypass = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
}

func detectFirewallEnvironment(hasCommand func(string) bool, run firewallRunner) firewallEnvironment {
	env := firewallEnvironment{nft: hasCommand("nft"), iptables: hasCommand("iptables"), fw4: hasCommand("fw4")}
	if env.fw4 {
		return env
	}
	if env.nft {
		tables, err := run("", "nft", "list", "tables")
		if err != nil || strings.TrimSpace(string(tables)) != "" {
			// Existing or unreadable nftables state must not be mixed with legacy rules.
			return env
		}
	}
	if env.iptables {
		version, err := run("", "iptables", "-V")
		env.legacyIPTables = err == nil && strings.Contains(string(version), "legacy")
	}
	return env
}

func ensureIPv4Forwarding(run firewallRunner) error {
	value, err := run("", "sysctl", "-n", "net.ipv4.ip_forward")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(value)) == "1" {
		return nil
	}
	_, err = run("", "sysctl", "-w", "net.ipv4.ip_forward=1")
	return err
}

// Prefer native nftables. A fallback is allowed only after a failed dry run on
// an unused nftables stack; never mix legacy rules into an active nft firewall.
func selectFirewallBackend(requested string, env firewallEnvironment) (string, error) {
	switch requested {
	case "", "auto":
		if env.fw4 {
			requested = "nftables"
		} else if env.legacyIPTables {
			requested = "iptables"
		} else if env.nft {
			requested = "nftables"
		} else {
			requested = "iptables"
		}
	case "iptables", "nftables":
	default:
		return "", fmt.Errorf("unknown firewall backend %q", requested)
	}
	if requested == "nftables" && !env.nft {
		return "", errors.New("nftables backend requires the nft command (Firewall4 must not fall back to legacy iptables)")
	}
	if requested == "iptables" && !env.iptables {
		return "", errors.New("iptables backend requires the iptables command")
	}
	return requested, nil
}

func canFallbackToIPTables(requested string, env firewallEnvironment, run firewallRunner, setupErr error) bool {
	if (requested != "" && requested != "auto") || env.fw4 || !env.iptables || !errors.Is(setupErr, errNFTPreflight) {
		return false
	}
	tables, err := run("", "nft", "list", "tables")
	return err == nil && strings.TrimSpace(string(tables)) == ""
}

func runFirewallCommand(input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

var firewallState struct {
	sync.Mutex
	cleanup func() error
}

// SetTProxyFirewall keeps the existing iptables configuration key and TPROXY
// listeners while selecting the rule backend for the running Linux system.
func SetTProxyFirewall(backend, ifname string, bypass []string, tport uint16, dnsredir bool, dport uint16) (string, error) {
	firewallState.Lock()
	defer firewallState.Unlock()
	if runtime.GOOS != "linux" {
		return "", errors.New("automatic TPROXY firewall configuration requires Linux")
	}
	if firewallState.cleanup != nil {
		return "", errors.New("previous TPROXY firewall must be cleaned up before setup")
	}
	hasCommand := func(name string) bool {
		_, err := exec.LookPath(name)
		return err == nil
	}
	env := detectFirewallEnvironment(hasCommand, runFirewallCommand)
	selected, err := selectFirewallBackend(backend, env)
	if err != nil {
		return "", err
	}
	setupIPTables := func() (string, error) {
		if err = SetTProxyIPTables(ifname, bypass, tport, dnsredir, dport); err != nil {
			if len(iptablesCleanup) != 0 {
				firewallState.cleanup = CleanupTProxyIPTables
			}
			return "", err
		}
		firewallState.cleanup = CleanupTProxyIPTables
		return "iptables", nil
	}
	if selected == "iptables" {
		return setupIPTables()
	}
	fw := &nftFirewall{
		run:    runFirewallCommand,
		ifname: ifname, bypass: bypass, tport: tport, dnsredir: dnsredir, dport: dport,
		mark: dialer.DefaultRoutingMark.Load(),
	}
	if err = fw.setup(); err != nil {
		if canFallbackToIPTables(backend, env, runFirewallCommand, err) {
			log.Warnln("[TPROXY] nftables preflight failed on an unused nftables stack; using iptables: %s", err)
			return setupIPTables()
		}
		if cleanupErr := fw.cleanup(); cleanupErr != nil {
			// Keep failed cleanup retryable; do not lose ownership information.
			firewallState.cleanup = fw.cleanup
			return "", errors.Join(err, fmt.Errorf("rollback TPROXY firewall: %w", cleanupErr))
		}
		return "", err
	}
	firewallState.cleanup = fw.cleanup
	return selected, nil
}

func CleanupTProxyFirewall() error {
	firewallState.Lock()
	defer firewallState.Unlock()
	if firewallState.cleanup == nil {
		return nil
	}
	if err := firewallState.cleanup(); err != nil {
		return err
	}
	firewallState.cleanup = nil
	// The executor may already have installed a new user-selected routing mark.
	// Cleanup owns rules, not the current configuration.
	return nil
}
