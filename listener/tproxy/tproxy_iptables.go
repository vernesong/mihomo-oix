package tproxy

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/log"
)

var (
	iptablesCleanup    []string
	runIPTablesCommand = func(command string) (string, error) {
		args := strings.Fields(command)
		out, err := runFirewallCommand("", args[0], args[1:]...)
		return string(out), err
	}
)

const (
	PROXY_FWMARK      = "0x2d0"
	PROXY_ROUTE_TABLE = "0x2d0"
)

func SetTProxyIPTables(ifname string, bypass []string, tport uint16, dnsredir bool, dport uint16) error {
	if _, err := runIPTablesCommand("iptables -V"); err != nil {
		return fmt.Errorf("iptables backend unavailable on %s: %w", runtime.GOOS, err)
	}

	if ifname == "" {
		return errors.New("the 'interface-name' can not be empty")
	}

	if len(iptablesCleanup) != 0 {
		return errors.New("previous iptables rules must be cleaned up first")
	}
	var setupErr error
	execCmd := func(command string) {
		if setupErr != nil {
			return
		}
		log.Debugln("[IPTABLES] %s", command)
		if _, setupErr = runIPTablesCommand(command); setupErr != nil {
			setupErr = fmt.Errorf("%s: %w", command, setupErr)
			return
		}
		if undo := undoIPTablesCommand(command); undo != "" {
			iptablesCleanup = append(iptablesCleanup, undo)
		}
	}

	// Claim the exclusive route before adding a non-exclusive policy rule.
	// A route conflict must not add or remove another instance's matching rule.
	execCmd(fmt.Sprintf("ip -f inet route add local default dev %s table %s", ifname, PROXY_ROUTE_TABLE))
	execCmd(fmt.Sprintf("ip -f inet rule add fwmark %s lookup %s", PROXY_FWMARK, PROXY_ROUTE_TABLE))

	// set FORWARD
	if ifname != "lo" {
		if setupErr == nil {
			setupErr = ensureIPv4Forwarding(func(input, name string, args ...string) ([]byte, error) {
				out, err := runIPTablesCommand(strings.Join(append([]string{name}, args...), " "))
				return []byte(out), err
			})
		}
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -j ACCEPT", ifname))
		execCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s -j ACCEPT", ifname))
	}

	// set mihomo divert
	execCmd("iptables -t mangle -N mihomo_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_divert -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd("iptables -t mangle -A mihomo_divert -j ACCEPT")

	// set pre routing
	execCmd("iptables -t mangle -N mihomo_prerouting")
	execCmd("iptables -t mangle -A mihomo_prerouting -s 172.17.0.0/16 -j RETURN")
	if dnsredir {
		execCmd("iptables -t mangle -A mihomo_prerouting -p udp --dport 53 -j ACCEPT")
		execCmd("iptables -t mangle -A mihomo_prerouting -p tcp --dport 53 -j ACCEPT")
	}
	execCmd("iptables -t mangle -A mihomo_prerouting -m addrtype --dst-type LOCAL -j RETURN")
	addLocalnetworkToChain("mihomo_prerouting", bypass, execCmd)
	execCmd("iptables -t mangle -A mihomo_prerouting -p tcp -m socket -j mihomo_divert")
	execCmd("iptables -t mangle -A mihomo_prerouting -p udp -m socket -j mihomo_divert")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_prerouting -p tcp -j TPROXY --on-port %d --tproxy-mark %s/%s", tport, PROXY_FWMARK, PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_prerouting -p udp -j TPROXY --on-port %d --tproxy-mark %s/%s", tport, PROXY_FWMARK, PROXY_FWMARK))
	execCmd("iptables -t mangle -A PREROUTING -j mihomo_prerouting")

	if dnsredir {
		execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to %d", dport))
		execCmd(fmt.Sprintf("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to %d", dport))
	}

	// set post routing
	if ifname != "lo" {
		execCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -m addrtype ! --src-type LOCAL -j MASQUERADE", ifname))
	}

	// set output
	execCmd("iptables -t mangle -N mihomo_output")
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -m mark --mark %#x -j RETURN", dialer.DefaultRoutingMark.Load()))
	if dnsredir {
		execCmd("iptables -t mangle -A mihomo_output -p udp -m multiport --dports 53,123,137 -j ACCEPT")
		execCmd("iptables -t mangle -A mihomo_output -p tcp --dport 53 -j ACCEPT")
	}
	execCmd("iptables -t mangle -A mihomo_output -m addrtype --dst-type LOCAL -j RETURN")
	execCmd("iptables -t mangle -A mihomo_output -m addrtype --dst-type BROADCAST -j RETURN")
	addLocalnetworkToChain("mihomo_output", bypass, execCmd)
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -p tcp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -A mihomo_output -p udp -j MARK --set-mark %s", PROXY_FWMARK))
	execCmd(fmt.Sprintf("iptables -t mangle -I OUTPUT -o %s -j mihomo_output", ifname))

	// set dns output
	if dnsredir {
		execCmd("iptables -t nat -N mihomo_dns_output")
		execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -m mark --mark %#x -j RETURN", dialer.DefaultRoutingMark.Load()))
		execCmd("iptables -t nat -A mihomo_dns_output -s 172.17.0.0/16 -j RETURN")
		execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -p udp -j REDIRECT --to-ports %d", dport))
		execCmd(fmt.Sprintf("iptables -t nat -A mihomo_dns_output -p tcp -j REDIRECT --to-ports %d", dport))
		execCmd("iptables -t nat -I OUTPUT -p tcp --dport 53 -j mihomo_dns_output")
		execCmd("iptables -t nat -I OUTPUT -p udp --dport 53 -j mihomo_dns_output")
	}

	if setupErr != nil {
		return errors.Join(setupErr, CleanupTProxyIPTables())
	}
	return nil
}

// Cleanup removes only successfully installed rules, in reverse order. A failed
// deletion stays in the journal for retry instead of forgetting partial state.
func CleanupTProxyIPTables() error {
	for len(iptablesCleanup) > 0 {
		i := len(iptablesCleanup) - 1
		if _, err := runIPTablesCommand(iptablesCleanup[i]); err != nil {
			return fmt.Errorf("cleanup %s: %w", iptablesCleanup[i], err)
		}
		iptablesCleanup = iptablesCleanup[:i]
	}
	return nil
}

func undoIPTablesCommand(command string) string {
	if strings.HasPrefix(command, "ip ") {
		return strings.Replace(command, " add ", " del ", 1)
	}
	if strings.HasPrefix(command, "iptables ") {
		for _, op := range []string{" -A ", " -I "} {
			if strings.Contains(command, op) {
				return strings.Replace(command, op, " -D ", 1)
			}
		}
		if strings.Contains(command, " -N ") {
			return strings.Replace(command, " -N ", " -X ", 1)
		}
	}
	return ""
}

func addLocalnetworkToChain(chain string, bypass []string, execCmd func(string)) {
	for _, bp := range bypass {
		_, _, err := net.ParseCIDR(bp)
		if err != nil {
			log.Warnln("[IPTABLES] %s", err)
			continue
		}
		execCmd(fmt.Sprintf("iptables -t mangle -A %s -d %s -j RETURN", chain, bp))
	}
	for _, prefix := range tproxyIPv4Bypass {
		execCmd(fmt.Sprintf("iptables -t mangle -A %s -d %s -j RETURN", chain, prefix))
	}
}
