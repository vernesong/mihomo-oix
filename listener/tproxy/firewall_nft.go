package tproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"go4.org/netipx"
)

const nftTProxyTable = "mihomo_tproxy"

var errNFTPreflight = errors.New("nftables TPROXY preflight failed (check permissions and kernel nft_tproxy support)")

// The nft backend, like the original automatic iptables path, manages IPv4.
// Preserve the legacy interface meaning: PREROUTING is not interface-scoped,
// while local output and gateway forwarding/NAT use inbound-interface.
type nftFirewall struct {
	run      firewallRunner
	ifname   string
	bypass   []string
	tport    uint16
	dnsredir bool
	dport    uint16
	mark     int32

	tableApplied, routeAdded, ruleAdded bool
}

func (f *nftFirewall) setup() error {
	rules, err := f.rules()
	if err != nil {
		return err
	}
	// Probe the actual kernel rules, including NFT_TPROXY support,
	// before changing policy routes.
	if _, err = f.run(rules, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("%w: %w", errNFTPreflight, err)
	}
	if _, err = f.run("", "ip", "-4", "route", "add", "local", "default", "dev", "lo", "table", PROXY_ROUTE_TABLE); err != nil {
		return err
	}
	f.routeAdded = true
	if _, err = f.run("", "ip", "-4", "rule", "add", "fwmark", PROXY_FWMARK, "lookup", PROXY_ROUTE_TABLE); err != nil {
		return err
	}
	f.ruleAdded = true
	if f.ifname != "lo" {
		if err = ensureIPv4Forwarding(f.run); err != nil {
			return err
		}
	}
	// A single nft transaction replaces only our own table. Track even an
	// uncertain command failure so rollback removes possibly applied rules.
	f.tableApplied = true
	if _, err = f.run(rules, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("apply nftables TPROXY rules: %w", err)
	}
	return nil
}

func (f *nftFirewall) cleanup() error {
	// Stop interception before removing the policy route it relies on.
	if f.tableApplied {
		if _, err := f.run(nftDeleteTable(), "nft", "-f", "-"); err != nil {
			return err
		}
		f.tableApplied = false
	}
	var errs []error
	if f.ruleAdded {
		if _, err := f.run("", "ip", "-4", "rule", "del", "fwmark", PROXY_FWMARK, "lookup", PROXY_ROUTE_TABLE); err != nil {
			errs = append(errs, err)
		} else {
			f.ruleAdded = false
		}
	}
	if f.routeAdded && !f.ruleAdded {
		if _, err := f.run("", "ip", "-4", "route", "del", "local", "default", "dev", "lo", "table", PROXY_ROUTE_TABLE); err != nil {
			errs = append(errs, err)
		} else {
			f.routeAdded = false
		}
	}
	return errors.Join(errs...)
}

func nftDeleteTable() string {
	// add is idempotent, making this work after an external firewall restart too.
	return "add table ip " + nftTProxyTable + "\ndelete table ip " + nftTProxyTable + "\n"
}

func (f *nftFirewall) rules() (string, error) {
	// Only allow literal Linux interface names in the generated nft syntax.
	if f.ifname == "" || len(f.ifname) > 15 || strings.Trim(f.ifname, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-") != "" || f.ifname == "." || f.ifname == ".." {
		return "", fmt.Errorf("invalid TPROXY inbound-interface %q", f.ifname)
	}
	if f.tport == 0 || (f.dnsredir && f.dport == 0) {
		return "", errors.New("TPROXY and enabled DNS redirect ports must be greater than zero")
	}
	if f.mark == 0 || f.mark == 0x2d0 {
		return "", errors.New("TPROXY outbound routing-mark must be nonzero and different from 0x2d0")
	}
	var addresses netipx.IPSetBuilder
	for _, raw := range slices.Concat(tproxyIPv4Bypass, f.bypass) {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || !prefix.Addr().Is4() {
			return "", fmt.Errorf("invalid IPv4 TPROXY bypass CIDR %q", raw)
		}
		addresses.AddPrefix(prefix.Masked())
	}
	set, err := addresses.IPSet()
	if err != nil {
		return "", err
	}
	var prefixes []string
	for _, prefix := range set.Prefixes() {
		prefixes = append(prefixes, prefix.String())
	}
	var b strings.Builder
	b.WriteString(nftDeleteTable())
	fmt.Fprintf(&b, "table ip %s {\n", nftTProxyTable)
	fmt.Fprintf(&b, " set bypass { type ipv4_addr; flags interval; elements = { %s }; }\n", strings.Join(prefixes, ", "))
	b.WriteString(" chain prerouting {\n  type filter hook prerouting priority mangle - 1; policy accept;\n")
	fmt.Fprintf(&b, "  meta mark %#x return\n", uint32(f.mark))
	b.WriteString("  ip saddr 172.17.0.0/16 return\n")
	if f.dnsredir {
		b.WriteString("  meta l4proto { tcp, udp } th dport 53 return\n")
	}
	b.WriteString("  fib daddr type local return\n  ip daddr @bypass return\n")
	// nft_tproxy already looks up established transparent sockets before the listener.
	// Avoid requiring the optional nft_socket expression solely for a divert shortcut.
	fmt.Fprintf(&b, "  meta l4proto { tcp, udp } tproxy to :%d meta mark set %s accept\n }\n", f.tport, PROXY_FWMARK)
	b.WriteString(" chain output {\n  type route hook output priority mangle - 1; policy accept;\n")
	fmt.Fprintf(&b, "  oifname != \"%s\" return\n", f.ifname)
	fmt.Fprintf(&b, "  meta mark %#x return\n", uint32(f.mark))
	if f.dnsredir {
		b.WriteString("  udp dport { 53, 123, 137 } return\n  tcp dport 53 return\n")
	}
	b.WriteString("  fib daddr type { local, broadcast } return\n  ip daddr @bypass return\n")
	fmt.Fprintf(&b, "  meta l4proto { tcp, udp } meta mark set %s\n }\n", PROXY_FWMARK)
	if f.dnsredir {
		b.WriteString(" chain dns_prerouting {\n  type nat hook prerouting priority dstnat - 1; policy accept;\n")
		fmt.Fprintf(&b, "  meta mark %#x return\n", uint32(f.mark))
		b.WriteString("  ip saddr 172.17.0.0/16 return\n  ip daddr 127.0.0.0/8 return\n")
		fmt.Fprintf(&b, "  meta l4proto { tcp, udp } th dport 53 redirect to :%d\n }\n", f.dport)
		b.WriteString(" chain dns_output {\n  type nat hook output priority -101; policy accept;\n")
		fmt.Fprintf(&b, "  meta mark %#x return\n", uint32(f.mark))
		b.WriteString("  ip saddr 172.17.0.0/16 return\n")
		fmt.Fprintf(&b, "  meta l4proto { tcp, udp } th dport 53 redirect to :%d\n }\n", f.dport)
	}
	if f.ifname != "lo" {
		b.WriteString(" chain postrouting {\n  type nat hook postrouting priority srcnat; policy accept;\n")
		fmt.Fprintf(&b, "  oifname \"%s\" fib saddr type != local masquerade\n }\n", f.ifname)
	}
	b.WriteString("}\n")
	return b.String(), nil
}
