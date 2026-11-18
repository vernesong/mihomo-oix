// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"io"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/metacubex/tailscale/types/result"
	"github.com/metacubex/tailscale/util/lineiter"
	"github.com/metacubex/tailscale/version"
	"go4.org/mem"
)

func TestLikelyHomeRouterIPSyscallExec(t *testing.T) {
	syscallIP, _, syscallOK := likelyHomeRouterIPBSDFetchRIB()
	netstatIP, netstatIf, netstatOK := likelyHomeRouterIPDarwinExec()

	if syscallOK != netstatOK || syscallIP != netstatIP {
		t.Errorf("syscall() = %v, %v, netstat = %v, %v",
			syscallIP, syscallOK,
			netstatIP, netstatOK,
		)
	}

	if !syscallOK {
		return
	}

	def, err := defaultRoute()
	if err != nil {
		t.Errorf("defaultRoute() error: %v", err)
	}

	if def.InterfaceName != netstatIf {
		t.Errorf("syscall default route interface %s differs from netstat %s", def.InterfaceName, netstatIf)
	}
}

/*
Parse out 10.0.0.1 and en0 from:

$ netstat -r -n -f inet
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGSc           en0
default            link#14            UCSI         utun2
10/16              link#4             UCS            en0      !
10.0.0.1/32        link#4             UCS            en0      !
...
*/
func likelyHomeRouterIPDarwinExec() (ret netip.Addr, netif string, ok bool) {
	if version.IsMobile() {
		// Don't try to do subprocesses on iOS. Ends up with log spam like:
		// kernel: "Sandbox: IPNExtension(86580) deny(1) process-fork"
		// This is why we have likelyHomeRouterIPDarwinSyscall.
		return ret, "", false
	}
	cmd := exec.Command("/usr/sbin/netstat", "-r", "-n", "-f", "inet")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer cmd.Wait()
	defer io.Copy(io.Discard, stdout) // clear the pipe to prevent hangs

	var f []mem.RO
	lineiter.Reader(stdout)(func(lr result.Of[[]byte]) bool {
		lineb, err := lr.Value()
		if err != nil {
			return false
		}
		line := mem.B(lineb)
		if !mem.Contains(line, mem.S("default")) {
			return true
		}
		f = mem.AppendFields(f[:0], line)
		if len(f) < 4 || !f[0].EqualString("default") {
			return true
		}
		ipm, flagsm, netifm := f[1], f[2], f[3]
		if !mem.Contains(flagsm, mem.S("G")) {
			return true
		}
		if mem.Contains(flagsm, mem.S("I")) {
			return true
		}
		ip, err := netip.ParseAddr(string(mem.Append(nil, ipm)))
		if err == nil && ip.IsPrivate() {
			ret = ip
			netif = netifm.StringCopy()
			return false
		}
		return true
	})
	return ret, netif, ret.IsValid()
}

func TestFetchRoutingTable(t *testing.T) {
	// Issue 1345: this used to be flaky on darwin.
	for i := 0; i < 20; i++ {
		_, err := fetchRoutingTable()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestUpdateLastKnownDefaultRouteInterface(t *testing.T) {
	// Pick some interface on the machine
	interfaces, err := netInterfaces()
	if err != nil || len(interfaces) == 0 {
		t.Fatalf("netInterfaces() error: %v", err)
	}

	// Set it as our last known default route interface
	ifName := interfaces[0].Name
	UpdateLastKnownDefaultRouteInterface(ifName)

	// And make sure we can get it back
	route, err := OSDefaultRoute()
	if err != nil {
		t.Fatalf("OSDefaultRoute() error: %v", err)
	}
	want, got := ifName, route.InterfaceName
	if want != got {
		t.Errorf("OSDefaultRoute() = %q, want %q", got, want)
	}
}
