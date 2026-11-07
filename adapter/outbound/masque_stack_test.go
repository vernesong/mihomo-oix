package outbound

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

func memoryStackModes() []string {
	modes := []string{ipStackMips}
	if features.WithGVisor {
		modes = append(modes, ipStackGVisor)
	}
	return modes
}

func TestMasqueStackValidationCompatibility(t *testing.T) {
	option := masqueMemoryOption(t)
	cases := []struct {
		ip, ipv6 string
		mtu      int
	}{
		{"10.0.0.2/32", "", 0},
		{"10.0.0.2/24", "fd00::2/64", 1280},
		{"10.0.0.2/32", "", 67},
		{"10.0.0.2/32", "", 65536},
		{"10.0.0.2/32", "", -1},
		{"10.0.0.2/32", "fd00::2/128", 1200},
		{"10.0.0.255/24", "", 1280},
		{"10.0.0.255/32", "10.0.0.2/24", 1280},
		{"10.0.0.1/31", "", 1280},
		{"10.0.0.3/30", "", 1280},
		{"0.0.0.0/32", "", 1280},
		{"224.0.0.1/32", "", 1280},
		{"255.255.255.255/32", "", 1280},
		{"", "::/128", 1280},
		{"", "ff02::1/128", 1280},
		{"10.0.0.2/32", "10.0.0.2/24", 1280},
		{"fd00::2/128", "fd00::2/64", 1280},
		{"", "::ffff:10.0.0.2/128", 1280},
		{"", "::ffff:10.0.0.2/80", 1280},
	}
	for _, mode := range memoryStackModes() {
		t.Run(mode, func(t *testing.T) {
			// The pinned sing-wireguard constructor returns nil without closing
			// its gVisor stack when AddProtocolAddress fails. Keep both the old
			// and new rejection paths covered, but contain those workers in a
			// child process so they cannot interfere with later protocol tests.
			const childEnv = "MIHOMO_TEST_MASQUE_STACK_VALIDATION"
			if mode == ipStackGVisor && os.Getenv(childEnv) != "1" {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, "-test.run=^TestMasqueStackValidationCompatibility$/^gvisor$", "-test.timeout=30s")
				cmd.Env = append(os.Environ(), childEnv+"=1")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("gVisor validation: %v\n%s", err, output)
				}
				return
			}
			for _, tc := range cases {
				t.Run(fmt.Sprintf("%s/%s/%d", tc.ip, tc.ipv6, tc.mtu), func(t *testing.T) {
					opt := option
					opt.IPStack.Mode, opt.Ip, opt.Ipv6, opt.MTU = mode, tc.ip, tc.ipv6, tc.mtu
					prefixes, err := opt.Prefixes()
					if err != nil {
						t.Fatal(err)
					}
					mtu := tc.mtu
					if mtu == 0 {
						mtu = 1280
					}
					original, wantErr := newIPStack(opt.IPStack, prefixes, uint32(mtu))
					if wantErr == nil {
						_ = original.Close()
					}
					node, err := NewMasque(opt)
					if wantErr != nil {
						if node != nil {
							_ = node.Close()
						}
						if err == nil || err.Error() != "create device: "+wantErr.Error() {
							t.Fatalf("parse error = %v, want original stack error %v", err, wantErr)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					defer node.Close()
					if canDeferIPStack(prefixes, uint32(mtu)) && node.tunDevice != nil {
						t.Fatal("unused node constructed an IP stack")
					}
					if _, err := node.startIPStack(); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func TestMasqueCloseDoesNotStartUnusedStack(t *testing.T) {
	option := masqueMemoryOption(t)
	for _, mode := range memoryStackModes() {
		t.Run(mode, func(t *testing.T) {
			option.IPStack.Mode = mode
			node, err := NewMasque(option)
			if err != nil {
				t.Fatal(err)
			}
			if node.tunDevice != nil {
				t.Fatal("constructed an unused stack")
			}
			_ = node.Close()
			_ = node.Close()
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("10.0.0.1"), DstPort: 80}
			if _, err := node.DialContext(t.Context(), metadata); !errors.Is(err, context.Canceled) {
				t.Fatalf("dial after close: %v", err)
			}
			if _, err := node.ListenPacketContext(t.Context(), metadata); !errors.Is(err, context.Canceled) {
				t.Fatalf("listen after close: %v", err)
			}
			if node.tunDevice != nil {
				t.Fatal("close or subsequent I/O created a stack")
			}
		})
	}
}

func TestMasqueStackStartRacingClose(t *testing.T) {
	option := masqueMemoryOption(t)
	for _, mode := range memoryStackModes() {
		t.Run(mode, func(t *testing.T) {
			option.IPStack.Mode = mode
			node, err := NewMasque(option)
			if err != nil {
				t.Fatal(err)
			}
			defer node.Close()
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					if _, err := node.startIPStack(); err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("start during close: %v", err)
					}
				})
			}
			_ = node.Close()
			wg.Wait()
			if _, err := node.startIPStack(); !errors.Is(err, context.Canceled) {
				t.Fatalf("start after close: %v", err)
			}
			if node.tunDevice != nil {
				if conn, err := node.tunDevice.DialUDP(t.Context(), "udp", netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.1:53")); err == nil {
					_ = conn.Close()
					t.Fatal("stack remained usable after close")
				}
				// gVisor reports network-unreachable after removing its routes;
				// mipstack reports ErrClosed. Both must reject the new socket.
			}
		})
	}
}
