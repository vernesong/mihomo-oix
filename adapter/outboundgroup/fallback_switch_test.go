package outboundgroup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

type fallbackSwitchProxy struct {
	C.Proxy
	alive   atomic.Bool
	probe   func(context.Context)
	inspect func()
}

func (p *fallbackSwitchProxy) AliveForTestUrl(string) bool {
	if p.inspect != nil {
		p.inspect()
	}
	return p.alive.Load()
}
func (p *fallbackSwitchProxy) URLTest(ctx context.Context, _ string, _ utils.IntRanges[uint16]) (uint16, error) {
	if p.probe != nil {
		p.probe(ctx)
	}
	return 1, nil
}

func fallbackSwitchNode(name string, alive bool) *fallbackSwitchProxy {
	p := &fallbackSwitchProxy{Proxy: newURLTestFakeProxy(name, 10)}
	p.alive.Store(alive)
	return p
}
func fallbackSwitchGroup(t *testing.T, nodes ...C.Proxy) *Fallback {
	t.Helper()
	f, err := NewFallback(GroupCommonOption{Name: "fixture", URL: C.DefaultTestURL}, FallbackOption{}, nodes[0],
		[]P.ProxyProvider{&urlTestFakeProvider{proxies: nodes}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFallbackSwitchDeadLastPinUsesEarlierHealthyNode(t *testing.T) {
	first, healthy, pin := fallbackSwitchNode("first", false), fallbackSwitchNode("healthy", true), fallbackSwitchNode("pin", false)
	f := fallbackSwitchGroup(t, first, healthy, pin)
	f.ForceSet("pin")
	if got := f.Now(); got != "healthy" {
		t.Fatalf("dead pin selected %s instead of healthy", got)
	}
}

func TestFallbackSlowProbeCannotOverwriteANewerSelection(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "set", true: "force"}[force], func(t *testing.T) {
			old, latest := fallbackSwitchNode("old", false), fallbackSwitchNode("latest", true)
			entered, release := make(chan struct{}, 1), make(chan struct{})
			defer close(release)
			old.probe = func(ctx context.Context) {
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
				}
				old.alive.Store(true)
			}
			f := fallbackSwitchGroup(t, old, latest)
			done := make(chan error, 1)
			go func() { done <- f.Set("old") }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("probe did not start")
			}
			if force {
				f.ForceSet("latest")
			} else if err := f.Set("latest"); err != nil {
				t.Fatal(err)
			}
			release <- struct{}{}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("old probe did not finish")
			}
			if got := f.Now(); got != "latest" {
				t.Fatalf("old probe overwrote latest selection: %s", got)
			}
		})
	}
}

func TestFallbackOldHealthCheckDoesNotClearTheSameNewPin(t *testing.T) {
	healthy, pin := fallbackSwitchNode("healthy", true), fallbackSwitchNode("pin", false)
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	var once sync.Once
	pin.inspect = func() { once.Do(func() { entered <- struct{}{}; <-release }) }
	f := fallbackSwitchGroup(t, healthy, pin)
	f.ForceSet("pin")
	done := make(chan string, 1)
	go func() { done <- f.Now() }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("health check did not start")
	}
	f.ForceSet("pin")
	release <- struct{}{}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health check did not finish")
	}
	if got := f.selected.Load(); got != "pin" {
		t.Fatal("old health result cleared a newer pin")
	}
}

func TestFallbackSelectionAndStatusCanRunTogether(t *testing.T) {
	first, second := fallbackSwitchNode("first", true), fallbackSwitchNode("second", true)
	f := fallbackSwitchGroup(t, first, second)
	var work sync.WaitGroup
	for i := 0; i < 4; i++ {
		work.Add(1)
		go func(index int) {
			defer work.Done()
			for range 100 {
				if index%2 == 0 {
					f.ForceSet("first")
				} else {
					_ = f.Now()
					if _, err := f.MarshalJSON(); err != nil {
						t.Error(err)
					}
				}
			}
		}(i)
	}
	work.Wait()
}
