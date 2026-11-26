package outboundgroup

import (
	"math"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestURLTestRechecksAnUnmeasuredSelectionAfterFirstResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		first, measured := newURLTestFakeProxy("first", math.MaxUint16), newURLTestFakeProxy("measured", math.MaxUint16)
		group, err := NewURLTest(GroupCommonOption{Name: "fixture", URL: C.DefaultTestURL}, URLTestOption{}, first,
			[]P.ProxyProvider{&urlTestFakeProvider{proxies: []C.Proxy{first, measured}}})
		if err != nil {
			t.Fatal(err)
		}
		if got := group.Now(); got != "first" {
			t.Fatalf("initial selection = %s", got)
		}
		measured.delay = 50
		if got := group.Now(); got != "first" {
			t.Fatalf("initial hold was bypassed: %s", got)
		}
		time.Sleep(time.Second)
		if got := group.Now(); got != "measured" {
			t.Fatalf("measured result is hidden by the unmeasured cache: %s", got)
		}
		first.delay = 10
		time.Sleep(time.Second)
		if got := group.Now(); got != "measured" {
			t.Fatalf("a measured selection lost its normal cache interval: %s", got)
		}
		group.ForceSet("first")
		if got := group.Now(); got != "first" {
			t.Fatalf("manual selection did not override the cache: %s", got)
		}
	})
}

func TestURLTestPrefersUnmeasuredMemberOverKnownFailedMembers(t *testing.T) {
	first, second, unmeasured := newURLTestFakeProxy("first", math.MaxUint16), newURLTestFakeProxy("second", math.MaxUint16), newURLTestFakeProxy("new", math.MaxUint16)
	first.alive, second.alive = false, false
	group, err := NewURLTest(GroupCommonOption{Name: "fixture", URL: C.DefaultTestURL}, URLTestOption{}, first,
		[]P.ProxyProvider{&urlTestFakeProvider{proxies: []C.Proxy{first, second, unmeasured}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := group.Now(); got != unmeasured.Name() {
		t.Fatalf("known failed member %q hid the unmeasured candidate", got)
	}
}

type selectionProxy struct {
	C.Proxy
	name  string
	delay uint16
}

func TestURLTestSelectionAndStatusCanRunTogether(t *testing.T) {
	first, second := newURLTestFakeProxy("first", 100), newURLTestFakeProxy("second", 120)
	group, err := NewURLTest(GroupCommonOption{Name: "fixture", URL: C.DefaultTestURL}, URLTestOption{Tolerance: 50}, first,
		[]P.ProxyProvider{&urlTestFakeProvider{proxies: []C.Proxy{first, second}}})
	if err != nil {
		t.Fatal(err)
	}
	var work sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		work.Add(1)
		go func(index int) {
			defer work.Done()
			for range 200 {
				if index%2 == 0 {
					group.ForceSet(first.Name())
				} else {
					_ = group.Now()
					if _, err := group.MarshalJSON(); err != nil {
						t.Error(err)
					}
				}
			}
		}(worker)
	}
	work.Wait()
}

func (p *selectionProxy) Name() string                      { return p.name }
func (p *selectionProxy) AliveForTestUrl(string) bool       { return true }
func (p *selectionProxy) LastDelayForTestUrl(string) uint16 { return p.delay }

func TestURLTestToleranceIncludesFirstMember(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		current := &selectionProxy{name: "current", delay: 120}
		candidate := &selectionProxy{name: "candidate", delay: 100}
		members := []C.Proxy{current, candidate}
		if reverse {
			members[0], members[1] = members[1], members[0]
		}
		group := &URLTest{fastNode: current, tolerance: 50}
		if got := group.selectFast(members, nil); got != current {
			t.Fatalf("reverse=%v: switched below tolerance to %s", reverse, got.Name())
		}
		replacement := &selectionProxy{name: current.name, delay: current.delay}
		for index, proxy := range members {
			if proxy == current {
				members[index] = replacement
			}
		}
		if got := group.selectFast(members, nil); got != replacement {
			t.Fatalf("reverse=%v: kept the previous provider's proxy object", reverse)
		}
		candidate.delay = 60
		if got := group.selectFast(members, nil); got != candidate {
			t.Fatalf("reverse=%v: did not switch above tolerance", reverse)
		}
	}
}
