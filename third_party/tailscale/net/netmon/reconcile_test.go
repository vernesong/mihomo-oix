// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package netmon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale/util/eventbus"
)

func TestPollWallTimeSchedulesReconciliation(t *testing.T) {
	tests := []struct {
		name             string
		state            *State
		lastReconcileAgo time.Duration
		wake             bool
		wantEvent        bool
		wantForce        bool
	}{
		{
			name:             "online",
			state:            &State{HaveV4: true},
			lastReconcileAgo: time.Hour,
		},
		{
			name:             "offline before interval",
			state:            &State{},
			lastReconcileAgo: networkDownReconcileInterval / 2,
		},
		{
			name:             "offline interval elapsed",
			state:            &State{},
			lastReconcileAgo: networkDownReconcileInterval + time.Second,
			wantEvent:        true,
		},
		{
			name:             "wake forces reconciliation",
			state:            &State{HaveV4: true},
			lastReconcileAgo: time.Second,
			wake:             true,
			wantEvent:        true,
			wantForce:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timer := time.NewTimer(time.Hour)
			defer timer.Stop()

			lastWall := wallTime()
			if tt.wake {
				lastWall = lastWall.Add(-time.Hour)
			}
			m := &Monitor{
				change:        make(chan bool, 1),
				ifState:       tt.state,
				wallTimer:     timer,
				lastWall:      lastWall,
				lastReconcile: time.Now().Add(-tt.lastReconcileAgo),
			}

			m.pollWallTime()

			select {
			case force := <-m.change:
				if !tt.wantEvent {
					t.Fatalf("unexpected reconciliation event (force=%v)", force)
				}
				if force != tt.wantForce {
					t.Fatalf("force = %v, want %v", force, tt.wantForce)
				}
			default:
				if tt.wantEvent {
					t.Fatal("reconciliation event was not scheduled")
				}
			}
		})
	}
}

func TestOfflineReconciliationObservesRecoveredInterfaceWithoutOSEvent(t *testing.T) {
	var interfaceUp atomic.Bool
	interfaceUp.Store(true)

	ipNet := func(s string) net.Addr {
		ip, prefix, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		prefix.IP = ip
		return prefix
	}
	oldInterfaceGetter := altNetInterfaces
	altNetInterfaces = func() ([]Interface, error) {
		flags := net.FlagBroadcast | net.FlagMulticast
		var addrs []net.Addr
		if interfaceUp.Load() {
			flags |= net.FlagUp | net.FlagRunning
			addrs = []net.Addr{ipNet("192.0.2.10/24")}
		}
		return []Interface{{
			Interface: &net.Interface{Index: 100, MTU: 1500, Name: "reconcile-test0", Flags: flags},
			AltAddrs:  addrs,
		}}, nil
	}
	t.Cleanup(func() { altNetInterfaces = oldInterfaceGetter })

	bus := eventbus.New()
	defer bus.Close()
	m, err := New(bus, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	states := make(chan bool, 2)
	m.RegisterChangeCallback(func(delta *ChangeDelta) {
		states <- delta.AnyInterfaceUp()
	})
	m.Start()

	interfaceUp.Store(false)
	m.mu.Lock()
	m.lastWall = wallTime().Add(-time.Hour)
	m.mu.Unlock()
	m.pollWallTime()
	wantInterfaceState(t, states, false)

	// The interface recovers without an address or route notification. Make
	// the successful offline snapshot old enough for reconciliation to run.
	interfaceUp.Store(true)
	m.mu.Lock()
	m.lastReconcile = time.Now().Add(-networkDownReconcileInterval - time.Second)
	m.mu.Unlock()
	m.pollWallTime()
	wantInterfaceState(t, states, true)
}

func wantInterfaceState(t *testing.T, states <-chan bool, want bool) {
	t.Helper()
	select {
	case got := <-states:
		if got != want {
			t.Fatalf("AnyInterfaceUp = %v, want %v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for AnyInterfaceUp = %v", want)
	}
}
