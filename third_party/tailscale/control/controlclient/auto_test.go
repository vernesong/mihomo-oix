// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package controlclient

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/tailscale/tailcfg"
)

type userProfileUpdateObserver struct{}

func (userProfileUpdateObserver) SetControlClientStatus(Client, Status) {}

func (userProfileUpdateObserver) UpdateUserProfiles(map[tailcfg.UserID]tailcfg.UserProfileView) bool {
	return true
}

func TestMapRoutineStateUpdateUserProfilesConcurrentCancelMapCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Auto{
		logf:      func(string, ...any) {},
		observer:  userProfileUpdateObserver{},
		mapCtx:    ctx,
		mapCancel: cancel,
		loggedIn:  true,
		inMapPoll: true,
	}
	mrs := mapRoutineState{c: c}

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 2000; i++ {
				c.mu.Lock()
				c.cancelMapCtxLocked()
				c.mu.Unlock()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 2000; i++ {
				mrs.UpdateUserProfiles(nil)
			}
		}()
	}

	close(start)
	wg.Wait()

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.observerQueue.Wait(waitCtx); err != nil {
		t.Fatal(err)
	}
	c.observerQueue.Shutdown()
	c.mapCancel()
}
