// Adapted from ProjectClash/Clash, Copyright (C) 2026 The Clash Authors.
// GPL-3.0-or-later; see docs/optimizations.md for source revisions and changes.

package adapter

import "sync"

type proxyStates struct {
	mu     sync.RWMutex
	states map[string]*internalProxyState
}

func (s *proxyStates) Load(url string) (*internalProxyState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.states[url]
	return state, ok
}

func (s *proxyStates) LoadOrStoreFn(url string, fn func() *internalProxyState) (state *internalProxyState, loaded bool) {
	if state, ok := s.Load(url); ok {
		return state, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.states[url]; ok {
		return state, true
	}
	if s.states == nil {
		s.states = make(map[string]*internalProxyState, 1)
	}
	state = fn()
	s.states[url] = state
	return state, false
}

func (s *proxyStates) Range(f func(url string, state *internalProxyState) bool) {
	s.mu.RLock()
	type entry struct {
		url   string
		state *internalProxyState
	}
	var small [8]entry
	snapshot := small[:0]
	if len(s.states) > len(small) {
		snapshot = make([]entry, 0, len(s.states))
	}
	for url, state := range s.states {
		snapshot = append(snapshot, entry{url, state})
	}
	s.mu.RUnlock()
	for _, entry := range snapshot {
		if !f(entry.url, entry.state) {
			return
		}
	}
}
