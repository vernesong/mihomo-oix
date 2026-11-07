package adapter

import (
	"sync"

	C "github.com/metacubex/mihomo/constant"
)

// delayHistory allocates only after a probe. A ring keeps the latest records
// bounded even when probes finish concurrently, without reallocating on eviction.
// Inspired by ProjectClash/Clash's lazy nodeHistory; see docs/optimizations.md.
type delayHistory struct {
	mu    sync.RWMutex
	items []C.DelayHistory
	next  int
}

func (h *delayHistory) Put(record C.DelayHistory) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.items == nil {
		h.items = make([]C.DelayHistory, 0, defaultHistoriesNum)
	}
	if len(h.items) < defaultHistoriesNum {
		h.items = append(h.items, record)
		return
	}
	h.items[h.next] = record
	h.next = (h.next + 1) % defaultHistoriesNum
}

func (h *delayHistory) Last() (last C.DelayHistory) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.items) == 0 {
		return
	}
	if len(h.items) < defaultHistoriesNum {
		return h.items[len(h.items)-1]
	}
	return h.items[(h.next+defaultHistoriesNum-1)%defaultHistoriesNum]
}

func (h *delayHistory) Copy() []C.DelayHistory {
	h.mu.RLock()
	defer h.mu.RUnlock()
	// Keep the controller's empty history encoded as [], not null.
	items := make([]C.DelayHistory, len(h.items))
	n := copy(items, h.items[h.next:])
	copy(items[n:], h.items[:h.next])
	return items
}
