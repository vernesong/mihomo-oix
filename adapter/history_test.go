package adapter

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func TestDelayHistoryRetainsLatestRecords(t *testing.T) {
	var h delayHistory
	for i := 1; i <= 3*defaultHistoriesNum+2; i++ {
		h.Put(C.DelayHistory{Time: time.Unix(int64(i), 0), Delay: uint16(i)})
		snapshot := h.Copy()
		wantLen := min(i, defaultHistoriesNum)
		if len(snapshot) != wantLen {
			t.Fatalf("history length = %d, want %d", len(snapshot), wantLen)
		}
		for j, record := range snapshot {
			want := i - wantLen + j + 1
			if record.Delay != uint16(want) || !record.Time.Equal(time.Unix(int64(want), 0)) {
				t.Fatalf("history[%d] = %+v, want record %d", j, record, want)
			}
		}
		snapshot[len(snapshot)-1].Delay = 0
		if h.Last().Delay != uint16(i) {
			t.Fatal("snapshot modified stored history")
		}
	}
}

func TestProxyHistoriesConcurrent(t *testing.T) {
	p := NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "direct"}))
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		History json.RawMessage         `json:"history"`
		Extra   map[string]C.ProxyState `json:"extra"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if string(state.History) != "[]" || len(state.Extra) != 0 {
		t.Fatalf("unexpected empty histories: %s", data)
	}
	urls := []string{"://one", "://two"}
	if h := p.DelayHistoryForTestUrl(urls[0]); h == nil || len(h) != 0 {
		t.Fatalf("unknown URL history = %v", h)
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for range 50 {
				_, err := p.URLTest(context.Background(), urls[i%len(urls)], nil)
				if err == nil {
					t.Error("invalid probe URL accepted")
				}
				if len(p.DelayHistory()) > defaultHistoriesNum {
					t.Error("concurrent history exceeded limit")
				}
				_ = p.LastDelayForTestUrl(urls[i%len(urls)])
				_ = p.ExtraDelayHistories()
			}
		})
	}
	wg.Wait()
	if len(p.DelayHistory()) != defaultHistoriesNum {
		t.Fatal("incorrect history retention")
	}
	all := p.ExtraDelayHistories()
	if len(all) != len(urls) {
		t.Fatalf("retained %d URL states", len(all))
	}
	for _, url := range urls {
		if all[url].Alive || p.AliveForTestUrl(url) || p.LastDelayForTestUrl(url) != maxDelay {
			t.Fatal("failed probe marked alive")
		}
		if len(all[url].History) != defaultHistoriesNum || len(p.DelayHistoryForTestUrl(url)) != defaultHistoriesNum {
			t.Fatal("incorrect per-URL retention")
		}
	}
}
