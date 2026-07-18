package adapter

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestDurationToDelay(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     uint16
	}{
		{name: "zero", duration: 0, want: 1},
		{name: "sub-millisecond", duration: time.Microsecond, want: 1},
		{name: "one millisecond", duration: time.Millisecond, want: 1},
		{name: "whole milliseconds", duration: 42 * time.Millisecond, want: 42},
		{name: "fractional milliseconds", duration: 42*time.Millisecond + 999*time.Microsecond, want: 42},
		{name: "saturated", duration: 70 * time.Second, want: ^uint16(0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := durationToDelay(test.duration); got != test.want {
				t.Fatalf("durationToDelay(%s) = %d, want %d", test.duration, got, test.want)
			}
		})
	}
}

func TestURLTestUsesFirstMeasurementWhenUnifiedRetryFails(t *testing.T) {
	previousUnifiedDelay := UnifiedDelay.Load()
	UnifiedDelay.Store(true)
	t.Cleanup(func() {
		UnifiedDelay.Store(previousUnifiedDelay)
	})

	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestCount.Add(1) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	proxy := NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "direct"}))
	delay, err := proxy.URLTest(ctx, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestCount.Load(); got != 2 {
		t.Fatalf("request count = %d, want 2", got)
	}
	if delay >= 100 {
		t.Fatalf("delay = %dms, want first successful measurement below 100ms", delay)
	}
}
