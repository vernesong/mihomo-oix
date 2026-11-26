package adapter

import (
	"context"
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

var (
	benchmarkProxy     *Proxy
	benchmarkHistories []C.DelayHistory
)

func BenchmarkNewProxy(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		benchmarkProxy = NewProxy(nil)
	}
}

func BenchmarkProxyRecordHistory(b *testing.B) {
	p := NewProxy(nil)
	b.ReportAllocs()
	for b.Loop() {
		// Invalid URLs exercise recording without network or transport allocations.
		_, _ = p.URLTest(context.Background(), "://invalid", nil)
	}
}

func BenchmarkProxyDelayHistory(b *testing.B) {
	p := NewProxy(nil)
	for range defaultHistoriesNum {
		_, _ = p.URLTest(context.Background(), "://invalid", nil)
	}
	b.ReportAllocs()
	for b.Loop() {
		benchmarkHistories = p.DelayHistory()
	}
}

func BenchmarkProxyMarshalJSON(b *testing.B) {
	p := NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "direct"}))
	for range defaultHistoriesNum {
		_, _ = p.URLTest(context.Background(), "://invalid", nil)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := p.MarshalJSON(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProxyExtraDelayHistories(b *testing.B) {
	for _, count := range []int{1, 4, 16} {
		b.Run(fmt.Sprintf("urls=%d", count), func(b *testing.B) {
			p := NewProxy(nil)
			for i := range count {
				_, _ = p.URLTest(context.Background(), fmt.Sprintf("://invalid-%d", i), nil)
			}
			b.ReportAllocs()
			for b.Loop() {
				_ = p.ExtraDelayHistories()
			}
		})
	}
}
