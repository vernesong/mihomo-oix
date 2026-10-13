package adapter

import (
	"context"
	"testing"

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
