package once

import (
	"sync"
	"testing"
	"unsafe"
)

func TestOnceLayout(t *testing.T) {
	if unsafe.Sizeof(Once{}) != unsafe.Sizeof(sync.Once{}) {
		t.Fatalf("size = %d, want %d", unsafe.Sizeof(Once{}), unsafe.Sizeof(sync.Once{}))
	}
	if unsafe.Alignof(Once{}) != unsafe.Alignof(sync.Once{}) {
		t.Fatalf("alignment = %d, want %d", unsafe.Alignof(Once{}), unsafe.Alignof(sync.Once{}))
	}
}

func TestReset(t *testing.T) {
	var once sync.Once
	count := 0
	once.Do(func() { count++ })
	if !Done(&once) {
		t.Fatal("once is not done")
	}
	Reset(&once)
	if Done(&once) {
		t.Fatal("once is still done after reset")
	}
	once.Do(func() { count++ })
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}
