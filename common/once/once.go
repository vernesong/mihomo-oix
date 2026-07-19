package once

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

type Once struct {
	done atomic.Bool
	m    sync.Mutex
}

func Done(once *sync.Once) bool {
	return (*atomic.Bool)(unsafe.Pointer(once)).Load()
}

func Reset(once *sync.Once) {
	o := (*Once)(unsafe.Pointer(once))
	o.m.Lock()
	defer o.m.Unlock()
	o.done.Store(false)
}
