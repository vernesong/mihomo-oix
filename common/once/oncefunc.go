package once

import "sync"

func OnceFunc(f func()) func() {
	return sync.OnceFunc(f)
}

func OnceValue[T any](f func() T) func() T {
	return sync.OnceValue(f)
}
