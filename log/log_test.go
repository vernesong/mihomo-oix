package log

import (
	"sync"
	"testing"
)

func TestChangingLevelDuringRuntimeLogging(t *testing.T) {
	previous := Level()
	t.Cleanup(func() { SetLevel(previous) })
	var workers sync.WaitGroup
	workers.Go(func() {
		for range 100 {
			SetLevel(WARNING)
			SetLevel(INFO)
		}
	})
	workers.Go(func() {
		for range 100 {
			_ = Level()
			Debugln("runtime log level test")
		}
	})
	workers.Wait()
}
