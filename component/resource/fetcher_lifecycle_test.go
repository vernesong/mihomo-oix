package resource

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	P "github.com/metacubex/mihomo/constant/provider"
)

type controlledVehicle struct {
	started chan struct{}
	release chan struct{}
	read    chan struct{}
	reads   atomic.Int32
	err     error
}

func (v *controlledVehicle) Type() P.VehicleType { return P.HTTP }
func (v *controlledVehicle) Path() string        { return "unused" }
func (v *controlledVehicle) Url() string         { return "unused" }
func (v *controlledVehicle) Proxy() string       { return "" }
func (v *controlledVehicle) Read(context.Context, utils.HashType) ([]byte, utils.HashType, error) {
	v.reads.Add(1)
	if v.read != nil {
		v.read <- struct{}{}
	}
	data := []byte("valid")
	return data, utils.MakeHash(data), v.err
}
func (v *controlledVehicle) Write([]byte) error {
	if v.started != nil {
		close(v.started)
		<-v.release
	}
	return nil
}

func TestFetcherCloseDuringWriteDoesNotPublish(t *testing.T) {
	v := &controlledVehicle{started: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	defer once.Do(func() { close(v.release) })
	var published, discarded atomic.Int32
	f := NewFetcher("fixture", 0, v, nil, func(data []byte) (string, error) { return string(data), nil }, func(string) { published.Add(1) })
	f.SetDiscard(func(string) { discarded.Add(1) })
	defer f.Close()
	done := make(chan error, 1)
	go func() { _, _, err := f.Update(); done <- err }()
	select {
	case <-v.started:
	case <-time.After(time.Second):
		t.Fatal("write did not start")
	}
	_ = f.Close()
	once.Do(func() { close(v.release) })
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("update after close = %v", err)
	}
	if published.Load() != 0 || discarded.Load() != 1 {
		t.Fatalf("published=%d discarded=%d", published.Load(), discarded.Load())
	}
	before := v.reads.Load()
	if _, _, err := f.Update(); !errors.Is(err, context.Canceled) {
		t.Fatalf("closed update = %v", err)
	}
	if v.reads.Load() != before {
		t.Fatal("closed provider performed another read")
	}
}

func TestFetcherMetadataDuringUpdate(t *testing.T) {
	f := NewFetcher("fixture", 0, NewFileVehicle(filepath.Join(t.TempDir(), "provider")), nil, func(data []byte) (string, error) { return string(data), nil }, nil)
	defer f.Close()
	var work sync.WaitGroup
	work.Go(func() {
		for range 500 {
			if _, _, err := f.SideUpdate([]byte("valid")); err != nil {
				t.Error(err)
			}
		}
	})
	work.Go(func() {
		for range 500 {
			_ = f.UpdatedAt()
		}
	})
	work.Wait()
	if f.UpdatedAt().IsZero() {
		t.Fatal("update time not published")
	}
}

func TestPullLoopDoesNotImmediatelyRepeatAnOverdueRead(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "forced-stale-refresh", true: "failed-initial-read"}[failed], func(t *testing.T) {
			v := &controlledVehicle{read: make(chan struct{}, 8)}
			if failed {
				v.err = errors.New("download failed")
			}
			f := NewFetcher("fixture", time.Hour, v, nil, func(data []byte) (string, error) { return string(data), nil }, nil)
			f.updatedAt.Store(time.Now().Add(-2 * time.Hour))
			if failed {
				_, _, _ = f.Update()
			}
			done := make(chan struct{})
			go func() { f.pullLoop(!failed); close(done) }()
			defer func() { _ = f.Close(); <-done }()
			select {
			case <-v.read:
			case <-time.After(time.Second):
				t.Fatal("initial read did not start")
			}
			time.Sleep(50 * time.Millisecond)
			if got := v.reads.Load(); got != 1 {
				t.Fatalf("initial refresh immediately repeated: reads=%d", got)
			}
		})
	}
}
