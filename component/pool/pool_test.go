package pool

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func lg() Factory[int] {
	initial := -1
	return func(context.Context) (int, error) {
		initial++
		return initial, nil
	}
}

func TestPool_Basic(t *testing.T) {
	g := lg()
	pool := New[int](g)

	elm, _ := pool.Get()
	assert.Equal(t, 0, elm)
	pool.Put(elm)
	elm, _ = pool.Get()
	assert.Equal(t, 0, elm)
	elm, _ = pool.Get()
	assert.Equal(t, 1, elm)
}

func TestPool_MaxSize(t *testing.T) {
	g := lg()
	size := 5
	pool := New[int](g, WithSize[int](size))

	var items []int

	for i := 0; i < size; i++ {
		item, _ := pool.Get()
		items = append(items, item)
	}

	extra, _ := pool.Get()
	assert.Equal(t, size, extra)

	for _, item := range items {
		pool.Put(item)
	}

	pool.Put(extra)

	for _, item := range items {
		elm, _ := pool.Get()
		assert.Equal(t, item, elm)
	}
}

func TestPool_MaxAge(t *testing.T) {
	g := lg()
	pool := New[int](g, WithAge[int](20))

	elm, _ := pool.Get()
	pool.Put(elm)

	elm, _ = pool.Get()
	assert.Equal(t, 0, elm)
	pool.Put(elm)

	time.Sleep(time.Millisecond * 22)
	elm, _ = pool.Get()
	assert.Equal(t, 1, elm)
}

func TestPool_CloseEvictsQueuedItemsAndRejectsReuse(t *testing.T) {
	g := lg()
	evicted := make([]int, 0, 2)
	pool := New[int](g, WithSize[int](2), WithEvict(func(item int) {
		evicted = append(evicted, item)
	}))

	first, _ := pool.Get()
	second, _ := pool.Get()
	pool.Put(first)
	pool.Put(second)
	assert.NoError(t, pool.Close())
	assert.ElementsMatch(t, []int{first, second}, evicted)

	_, err := pool.Get()
	assert.ErrorIs(t, err, ErrClosed)
	pool.Put(3)
	assert.Contains(t, evicted, 3)
}

func TestPool_FinalizerRecycleReturnsWithBlockingEvict(t *testing.T) {
	block := make(chan struct{})
	pool := New[int](lg(), WithEvict(func(int) { <-block }))
	item, _ := pool.Get()
	pool.Put(item)
	done := make(chan struct{})
	go func() {
		recycle(pool)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pool finalizer recycle blocked")
	}
	close(block)
}
