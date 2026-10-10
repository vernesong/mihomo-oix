package pool

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"time"
)

var ErrClosed = errors.New("pool is closed")

type Factory[T any] func(context.Context) (T, error)

type entry[T any] struct {
	elm  T
	time time.Time
}

type Option[T any] func(*pool[T])

// WithEvict set the evict callback
func WithEvict[T any](cb func(T)) Option[T] {
	return func(p *pool[T]) {
		p.evict = cb
	}
}

// WithAge defined element max age (millisecond)
func WithAge[T any](maxAge int64) Option[T] {
	return func(p *pool[T]) {
		p.maxAge = maxAge
	}
}

// WithSize defined max size of Pool
func WithSize[T any](maxSize int) Option[T] {
	return func(p *pool[T]) {
		p.ch = make(chan *entry[T], maxSize)
	}
}

// Pool is for GC, see New for detail
type Pool[T any] struct {
	*pool[T]
}

type pool[T any] struct {
	ch      chan *entry[T]
	factory Factory[T]
	evict   func(T)
	maxAge  int64
	mu      sync.Mutex
	closed  bool
}

func (p *pool[T]) GetContext(ctx context.Context) (T, error) {
	now := time.Now()
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			var zero T
			return zero, ErrClosed
		}
		select {
		case item := <-p.ch:
			p.mu.Unlock()
			elm := item
			if p.maxAge != 0 && now.Sub(item.time).Milliseconds() > p.maxAge {
				if p.evict != nil {
					p.evict(elm.elm)
				}
				continue
			}

			return elm.elm, nil
		default:
			p.mu.Unlock()
			item, err := p.factory(ctx)
			if err != nil {
				return item, err
			}
			p.mu.Lock()
			closed := p.closed
			p.mu.Unlock()
			if closed {
				if p.evict != nil {
					p.evict(item)
				}
				var zero T
				return zero, ErrClosed
			}
			return item, nil
		}
	}
}

func (p *pool[T]) Get() (T, error) {
	return p.GetContext(context.Background())
}

func (p *pool[T]) Put(item T) {
	e := &entry[T]{
		elm:  item,
		time: time.Now(),
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		if p.evict != nil {
			p.evict(item)
		}
		return
	}
	select {
	case p.ch <- e:
		p.mu.Unlock()
		return
	default:
		p.mu.Unlock()
		// pool is full
		if p.evict != nil {
			p.evict(item)
		}
		return
	}
}

func recycle[T any](p *Pool[T]) {
	items, evict := p.pool.close()
	if evict != nil && len(items) > 0 {
		go func() {
			for _, item := range items {
				evict(item)
			}
		}()
	}
}

func (p *pool[T]) close() ([]T, func(T)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, nil
	}
	p.closed = true
	items := make([]T, 0, len(p.ch))
	for {
		select {
		case item := <-p.ch:
			items = append(items, item.elm)
		default:
			return items, p.evict
		}
	}
}

func (p *Pool[T]) Close() error {
	runtime.SetFinalizer(p, nil)
	items, evict := p.pool.close()
	if evict != nil {
		for _, item := range items {
			evict(item)
		}
	}
	return nil
}

func New[T any](factory Factory[T], options ...Option[T]) *Pool[T] {
	p := &pool[T]{
		ch:      make(chan *entry[T], 10),
		factory: factory,
	}

	for _, option := range options {
		option(p)
	}

	P := &Pool[T]{p}
	runtime.SetFinalizer(P, recycle[T])
	return P
}
