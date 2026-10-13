package snell

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/pool"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

type Pool struct {
	pool    *pool.Pool[*pooledEntry]
	factory func(context.Context) (*Snell, error)
	closed  atomic.Bool
	// idleAge is how long a connection may wait in the pool.
	idleAge time.Duration
}

func (p *Pool) Warm(ctx context.Context, count int) {
	for range count {
		if p.closed.Load() {
			return
		}
		conn, err := p.factory(ctx)
		if err != nil {
			return
		}
		p.put(conn)
	}
}

const (
	poolConnNew int32 = iota
	poolConnReusable
	poolConnClosed

	defaultIdleAge = 15 * time.Second
)

const (
	entryWaiting int32 = iota
	entryClaimed
	entryExpired
)

// pooledEntry is a connection in the pool. The pool only ages entries out when
// something asks for one, so a timer closes a connection nobody takes: an
// HTTP/3 stream pins its QUIC session for as long as it is open.
type pooledEntry struct {
	conn   *Snell
	mu     sync.Mutex
	state  int32
	expiry *time.Timer
}

func (e *pooledEntry) park(maxAge time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if maxAge > 0 {
		e.expiry = time.AfterFunc(maxAge, e.expire)
	}
}

func (e *pooledEntry) expire() {
	e.mu.Lock()
	if e.state != entryWaiting {
		e.mu.Unlock()
		return
	}
	e.state = entryExpired
	e.expiry = nil
	e.mu.Unlock()
	_ = e.conn.Close()
}

// claim takes the entry out of the pool; false once it closed while waiting.
func (e *pooledEntry) claim() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == entryExpired {
		return false
	}
	e.state = entryClaimed
	if e.expiry != nil {
		e.expiry.Stop()
		e.expiry = nil
	}
	return true
}

func (e *pooledEntry) evict() {
	e.mu.Lock()
	e.state = entryExpired
	if e.expiry != nil {
		e.expiry.Stop()
		e.expiry = nil
	}
	e.mu.Unlock()
	_ = e.conn.Close()
}

func (p *Pool) Get() (net.Conn, error) {
	return p.GetContext(context.Background())
}

func (p *Pool) GetContext(ctx context.Context) (net.Conn, error) {
	for {
		// A canceled request closes the connection it takes before using it.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		entry, err := p.pool.GetContext(ctx)
		if err != nil {
			return nil, err
		}
		if !entry.claim() {
			// The timer closed it while it waited.
			_ = entry.conn.Close()
			continue
		}

		return &PoolConn{Snell: entry.conn, pool: p}, nil
	}
}

func (p *Pool) Put(conn *Snell) {
	if err := HalfClose(conn); err != nil {
		_ = conn.Close()
		return
	}

	p.put(conn)
}

func (p *Pool) put(conn *Snell) {
	entry := &pooledEntry{conn: conn}
	entry.park(p.idleAge)
	p.pool.Put(entry)
}

func (p *Pool) Close() error {
	p.closed.Store(true)
	return p.pool.Close()
}

type PoolConn struct {
	*Snell
	pool               *Pool
	closeWriteOnce     sync.Once
	closeWriteReusable bool
	closeWriteErr      error
	closeOnce          sync.Once
	closeErr           error
	reusableState      atomic.Int32
	peerClosed         atomic.Bool
}

func (pc *PoolConn) Read(b []byte) (int, error) {
	n, err := pc.Snell.Read(b)
	if err == shadowaead.ErrZeroChunk {
		pc.peerClosed.Store(true)
		return n, io.EOF
	}
	return n, err
}

func (pc *PoolConn) Write(b []byte) (int, error) {
	return pc.Snell.Write(b)
}

// MarkReusable allows Close to return this request to the pool after the request header is committed.
func (pc *PoolConn) MarkReusable() {
	pc.reusableState.CompareAndSwap(poolConnNew, poolConnReusable)
}

func (pc *PoolConn) CloseWrite() error {
	_, err := pc.closeWrite()
	return err
}

func (pc *PoolConn) closeWrite() (bool, error) {
	pc.closeWriteOnce.Do(func() {
		if pc.reusableState.Swap(poolConnClosed) != poolConnReusable {
			pc.closeWriteErr = pc.Snell.Close()
			return
		}
		pc.closeWriteReusable = true
		pc.closeWriteErr = writeZeroChunk(pc.Snell)
	})
	return pc.closeWriteReusable, pc.closeWriteErr
}

func (pc *PoolConn) Close() error {
	pc.closeOnce.Do(func() {
		reusable, err := pc.closeWrite()
		if err != nil {
			pc.closeErr = err
			_ = pc.Snell.Close()
			return
		}
		if !reusable {
			return
		}

		if !pc.peerClosed.Load() {
			_ = pc.Snell.Close()
			return
		}
		// mihomo use SetReadDeadline to break bidirectional copy between client and server.
		// reset it before reuse connection to avoid io timeout error.
		_ = pc.SetReadDeadline(time.Time{})
		pc.reply = false
		pc.pool.put(pc.Snell)
	})
	return pc.closeErr
}

func NewPool(factory func(context.Context) (*Snell, error)) *Pool {
	p := pool.New[*pooledEntry](
		func(ctx context.Context) (*pooledEntry, error) {
			conn, err := factory(ctx)
			if err != nil {
				return nil, err
			}
			return &pooledEntry{conn: conn}, nil
		},
		pool.WithAge[*pooledEntry](defaultIdleAge.Milliseconds()),
		pool.WithSize[*pooledEntry](10),
		pool.WithEvict[*pooledEntry](func(item *pooledEntry) {
			item.evict()
		}),
	)

	return &Pool{pool: p, factory: factory, idleAge: defaultIdleAge}
}
