package outbound

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/transport/snell"
)

const (
	snellHTTP3FallbackDelay    = 250 * time.Millisecond
	snellHTTP3MinFallbackDelay = 100 * time.Millisecond
	snellHTTP3MaxFallbackDelay = time.Second
	snellHTTP3AutoTimeout      = 2 * time.Second
	snellHTTP3RetryDelay       = 30 * time.Second
)

// On a live session an H3 attempt is one CONNECT round trip, so TCP waits two
// smoothed RTTs, using measured RTT as RFC 8305 suggests: a high-RTT path stops
// opening a TCP connection per request that H3 then wins, and a low-RTT one
// reaches TCP sooner when its session has silently died. Before any session
// there is no RTT, so RFC 8305's 250 ms default applies.
func snellHTTP3FallbackDelayFor(smoothedRTT time.Duration) time.Duration {
	if smoothedRTT <= 0 {
		return snellHTTP3FallbackDelay
	}
	return min(max(2*smoothedRTT, snellHTTP3MinFallbackDelay), snellHTTP3MaxFallbackDelay)
}

// snellHTTP3Timeout bounds one H3 attempt in a transport mode, and the shared
// session dial behind it.
func snellHTTP3Timeout(transport string) time.Duration {
	if transport == "auto" {
		return snellHTTP3AutoTimeout
	}
	return snellECHTLSPreconnectTimeout
}

// A successful overlapping H3 attempt proves the path has recovered; do not
// leave new dials in the cooldown set by an earlier failed attempt.
func (s *Snell) recordSnellHTTP3Result(succeeded bool) {
	if succeeded {
		s.http3RetryAfter.Store(0)
		return
	}
	s.http3RetryAfter.Store(time.Now().Add(snellHTTP3RetryDelay).UnixNano())
}

// Race verified transports, before sending Snell authentication or request data.
// The unbuffered handoff leaves ownership with the dialer until accepted, so even
// a late success after cancellation is closed without a result-draining goroutine.
//
// H3 follows the caller's cancellation only until TCP wins, then runs on to
// h3Timeout and still reports to h3Finished: a path that silently drops UDP
// never fails before TCP wins, and a late success leaves the QUIC session warm.
func raceSnellTransports(ctx context.Context, delay, h3Timeout time.Duration,
	h3, tcp func(context.Context) (*snell.Snell, error), h3Finished func(bool),
) (*snell.Snell, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h3Ctx, cancelH3 := context.WithTimeout(context.WithoutCancel(ctx), h3Timeout)
	followCaller := context.AfterFunc(ctx, cancelH3)
	var orphaned atomic.Bool
	type result struct {
		conn *snell.Snell
		err  error
		h3   bool
	}
	results := make(chan result)
	start := func(isH3 bool, dialCtx context.Context, dial func(context.Context) (*snell.Snell, error)) {
		go func() {
			if isH3 {
				defer cancelH3()
			}
			conn, err := dial(dialCtx)
			select {
			case results <- result{conn, err, isH3}:
			case <-ctx.Done():
				if isH3 && orphaned.Load() {
					h3Finished(err == nil)
				}
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	start(true, h3Ctx, h3)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	timerC := timer.C
	startTCP := func() {
		if timerC != nil {
			timer.Stop()
			timerC = nil
			start(false, ctx, tcp)
		}
	}
	var h3Err, tcpErr error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timerC:
			startTCP()
		case r := <-results:
			if err := ctx.Err(); err != nil {
				if r.conn != nil {
					_ = r.conn.Close()
				}
				return nil, err
			}
			if r.err == nil {
				if r.h3 {
					h3Finished(true)
				} else if h3Err == nil {
					orphaned.Store(followCaller())
				}
				return r.conn, nil
			}
			if r.conn != nil {
				_ = r.conn.Close()
			}
			if r.h3 {
				h3Err = r.err
				h3Finished(false)
				startTCP()
			} else {
				tcpErr = r.err
			}
			if h3Err != nil && tcpErr != nil {
				return nil, errors.Join(fmt.Errorf("HTTP/3: %w", h3Err), fmt.Errorf("TCP: %w", tcpErr))
			}
		}
	}
}
