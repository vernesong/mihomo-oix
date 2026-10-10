package outbound

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/snell"

	"github.com/metacubex/quic-go"
)

type snellRaceTestConn struct {
	net.Conn
	closed atomic.Int32
}

func (c *snellRaceTestConn) Close() error { c.closed.Add(1); return nil }
func snellRaceConn() (*snell.Snell, *snellRaceTestConn) {
	c := &snellRaceTestConn{}
	return snell.StreamConn(c, []byte("test-password"), snell.Version4), c
}

func TestSnellHappyEyeballsTiming(t *testing.T) {
	for _, tc := range []struct {
		name                                     string
		h3Delay, tcpDelay, wantTime              time.Duration
		h3Fails, tcpFails, wantTCP, wantStartTCP bool
		wantH3OK                                 bool
	}{
		{"fast H3", 100 * time.Millisecond, 0, 100 * time.Millisecond, false, false, false, false, true},
		{"blackholed H3 still cools down", 5 * time.Second, 50 * time.Millisecond, 300 * time.Millisecond, false, false, true, true, false},
		{"early H3 failure", 20 * time.Millisecond, 30 * time.Millisecond, 50 * time.Millisecond, true, false, true, true, false},
		{"H3 wins after overlap", 300 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond, false, false, false, true, true},
		{"TCP failure leaves H3 running", 400 * time.Millisecond, 10 * time.Millisecond, 400 * time.Millisecond, false, true, false, true, true},
		{"late H3 success is recorded and closed", time.Second, 50 * time.Millisecond, 300 * time.Millisecond, false, false, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				h3, h3Raw := snellRaceConn()
				tcp, tcpRaw := snellRaceConn()
				var tcpStarted, successes, failures atomic.Int32
				dial := func(c *snell.Snell, d time.Duration, fails bool) func(context.Context) (*snell.Snell, error) {
					return func(ctx context.Context) (*snell.Snell, error) {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(d):
						}
						if fails {
							return nil, errors.New("unreachable")
						}
						return c, nil
					}
				}
				before := time.Now()
				got, err := raceSnellTransports(context.Background(), 250*time.Millisecond, 2*time.Second, dial(h3, tc.h3Delay, tc.h3Fails), func(ctx context.Context) (*snell.Snell, error) {
					tcpStarted.Add(1)
					return dial(tcp, tc.tcpDelay, tc.tcpFails)(ctx)
				}, func(succeeded bool) {
					if succeeded {
						successes.Add(1)
					} else {
						failures.Add(1)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
				if (got == tcp) != tc.wantTCP || time.Since(before) != tc.wantTime {
					t.Fatalf("winner TCP=%v elapsed=%v", got == tcp, time.Since(before))
				}
				// Let an H3 attempt orphaned by a TCP win run to its own timeout.
				time.Sleep(2 * time.Second)
				synctest.Wait()
				if (tcpStarted.Load() == 1) != tc.wantStartTCP {
					t.Fatal("unexpected TCP start")
				}
				if successes.Load()+failures.Load() != 1 || (successes.Load() == 1) != tc.wantH3OK {
					t.Fatalf("H3 health successes=%d failures=%d", successes.Load(), failures.Load())
				}
				// Only an H3 success that arrived after TCP won is closed.
				if (h3Raw.closed.Load() == 1) != (tc.wantTCP && tc.wantH3OK) || tcpRaw.closed.Load() != 0 {
					t.Fatal("late H3 success leaked, or a fixture or winner was closed")
				}
				_ = got.Close()
			})
		})
	}
}

func TestSnellHTTP3FallbackDelayFollowsRTT(t *testing.T) {
	for _, tc := range []struct{ rtt, want time.Duration }{
		{0, 250 * time.Millisecond},
		{10 * time.Millisecond, 100 * time.Millisecond},
		{150 * time.Millisecond, 300 * time.Millisecond},
		{300 * time.Millisecond, 600 * time.Millisecond},
		{800 * time.Millisecond, time.Second},
	} {
		if got := snellHTTP3FallbackDelayFor(tc.rtt); got != tc.want {
			t.Errorf("RTT %v: delay %v, want %v", tc.rtt, got, tc.want)
		}
	}
}

func TestSnellHappyEyeballsCancellation(t *testing.T) {
	for _, after := range []time.Duration{0, 100 * time.Millisecond, 300 * time.Millisecond} {
		t.Run(after.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				if after == 0 {
					cancel()
				} else {
					time.AfterFunc(after, cancel)
				}
				var starts, closes atomic.Int32
				dial := func(ctx context.Context) (*snell.Snell, error) {
					starts.Add(1)
					<-ctx.Done()
					closes.Add(1)
					return nil, ctx.Err()
				}
				got, err := raceSnellTransports(ctx, 250*time.Millisecond, 2*time.Second, dial, dial, func(bool) { t.Error("cancel changed health") })
				if got != nil || !errors.Is(err, context.Canceled) {
					t.Fatalf("got=%v err=%v", got, err)
				}
				synctest.Wait()
				want := int32(0)
				if after > 0 {
					want = 1
				}
				if after >= 250*time.Millisecond {
					want = 2
				}
				if starts.Load() != want || closes.Load() != want {
					t.Fatalf("starts=%d closes=%d", starts.Load(), closes.Load())
				}
			})
		})
	}
}

func TestSnellHappyEyeballsBothFailures(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		h3err, tcperr := errors.New("H3 unavailable"), errors.New("TCP unavailable")
		_, err := raceSnellTransports(context.Background(), time.Second, 2*time.Second, func(context.Context) (*snell.Snell, error) { return nil, h3err }, func(context.Context) (*snell.Snell, error) { return nil, tcperr }, func(bool) {})
		if !errors.Is(err, h3err) || !errors.Is(err, tcperr) {
			t.Fatalf("lost transport error: %v", err)
		}
	})
}

type snellRaceDialer struct {
	C.Dialer
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d snellRaceDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dial(ctx, network, address)
}

// newBlackholedSnell exercises the adapter entry point: an auto adapter whose H3
// session handshake never completes, and whose TCP dials go to dialTCP.
func newBlackholedSnell(dialTCP func() (net.Conn, error)) (s *Snell, h3Starts, tcpStarts *atomic.Int32) {
	h3Starts, tcpStarts = new(atomic.Int32), new(atomic.Int32)
	s = &Snell{
		Base: &Base{dialer: snellRaceDialer{dial: func(context.Context, string, string) (net.Conn, error) {
			tcpStarts.Add(1)
			return dialTCP()
		}}}, obfsOption: &simpleObfsOption{}, psk: []byte("test-password"), version: snell.Version4,
		echTLSTransport: "auto", http3: &snell.HTTP3Client{DialTimeout: snellHTTP3AutoTimeout, Dial: func(ctx context.Context) (*quic.Conn, error) {
			h3Starts.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		}},
	}
	return s, h3Starts, tcpStarts
}

// Even when TCP wins before silently dropped UDP times out, the H3 failure
// must start the cooldown and subsequent requests must go directly to TCP.
func TestSnellAutoCooldownAfterBlackholedH3(t *testing.T) {
	for _, tcpFails := range []bool{false, true} {
		name := "TCP wins"
		if tcpFails {
			name = "TCP fails"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var tcpAt time.Time
				tcpErr := errors.New("TCP unavailable")
				s, h3Starts, tcpStarts := newBlackholedSnell(func() (net.Conn, error) {
					tcpAt = time.Now()
					if tcpFails {
						return nil, tcpErr
					}
					return &snellRaceTestConn{}, nil
				})
				defer s.http3.Close()
				start := time.Now()
				c, err := s.dialSnell(context.Background())
				if tcpAt.Sub(start) != 250*time.Millisecond {
					t.Fatalf("TCP started after %v", tcpAt.Sub(start))
				}
				if tcpFails {
					if !errors.Is(err, tcpErr) || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 2*time.Second {
						t.Fatalf("error = %v, elapsed = %v", err, time.Since(start))
					}
				} else {
					if err != nil || time.Since(start) != 250*time.Millisecond {
						t.Fatalf("error = %v, elapsed = %v", err, time.Since(start))
					}
					_ = c.Close()
					time.Sleep(2 * time.Second)
				}
				synctest.Wait()
				if s.http3RetryAfter.Load() != start.Add(32*time.Second).UnixNano() {
					t.Fatal("missing H3 cooldown")
				}
				before := time.Now()
				c, err = s.dialSnell(context.Background())
				if (err != nil) != tcpFails || (tcpFails && !errors.Is(err, tcpErr)) || time.Since(before) != 0 || h3Starts.Load() != 1 || tcpStarts.Load() != 2 {
					t.Fatalf("error = %v, elapsed = %v, H3 starts = %d", err, time.Since(before), h3Starts.Load())
				}
				if c != nil {
					_ = c.Close()
				}
			})
		})
	}
}

// A dialer may finish successfully as its context is canceled. Neither a caller
// cancellation nor a competing winner may leak the connection it returns.
func TestSnellHappyEyeballsClosesLateConnections(t *testing.T) {
	for _, cancelCaller := range []bool{false, true} {
		name := "H3 wins"
		if cancelCaller {
			name = "caller cancels"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				h3, h3Raw := snellRaceConn()
				tcp, tcpRaw := snellRaceConn()
				if cancelCaller {
					time.AfterFunc(300*time.Millisecond, cancel)
				}
				got, err := raceSnellTransports(ctx, 250*time.Millisecond, 2*time.Second,
					func(ctx context.Context) (*snell.Snell, error) {
						if cancelCaller {
							<-ctx.Done()
						} else {
							time.Sleep(300 * time.Millisecond)
						}
						return h3, nil
					}, func(ctx context.Context) (*snell.Snell, error) {
						<-ctx.Done()
						return tcp, nil
					}, func(bool) {
						if cancelCaller {
							t.Error("caller cancellation changed H3 health")
						}
					})
				synctest.Wait()
				if tcpRaw.closed.Load() != 1 {
					t.Fatal("late TCP connection was not closed exactly once")
				}
				if cancelCaller {
					if got != nil || !errors.Is(err, context.Canceled) || h3Raw.closed.Load() != 1 {
						t.Fatalf("canceled race: conn=%v error=%v H3 closes=%d", got, err, h3Raw.closed.Load())
					}
				} else {
					if got != h3 || err != nil || h3Raw.closed.Load() != 0 {
						t.Fatalf("H3 winner: conn=%v error=%v H3 closes=%d", got, err, h3Raw.closed.Load())
					}
					_ = got.Close()
				}
			})
		})
	}
}

func TestSnellH3OnlyNeverStartsTCP(t *testing.T) {
	h3Err := errors.New("H3 unavailable")
	s := &Snell{echTLSTransport: "h3", http3: &snell.HTTP3Client{Dial: func(context.Context) (*quic.Conn, error) { return nil, h3Err }}}
	_, err := s.dialSnell(context.Background())
	if !errors.Is(err, h3Err) || s.http3RetryAfter.Load() != 0 {
		t.Fatalf("error = %v, retry = %v", err, s.http3RetryAfter.Load())
	}
}

func TestSnellHappyEyeballsSuccessClearsConcurrentFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		adapter := &Snell{}
		winner, _ := snellRaceConn()
		time.AfterFunc(100*time.Millisecond, func() { adapter.recordSnellHTTP3Result(false) })
		got, err := raceSnellTransports(context.Background(), 250*time.Millisecond, 2*time.Second,
			func(context.Context) (*snell.Snell, error) {
				time.Sleep(200 * time.Millisecond)
				return winner, nil
			}, func(context.Context) (*snell.Snell, error) {
				t.Error("fast H3 should avoid TCP")
				return nil, errors.New("unexpected TCP")
			}, adapter.recordSnellHTTP3Result)
		if err != nil || got != winner {
			t.Fatalf("winner = %v, error = %v", got, err)
		}
		defer got.Close()
		if adapter.http3RetryAfter.Load() != 0 {
			t.Fatal("successful H3 left an earlier failure's cooldown active")
		}
	})
}
