package vision

import (
	"errors"
	"io"
	"strconv"
	"testing"

	N "github.com/metacubex/mihomo/common/net"
)

type finalPayloadReader struct{ err error }

func (r finalPayloadReader) Read(p []byte) (int, error) { return copy(p, "data"), r.err }

func TestReadDeliversBufferedPayloadBeforeError(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("terminal read error")} {
		for _, size := range []int{1, 4, 8} {
			t.Run(terminal.Error()+"/"+strconv.Itoa(size), func(t *testing.T) {
				c := &Conn{ExtendedReader: N.NewExtendedReader(finalPayloadReader{terminal}), readRemainingContent: 4}
				c.readProcess.Store(true)
				var got []byte
				p := make([]byte, size)
				for i := 0; i < 4; i++ {
					n, err := c.Read(p)
					got = append(got, p[:n]...)
					if err != nil {
						if !errors.Is(err, terminal) {
							t.Fatalf("read error = %v, want %v", err, terminal)
						}
						if string(got) != "data" {
							t.Fatalf("payload before error = %q", got)
						}
						return
					}
				}
				t.Fatal("terminal error was lost")
			})
		}
	}
}
