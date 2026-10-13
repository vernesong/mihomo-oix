package outbound

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku"
)

func TestSudokuLazyTablesRoundTrip(t *testing.T) {
	option := sudokuTestOption(t.Name())
	option.TableType = "up_ascii_down_entropy"
	option.CustomTables = []string{"xpxvvpvv", "vvpxxpvv"}
	disabled := false
	option.HTTPMask = &disabled
	tables, err := sudoku.NewServerTablesWithCustomPatterns(sudoku.ClientAEADSeed(option.Key), option.TableType, "", option.CustomTables)
	if err != nil {
		t.Fatal(err)
	}
	cfg := sudoku.DefaultConfig()
	cfg.Key, cfg.Tables, cfg.DisableHTTPMask = option.Key, tables, true
	payload := []byte("table-sharing-roundtrip")
	const target = "192.0.2.1:80"
	for _, mode := range []string{"tcp", "mux", "udp"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				result <- func() error {
					raw, err := listener.Accept()
					if err != nil {
						return err
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
					conn, meta, err := sudoku.ServerHandshake(raw, cfg)
					if err != nil {
						return err
					}
					session, err := sudoku.ReadServerSession(conn, meta)
					if err != nil {
						return err
					}
					switch mode {
					case "udp":
						if session.Type != sudoku.SessionTypeUoT {
							return fmt.Errorf("unexpected session type: %v", session.Type)
						}
						address, data, err := sudoku.ReadDatagram(conn)
						if err != nil {
							return err
						}
						if address != target || !bytes.Equal(data, payload) {
							return fmt.Errorf("invalid datagram")
						}
						return sudoku.WriteDatagram(conn, address, data)
					case "mux":
						if session.Type != sudoku.SessionTypeMultiplex {
							return fmt.Errorf("unexpected session type: %v", session.Type)
						}
						mux, err := sudoku.AcceptMultiplexServer(conn)
						if err != nil {
							return err
						}
						defer mux.Close()
						var address string
						conn, address, err = mux.AcceptTCP()
						if err != nil {
							return err
						}
						defer conn.Close()
						if address != target {
							return fmt.Errorf("unexpected mux target: %s", address)
						}
					default:
						if session.Type != sudoku.SessionTypeTCP || session.Target != target {
							return fmt.Errorf("unexpected TCP target: %s", session.Target)
						}
					}
					data := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, data); err != nil {
						return err
					}
					if !bytes.Equal(data, payload) {
						return fmt.Errorf("invalid stream data")
					}
					_, err = conn.Write(data)
					return err
				}()
			}()
			local := option
			local.Port = listener.Addr().(*net.TCPAddr).Port
			if mode == "mux" {
				local.Multiplex = "on"
			}
			node, err := NewSudoku(local)
			if err != nil {
				t.Fatal(err)
			}
			defer node.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			metadata := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("192.0.2.1"), DstPort: 80}
			got := make([]byte, len(payload))
			if mode == "udp" {
				metadata.NetWork = C.UDP
				conn, err := node.ListenPacketContext(ctx, metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.WriteTo(payload, metadata.UDPAddr()); err != nil {
					t.Fatal(err)
				}
				n, address, err := conn.ReadFrom(got)
				if err != nil {
					t.Fatal(err)
				}
				if n != len(payload) || address.String() != target {
					t.Fatal("invalid UDP response")
				}
			} else {
				conn, err := node.DialContext(ctx, metadata)
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("response data differs")
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
