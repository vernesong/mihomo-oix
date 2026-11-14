package outbound

import (
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/sudoku"
)

func sudokuTestOption(key string) SudokuOption {
	return SudokuOption{Name: "sudoku", Server: "127.0.0.1", Port: 443, Key: key}
}

func TestSudokuLazySharedTables(t *testing.T) {
	patterns := []string{"xpxvvpvv", "vvpxxpvv"}
	option := sudokuTestOption(t.Name())
	option.TableType = "up_ascii_down_entropy"
	option.CustomTables = patterns
	var nodes []*Sudoku
	for range 4 {
		node, err := NewSudoku(option)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = node.Close() })
		if node.tables.set.Load() != nil || node.baseConf.Table != nil || len(node.baseConf.Tables) != 0 {
			t.Fatal("unused node allocated tables")
		}
		nodes = append(nodes, node)
	}
	// A caller may reuse its options after construction. Lazy building must use
	// the validated snapshot, not the caller's subsequently changed slice.
	patterns[0] = "invalid"
	var wg sync.WaitGroup
	for _, node := range nodes {
		for range 4 {
			wg.Go(func() {
				_, err := node.buildConfig(&C.Metadata{Host: "example.com", DstPort: 80})
				if err != nil {
					t.Error(err)
				}
			})
		}
	}
	wg.Wait()
	set := nodes[0].tables.set.Load()
	if set == nil {
		t.Fatal("first use did not build tables")
	}
	for _, node := range nodes {
		if node.tables.set.Load() != set {
			t.Fatal("identical nodes did not share their tables")
		}
	}
	expected, err := sudoku.NewClientTablesWithCustomPatterns(sudoku.ClientAEADSeed(option.Key), option.TableType, "", []string{"xpxvvpvv", "vvpxxpvv"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set.tables, expected) {
		t.Fatal("shared tables changed encoding or rotation order")
	}
	// A different seed and reversed rotation order must each have their own set.
	for _, change := range []func(*SudokuOption){
		func(o *SudokuOption) { o.Key += "-other" },
		func(o *SudokuOption) { o.CustomTables[0], o.CustomTables[1] = o.CustomTables[1], o.CustomTables[0] },
	} {
		other := option
		other.CustomTables = []string{"xpxvvpvv", "vvpxxpvv"}
		change(&other)
		node, err := NewSudoku(other)
		if err != nil {
			t.Fatal(err)
		}
		_, err = node.buildConfig(&C.Metadata{Host: "example.com", DstPort: 80})
		if err != nil {
			t.Fatal(err)
		}
		if node.tables.set.Load() == set {
			t.Fatal("incompatible table configurations shared a set")
		}
		_ = node.Close()
	}
}

func TestSudokuSharedTablesCollected(t *testing.T) {
	key := func() sudokuTableKey {
		node, err := NewSudoku(sudokuTestOption(t.Name()))
		if err != nil {
			t.Fatal(err)
		}
		_, err = node.buildConfig(&C.Metadata{Host: "example.com", DstPort: 80})
		if err != nil {
			t.Fatal(err)
		}
		_ = node.Close()
		return node.tables.spec.key
	}()
	cached := func() bool {
		sudokuTableCache.Lock()
		defer sudokuTableCache.Unlock()
		return sudokuTableCache.slots[key] != nil
	}
	deadline := time.Now().Add(5 * time.Second)
	for cached() && time.Now().Before(deadline) {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
	if cached() {
		t.Fatal("global cache kept unused tables or their key alive")
	}
	// Reusing a collected key must build a usable set again.
	node, err := NewSudoku(sudokuTestOption(t.Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	cfg, err := node.buildConfig(&C.Metadata{Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Table == nil {
		t.Fatal("collected key could not be rebuilt")
	}
}

func TestSudokuInvalidSettingsFailBeforeFirstUse(t *testing.T) {
	padding := 200
	for _, modify := range []func(*SudokuOption){
		func(o *SudokuOption) { o.CustomTable = "xxxxvvvv" },
		func(o *SudokuOption) { o.CustomTables = []string{"bad"} },
		func(o *SudokuOption) { o.TableType = "bogus" },
		func(o *SudokuOption) { o.AEADMethod = "bogus" },
		func(o *SudokuOption) { o.PaddingMin = &padding },
		func(o *SudokuOption) { o.PathRoot = "a/b" },
		func(o *SudokuOption) { o.Multiplex = "sometimes" },
	} {
		option := sudokuTestOption(t.Name())
		modify(&option)
		node, err := NewSudoku(option)
		if err == nil {
			_ = node.Close()
			t.Fatal("invalid settings accepted during configuration loading")
		}
	}
}
