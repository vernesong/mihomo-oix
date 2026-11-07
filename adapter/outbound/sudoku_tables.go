// Adapted from ProjectClash/Clash, Copyright (C) 2026 The Clash Authors.
// GPL-3.0-or-later; see docs/optimizations.md for source revisions and changes.

package outbound

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/metacubex/mihomo/transport/sudoku"
	obfs "github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

type sudokuTableKey struct {
	seed      string
	tableType string
	patterns  string
}

type sudokuTableSpec struct {
	key      sudokuTableKey
	patterns []string
}

type sudokuTableSet struct {
	tables []*obfs.Table
}

type sudokuTables struct {
	spec sudokuTableSpec
	set  atomic.Pointer[sudokuTableSet]
}

func newSudokuTableSpec(seed string, tableType string, customTable string, customTables []string) (sudokuTableSpec, error) {
	if err := sudoku.ValidateClientTablePatterns(tableType, customTable, customTables); err != nil {
		return sudokuTableSpec{}, err
	}
	normalized := sudoku.ClientTablePatterns(customTable, customTables)
	var patterns strings.Builder
	for _, pattern := range normalized {
		patterns.WriteString(strconv.Quote(pattern))
	}
	return sudokuTableSpec{
		key:      sudokuTableKey{seed: seed, tableType: tableType, patterns: patterns.String()},
		patterns: normalized,
	}, nil
}

func (spec sudokuTableSpec) build() ([]*obfs.Table, error) {
	return sudoku.NewClientTablesWithCustomPatterns(spec.key.seed, spec.key.tableType, "", spec.patterns)
}

var sudokuTablePresent obfs.Table

func (spec sudokuTableSpec) validate(conf sudoku.ProtocolConfig) error {
	conf.Table, conf.Tables = &sudokuTablePresent, nil
	return conf.Validate()
}

func (t *sudokuTables) fill(conf *sudoku.ProtocolConfig) error {
	set := t.set.Load()
	if set == nil {
		shared, err := sharedSudokuTables(t.spec)
		if err != nil {
			return fmt.Errorf("build table(s) failed: %w", err)
		}
		t.set.CompareAndSwap(nil, shared)
		set = t.set.Load()
	}
	if len(set.tables) == 1 {
		conf.Table = set.tables[0]
	} else {
		conf.Tables = set.tables
	}
	return nil
}

// Slots keep weak references so unused nodes do not leave tables pinned globally.
// The ready channel publishes one build to concurrent first users of a key.
type sudokuTableSlot struct {
	key   sudokuTableKey
	ready chan struct{}
	set   weak.Pointer[sudokuTableSet]
	err   error
}

var sudokuTableCache struct {
	sync.Mutex
	slots map[sudokuTableKey]*sudokuTableSlot
}

func sharedSudokuTables(spec sudokuTableSpec) (*sudokuTableSet, error) {
	for {
		sudokuTableCache.Lock()
		slot := sudokuTableCache.slots[spec.key]
		if slot == nil {
			slot = &sudokuTableSlot{key: spec.key, ready: make(chan struct{})}
			if sudokuTableCache.slots == nil {
				sudokuTableCache.slots = make(map[sudokuTableKey]*sudokuTableSlot)
			}
			sudokuTableCache.slots[spec.key] = slot
			sudokuTableCache.Unlock()
			return slot.fill(spec)
		}
		sudokuTableCache.Unlock()
		<-slot.ready
		if slot.err != nil {
			return nil, slot.err
		}
		if set := slot.set.Value(); set != nil {
			return set, nil
		}
		forgetSudokuTables(slot)
	}
}

func (slot *sudokuTableSlot) fill(spec sudokuTableSpec) (*sudokuTableSet, error) {
	defer close(slot.ready)
	tables, err := spec.build()
	if err != nil {
		slot.err = err
		forgetSudokuTables(slot)
		return nil, err
	}
	set := &sudokuTableSet{tables: tables}
	slot.set = weak.Make(set)
	runtime.AddCleanup(set, forgetSudokuTables, slot)
	return set, nil
}

func forgetSudokuTables(slot *sudokuTableSlot) {
	sudokuTableCache.Lock()
	if sudokuTableCache.slots[slot.key] == slot {
		delete(sudokuTableCache.slots, slot.key)
	}
	sudokuTableCache.Unlock()
}
