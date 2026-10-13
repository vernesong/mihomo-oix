// Adapted from ProjectClash/Clash, Copyright (C) 2026 The Clash Authors.
// GPL-3.0-or-later; see docs/optimizations.md for source revisions and changes.

package sudoku

import (
	"strings"

	"github.com/metacubex/mihomo/transport/sudoku/obfs/sudoku"
)

func ValidateClientTablePatterns(tableType string, customTable string, customTables []string) error {
	patterns, err := normalizeTablePatterns(tableType, customTable, customTables)
	if err != nil {
		return err
	}
	for _, pattern := range patterns {
		if err = sudoku.ValidateTableSpec(tableType, strings.TrimSpace(pattern)); err != nil {
			return err
		}
	}
	return nil
}

func ClientTablePatterns(customTable string, customTables []string) []string {
	raw := normalizeCustomPatterns(customTable, customTables)
	patterns := make([]string, len(raw))
	for i, pattern := range raw {
		patterns[i] = strings.TrimSpace(pattern)
	}
	return patterns
}
