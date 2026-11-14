// Adapted from ProjectClash/Clash, Copyright (C) 2026 The Clash Authors.
// GPL-3.0-or-later; see docs/optimizations.md for source revisions and changes.

package sudoku

func ValidateTableSpec(mode string, customPattern string) error {
	asciiMode, err := ParseASCIIMode(mode)
	if err != nil {
		return err
	}
	if _, err = resolveLayout(asciiMode.uplinkPreference(), customPatternForToken(asciiMode.Uplink, customPattern)); err != nil {
		return err
	}
	if asciiMode.Uplink == asciiMode.Downlink {
		return nil
	}
	_, err = resolveLayout(asciiMode.downlinkPreference(), customPatternForToken(asciiMode.Downlink, customPattern))
	return err
}
