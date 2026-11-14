// Adapted from ProjectClash/Clash, Copyright (C) 2026 The Clash Authors.
// GPL-3.0-or-later; see docs/optimizations.md for source revisions and changes.

package outbound

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// canDeferIPStack recognizes configurations accepted by both stack backends.
// Anything else uses the real constructor immediately, preserving its validation
// and exact error without maintaining a second implementation of that policy.
func canDeferIPStack(prefixes []netip.Prefix, mtu uint32) bool {
	if len(prefixes) == 0 || mtu < 68 || mtu > 65535 {
		return false
	}
	for i, prefix := range prefixes {
		address := prefix.Addr()
		if !prefix.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() || address.Zone() != "" {
			return false
		}
		if address.Is6() && mtu < 1280 {
			return false
		}
		for _, previous := range prefixes[:i] {
			if address == previous.Addr() {
				return false
			}
		}
		if !address.Is4() {
			continue
		}
		bytes := address.As4()
		value := binary.BigEndian.Uint32(bytes[:])
		if value == ^uint32(0) {
			return false
		}
		for _, other := range prefixes {
			if !other.IsValid() || !other.Addr().Is4() || other.Bits() >= 31 {
				continue
			}
			bytes := other.Addr().As4()
			broadcast := binary.BigEndian.Uint32(bytes[:]) | (^uint32(0) >> other.Bits())
			if value == broadcast {
				return false
			}
		}
	}
	return true
}

func (w *Masque) startIPStack() (ipStack, error) {
	w.stackMu.Lock()
	defer w.stackMu.Unlock()
	if err := w.runCtx.Err(); err != nil {
		return nil, err
	}
	if w.tunDevice == nil {
		device, err := newIPStack(w.option.IPStack, w.stackPrefixes, w.stackMTU)
		if err != nil {
			return nil, fmt.Errorf("create device: %w", err)
		}
		w.tunDevice = device
	}
	if !w.runDevice {
		if err := w.tunDevice.Start(); err != nil {
			return nil, err
		}
		w.runDevice = true
	}
	return w.tunDevice, nil
}
