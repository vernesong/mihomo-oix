package oix

import (
	"strconv"
	"strings"
)

const subscriptionCapabilitiesHeader = "X-oixCloud-Capabilities"

// Revisions are additive: advertising N also promises support for 1 through N.
func subscriptionCapabilities() string {
	revisions := []struct {
		name     string
		revision uint16
	}{
		{"snell.ech.h3", 1},
	}
	entries := make([]string, 0, len(revisions))
	for _, capability := range revisions {
		entries = append(entries, capability.name+"="+strconv.Itoa(int(capability.revision)))
	}
	return strings.Join(entries, ", ")
}
