//go:build linux

package oix

import (
	"os"
	"strings"
)

func debuggerPresent() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
			return v != "" && v != "0"
		}
	}
	return false
}
