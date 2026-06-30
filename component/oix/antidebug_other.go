//go:build !linux && !darwin && !windows

package oix

func debuggerPresent() bool {
	return false
}
