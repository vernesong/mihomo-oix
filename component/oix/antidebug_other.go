//go:build !linux && !darwin

package oix

func debuggerPresent() bool {
	return false
}
