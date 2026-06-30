//go:build windows

package oix

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procIsDebuggerPresent   = kernel32.NewProc("IsDebuggerPresent")
	procCheckRemoteDebugger = kernel32.NewProc("CheckRemoteDebuggerPresent")
)

func debuggerPresent() bool {
	if present, _, _ := procIsDebuggerPresent.Call(); present != 0 {
		return true
	}
	var remotePresent uint32
	ret, _, _ := procCheckRemoteDebugger.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&remotePresent)),
	)
	return ret != 0 && remotePresent != 0
}
