//go:build darwin

package oix

import (
	"os"

	"golang.org/x/sys/unix"
)

const pTraced = 0x00000800 // P_TRACED

func debuggerPresent() bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return false
	}
	return info.Proc.P_flag&pTraced != 0
}
