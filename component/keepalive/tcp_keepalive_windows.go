//go:build windows

package keepalive

import (
	"errors"
	"sync"
	"syscall"

	"github.com/metacubex/mihomo/constant/features"

	"golang.org/x/sys/windows"
)

var (
	tcpKeepAliveCountSupported bool
)

var initTCPKeepAlive = sync.OnceFunc(func() {
	s, err := windows.WSASocket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		major, build := features.WindowsMajorVersion, features.WindowsBuildNumber
		tcpKeepAliveCountSupported = major >= 10 && build >= 15063
		return
	}
	defer windows.Closesocket(s)
	optSupported := func(opt int) bool {
		err := windows.SetsockoptInt(s, syscall.IPPROTO_TCP, opt, 1)
		return !errors.Is(err, syscall.WSAENOPROTOOPT)
	}
	tcpKeepAliveCountSupported = optSupported(windows.TCP_KEEPCNT)
})

func supportTCPKeepAliveCount() bool {
	initTCPKeepAlive()
	return tcpKeepAliveCountSupported
}
