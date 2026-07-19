package mptcp

import "net"

func SetNetDialer(dialer *net.Dialer, open bool) {
	dialer.SetMultipathTCP(open)
}

func SetNetListenConfig(listenConfig *net.ListenConfig, open bool) {
	listenConfig.SetMultipathTCP(open)
}
