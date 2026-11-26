package keepalive

import "net"

type TCPConn interface {
	net.Conn
	SetKeepAlive(keepalive bool) error
	SetKeepAliveConfig(config net.KeepAliveConfig) error
}

func keepAliveConfig() net.KeepAliveConfig {
	config := net.KeepAliveConfig{
		Enable:   true,
		Idle:     KeepAliveIdle(),
		Interval: KeepAliveInterval(),
	}
	if !supportTCPKeepAliveCount() {
		config.Count = -1
	}
	return config
}

func tcpKeepAlive(tcp TCPConn) {
	if DisableKeepAlive() {
		_ = tcp.SetKeepAlive(false)
	} else {
		_ = tcp.SetKeepAliveConfig(keepAliveConfig())
	}
}

func setNetDialer(dialer *net.Dialer) {
	if DisableKeepAlive() {
		dialer.KeepAlive = -1
		dialer.KeepAliveConfig.Enable = false
	} else {
		dialer.KeepAliveConfig = keepAliveConfig()
	}
}

func setNetListenConfig(lc *net.ListenConfig) {
	if DisableKeepAlive() {
		lc.KeepAlive = -1
		lc.KeepAliveConfig.Enable = false
	} else {
		lc.KeepAliveConfig = keepAliveConfig()
	}
}
