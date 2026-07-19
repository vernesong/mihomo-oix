//go:build unix

package keepalive

func supportTCPKeepAliveCount() bool {
	return true
}
