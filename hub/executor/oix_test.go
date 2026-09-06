package executor

import (
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/oix"
	C "github.com/metacubex/mihomo/constant"
)

func TestShutdownStopsOIXUpdates(t *testing.T) {
	homeDir := t.TempDir()
	oldHomeDir, oldToken := C.Path.HomeDir(), oix.CurrentToken()
	oldSecret, oldDomains, oldSpare := oix.AppSecret, oix.ApiDomains, oix.SpareApiDomain
	t.Setenv("OIX_TOKEN", "")
	t.Setenv("OIX_UPDATE_INTERVAL", "1")
	C.SetHomeDir(homeDir)
	oix.SetToken("test-token")
	oix.AppSecret, oix.SpareApiDomain = "test-secret", ""
	t.Cleanup(func() {
		oix.StopPeriodicUpdate()
		C.SetHomeDir(oldHomeDir)
		oix.SetToken(oldToken)
		oix.AppSecret, oix.ApiDomains, oix.SpareApiDomain = oldSecret, oldDomains, oldSpare
	})

	// Reject TLS so an active fetch would retry unless shutdown cancels it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}()
	oix.ApiDomains = "https://" + listener.Addr().String()
	oix.StartPeriodicUpdate("providers", homeDir)
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("periodic OIX update did not start")
	}

	Shutdown()
	select {
	case <-accepted:
		t.Fatal("OIX update retried after shutdown")
	case <-time.After(2 * time.Second):
	}
}
