package outbound

import (
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/tuic"

	"github.com/metacubex/quic-go"
)

func TestTuicBuildsSharedQUICConfigOnFirstUse(t *testing.T) {
	for _, token := range []string{"", "v4-token"} {
		option := TuicOption{Name: "tuic", Server: "127.0.0.1", Port: 9, Token: token}
		node, err := NewTuic(option)
		if err != nil {
			t.Fatal(err)
		}
		if node.quicConfig != nil {
			t.Fatal("unused node retained QUIC config")
		}
		if node.tlsConfig == nil {
			t.Fatal("TLS configuration and trust roots must be captured while parsing")
		}
		configs := make(chan *quic.Config, 32)
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() { configs <- node.getQUICConfig() })
		}
		wg.Wait()
		close(configs)
		config := node.getQUICConfig()
		for actual := range configs {
			if actual != config {
				t.Fatal("concurrent first uses did not share one configuration")
			}
		}
		overhead := tuic.PacketOverHeadV5
		if token != "" {
			overhead = tuic.PacketOverHeadV4
		}
		if config.MaxIncomingStreams != 110 || config.MaxIncomingUniStreams != 110 ||
			config.KeepAlivePeriod != 10*time.Second || !config.EnableDatagrams ||
			config.MaxDatagramFrameSize != int64(1252+overhead) ||
			config.InitialStreamReceiveWindow != tuic.DefaultStreamReceiveWindow/10 ||
			config.MaxConnectionReceiveWindow != tuic.DefaultConnectionReceiveWindow {
			t.Fatalf("changed TUIC defaults: %+v", config)
		}
	}
}
