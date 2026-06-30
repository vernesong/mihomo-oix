package constant

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func TestMetadataStringMasksMarkedCloudIPWithoutHost(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	oixdns.MarkCloudIP(ip.String())

	metadata := &Metadata{DstIP: ip}
	if got := metadata.String(); got != "***.***.***.***" {
		t.Fatalf("expected masked OIX cloud IP, got %q", got)
	}
}
