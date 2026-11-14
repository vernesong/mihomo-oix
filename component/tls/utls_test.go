package tls

import (
	"encoding/json"
	"net"
	"testing"

	utls "github.com/metacubex/utls"
)

type stateConn struct {
	net.Conn
	state utls.ConnectionState
}

func (c stateConn) ConnectionState() utls.ConnectionState { return c.state }

func TestTLSStateLegacyFieldCompatibility(t *testing.T) {
	for _, mutual := range []bool{false, true} {
		original := utls.ConnectionState{
			Version:            utls.VersionTLS13,
			HandshakeComplete:  true,
			NegotiatedProtocol: "h2",
		}
		// Exercise the legacy field through its public JSON representation.
		input, err := json.Marshal(map[string]bool{"NegotiatedProtocolIsMutual": mutual})
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(input, &original); err != nil {
			t.Fatal(err)
		}
		converted := GetTLSConnectionState(stateConn{state: original})
		if converted.Version != original.Version || converted.NegotiatedProtocol != "h2" || !converted.HandshakeComplete {
			t.Fatal("connection state changed during conversion")
		}
		// Check the publicly serialized state without adding deprecated API uses.
		encoded, err := json.Marshal(converted)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		var got bool
		if err := json.Unmarshal(fields["NegotiatedProtocolIsMutual"], &got); err != nil {
			t.Fatal(err)
		}
		if got != mutual {
			t.Fatalf("legacy TLS field = %v, want %v", got, mutual)
		}
	}
}
