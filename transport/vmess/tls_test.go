package vmess

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	tlsC "github.com/metacubex/mihomo/component/tls"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

func TestStreamTLSConnECHRawALPN(t *testing.T) {
	const serverName = "origin.example.com"
	echConfigBase64, echKeyPEM, err := ech.GenECHConfig("front.example.com")
	if err != nil {
		t.Fatal(err)
	}
	echConfigList, err := base64.StdEncoding.DecodeString(echConfigBase64)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, privateKeyPEM, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	const alpn = "snell-ech/1"
	const exporterLabel = "EXPORTER-Dler-Snell-Identity-v2"
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{alpn},
	}
	if err = ech.LoadECHKey(echKeyPEM, serverConfig); err != nil {
		t.Fatal(err)
	}

	clientECH := &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
		return echConfigList, nil
	}}
	clientSessionCache := utls.NewLRUClientSessionCache(2)
	type serverResult struct {
		exporter []byte
		err      error
	}
	for attempt := range 2 {
		serverSide, clientSide := net.Pipe()
		deadline := time.Now().Add(5 * time.Second)
		_ = serverSide.SetDeadline(deadline)
		_ = clientSide.SetDeadline(deadline)
		result := make(chan serverResult, 1)
		go func() {
			defer serverSide.Close()
			serverConn := tls.Server(serverSide, serverConfig)
			if err := serverConn.Handshake(); err != nil {
				result <- serverResult{err: err}
				return
			}
			state := serverConn.ConnectionState()
			if !state.ECHAccepted {
				result <- serverResult{err: fmt.Errorf("server did not accept ECH")}
				return
			}
			if state.NegotiatedProtocol != alpn {
				result <- serverResult{err: fmt.Errorf("server ALPN = %q, want %s", state.NegotiatedProtocol, alpn)}
				return
			}
			exporter, err := state.ExportKeyingMaterial(exporterLabel, []byte{}, 32)
			if err != nil {
				result <- serverResult{err: err}
				return
			}
			var payload [4]byte
			if _, err = io.ReadFull(serverConn, payload[:]); err == nil {
				_, err = serverConn.Write(payload[:])
			}
			result <- serverResult{exporter: exporter, err: err}
		}()

		clientConn, err := StreamTLSConn(context.Background(), clientSide, &TLSConfig{
			Host:                 serverName,
			SkipCertVerify:       true,
			ClientFingerprint:    "chrome",
			NextProtos:           []string{alpn},
			ECH:                  clientECH,
			UClientSessionCache:  clientSessionCache,
			DisableRenegotiation: true,
		})
		if err != nil {
			t.Fatalf("attempt %d: StreamTLSConn() error = %v", attempt, err)
		}
		clientState := tlsC.GetTLSConnectionState(clientConn)
		clientExporter, err := clientState.ExportKeyingMaterial(exporterLabel, []byte{}, 32)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if _, err = clientConn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		var echo [4]byte
		if _, err = io.ReadFull(clientConn, echo[:]); err != nil {
			t.Fatal(err)
		}
		_ = clientConn.Close()
		server := <-result
		if server.err != nil {
			t.Fatal(server.err)
		}
		if !bytes.Equal(clientExporter, server.exporter) {
			t.Fatalf("attempt %d: client exporter = %x, server exporter = %x", attempt, clientExporter, server.exporter)
		}
	}
}
