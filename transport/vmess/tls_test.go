package vmess

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/tls"
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
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}
	if err = ech.LoadECHKey(echKeyPEM, serverConfig); err != nil {
		t.Fatal(err)
	}

	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	deadline := time.Now().Add(5 * time.Second)
	_ = serverSide.SetDeadline(deadline)
	_ = clientSide.SetDeadline(deadline)
	serverResult := make(chan error, 1)
	go func() {
		serverConn := tls.Server(serverSide, serverConfig)
		if err := serverConn.Handshake(); err != nil {
			serverResult <- err
			return
		}
		state := serverConn.ConnectionState()
		if !state.ECHAccepted {
			serverResult <- fmt.Errorf("server did not accept ECH")
			return
		}
		if state.NegotiatedProtocol != "h2" {
			serverResult <- fmt.Errorf("server ALPN = %q, want h2", state.NegotiatedProtocol)
			return
		}
		var payload [4]byte
		if _, err := io.ReadFull(serverConn, payload[:]); err != nil {
			serverResult <- err
			return
		}
		_, err := serverConn.Write(payload[:])
		serverResult <- err
	}()

	clientECH := &ech.Config{GetEncryptedClientHelloConfigList: func(context.Context, string) ([]byte, error) {
		return echConfigList, nil
	}}
	clientConn, err := StreamTLSConn(context.Background(), clientSide, &TLSConfig{
		Host:              serverName,
		SkipCertVerify:    true,
		ClientFingerprint: "chrome",
		NextProtos:        []string{"h2"},
		ECH:               clientECH,
	})
	if err != nil {
		t.Fatalf("StreamTLSConn() error = %v", err)
	}
	if _, err = clientConn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var echo [4]byte
	if _, err = io.ReadFull(clientConn, echo[:]); err != nil {
		t.Fatal(err)
	}
	if string(echo[:]) != "ping" {
		t.Fatalf("echo = %q, want ping", echo[:])
	}
	if err = <-serverResult; err != nil {
		t.Fatal(err)
	}
}
