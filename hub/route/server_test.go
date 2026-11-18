package route

import (
	"net"
	"testing"

	"github.com/metacubex/mihomo/component/ca"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestDebugRoutesRequireControllerSecret(t *testing.T) {
	handler := router(true, "fixture-secret", "", Cors{})
	for _, token := range []string{"", "Bearer wrong", "Bearer fixture-secret"} {
		request := httptest.NewRequest(http.MethodPut, "/debug/gc", nil)
		request.Header.Set("Authorization", token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		want := http.StatusUnauthorized
		if token == "Bearer fixture-secret" {
			want = http.StatusOK
		}
		if response.Code != want {
			t.Errorf("token=%q: status=%d, want %d", token, response.Code, want)
		}
	}
}

func TestTLSConfigFailureReleasesListener(t *testing.T) {
	certificate, privateKey, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	startTLS(&Config{TLSAddr: address, Certificate: certificate, PrivateKey: privateKey, ClientAuthCert: "missing-review-certificate.pem"})
	listener, err = net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("TLS setup retained its listening port after failure: %v", err)
	}
	listener.Close()
}
