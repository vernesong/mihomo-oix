package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

func masqueMemoryOption(tb testing.TB) MasqueOption {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		tb.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	return MasqueOption{
		Name: "masque", Server: "127.0.0.1", Port: 9, Ip: "10.0.0.2/32", UDP: true,
		PrivateKey: base64.StdEncoding.EncodeToString(private),
		PublicKey:  base64.StdEncoding.EncodeToString(public),
	}
}

func BenchmarkNewMasque(b *testing.B) {
	option := masqueMemoryOption(b)
	modes := []string{ipStackMips}
	if features.WithGVisor {
		modes = append(modes, ipStackGVisor)
	}
	for _, mode := range modes {
		b.Run(mode, func(b *testing.B) {
			option.IPStack.Mode = mode
			b.ReportAllocs()
			for b.Loop() {
				node, err := NewMasque(option)
				if err != nil {
					b.Fatal(err)
				}
				_ = node.Close()
			}
		})
	}
}

func BenchmarkNewTuic(b *testing.B) {
	option := TuicOption{Name: "tuic", Server: "127.0.0.1", Port: 9, UUID: "9f3fe162-0d26-475b-9f8c-7f121923206a", Password: "test"}
	if _, err := NewTuic(option); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		node, err := NewTuic(option)
		if err != nil {
			b.Fatal(err)
		}
		_ = node.Close()
	}
}

func BenchmarkBaseMarshalJSON(b *testing.B) {
	node := NewBase(BaseOption{Name: "direct", Type: C.Direct})
	b.ReportAllocs()
	for b.Loop() {
		if _, err := node.MarshalJSON(); err != nil {
			b.Fatal(err)
		}
	}
}
