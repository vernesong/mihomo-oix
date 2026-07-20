package oix

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func init() {
	AppSecret = decodeSecret(AppSecret, 0xA3)
	oixdns.DNSPrivateKey = decodeSecret(oixdns.DNSPrivateKey, 0x9B)
	oixdns.NodesDomains = decodeSecret(oixdns.NodesDomains, 0xE8)
	oixdns.DNSAddr = decodeSecret(oixdns.DNSAddr, 0xF2)
	ApiDomains = decodeSecret(ApiDomains, 0x5E)
	SpareApiDomain = decodeSecret(SpareApiDomain, 0x6D)
}

// decodeSecret decodes an injected secret. "v2:" values use the runtime-derived
// SHA256-CTR keystream (per-value nonce, no single constant key); anything else
// falls back to the legacy fixed-seed XOR-hex so secrets can migrate to v2 via
// the build/CI encoder without breaking existing values.
func decodeSecret(encoded string, legacySeed byte) string {
	if strings.HasPrefix(encoded, "v2:") {
		if out, ok := decodeV2(encoded); ok {
			return out
		}
		return ""
	}
	return decodeXORHex(encoded, legacySeed)
}

func decodeXORHex(encoded string, keySeed byte) string {
	if encoded == "" {
		return ""
	}
	// "raw:" prefix bypasses XOR decoding for plaintext ldflags values.
	if strings.HasPrefix(encoded, "raw:") {
		return encoded[4:]
	}
	data, err := hex.DecodeString(encoded)
	if err != nil {
		return encoded
	}
	for i := range data {
		data[i] ^= keySeed ^ byte(i)
	}
	return string(data)
}

func obfMaster() []byte {
	a := []byte{0x3d, 0xa1, 0x5c, 0xe8, 0x27, 0x9f, 0x4b, 0xd6, 0x10, 0x8c, 0x63, 0xf2, 0x59, 0xb4, 0x0e, 0xc7}
	b := []byte{0x91, 0x2e, 0xd7, 0x48, 0xba, 0x05, 0x6f, 0xe3, 0x1c, 0x87, 0x50, 0xa9, 0x3b, 0xce, 0x74, 0x12}
	seed := make([]byte, 0, len(a)+len(b)+17)
	seed = append(seed, a...)
	seed = append(seed, b...)
	seed = append(seed, []byte("oix-obf-v2-mihomo")...)
	h := sha256.Sum256(seed)
	return h[:]
}

func keystream(nonce []byte, count int) []byte {
	master := obfMaster()
	out := make([]byte, 0, count)
	var counter uint32
	for len(out) < count {
		block := make([]byte, 0, len(master)+len(nonce)+4)
		block = append(block, master...)
		block = append(block, nonce...)
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], counter)
		block = append(block, be[:]...)
		h := sha256.Sum256(block)
		out = append(out, h[:]...)
		counter++
	}
	return out[:count]
}

// decodeV2 reverses the v2 obfuscation: "v2:" + base64(nonce(8) || plaintext XOR
// keystream). Returns ok=false on malformed input.
func decodeV2(encoded string) (string, bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, "v2:"))
	if err != nil || len(raw) < 8 {
		return "", false
	}
	nonce := raw[:8]
	ct := raw[8:]
	ks := keystream(nonce, len(ct))
	out := make([]byte, len(ct))
	for i := range ct {
		out[i] = ct[i] ^ ks[i]
	}
	return string(out), true
}
