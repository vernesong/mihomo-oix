package oix

import (
	"encoding/hex"
	"strings"

	"github.com/metacubex/mihomo/component/oix/oixdns"
)

func init() {
	AppSecret = decodeXORHex(AppSecret, 0xA3)
	AgeSecretKey = decodeXORHex(AgeSecretKey, 0xB7)
	AgePublicKey = decodeXORHex(AgePublicKey, 0xC1)
	oixdns.DNSSecret = decodeXORHex(oixdns.DNSSecret, 0xD4)
	oixdns.NodesDomains = decodeXORHex(oixdns.NodesDomains, 0xE8)
	oixdns.DNSAddr = decodeXORHex(oixdns.DNSAddr, 0xF2)
	ApiDomains = decodeXORHex(ApiDomains, 0x5E)
	ProfileKey = decodeXORHex(ProfileKey, 0x7F)
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
