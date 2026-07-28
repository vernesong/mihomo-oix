package snell

import (
	"bytes"
	"testing"
)

func TestIdentityV2Header(t *testing.T) {
	psk := []byte("test-snell-ech-identity-v2")
	exporter := make([]byte, IdentityExporterLength)
	salt := make([]byte, v4SaltSize)
	for i := range exporter {
		exporter[i] = byte(i)
	}
	for i := range salt {
		salt[i] = byte(0xf0 + i)
	}

	identity := IdentityV2HeaderFromPSK(psk)
	if len(identity) != IdentityHeaderLength {
		t.Fatalf("identity length = %d", len(identity))
	}
	wantIdentity := []byte{
		0x39, 0x64, 0x4b, 0x63, 0x12, 0x2b, 0x80, 0x57,
		0xa8, 0xf9, 0x14, 0x9f, 0x1d, 0x9c, 0x80, 0x5c,
	}
	if !bytes.Equal(identity, wantIdentity) {
		t.Fatalf("identity = %x, want %x", identity, wantIdentity)
	}
	tag, err := IdentityV2AuthTag(psk, exporter, salt)
	if err != nil {
		t.Fatal(err)
	}
	wantTag := []byte{
		0xba, 0xbe, 0x8b, 0xba, 0x8b, 0x99, 0x27, 0x9b,
		0x49, 0x51, 0x62, 0x7c, 0x50, 0x6d, 0x2d, 0x9d,
	}
	if !bytes.Equal(tag, wantTag) {
		t.Fatalf("tag = %x, want %x", tag, wantTag)
	}
	changedSalt := append([]byte(nil), salt...)
	changedSalt[0] ^= 0xff
	changedTag, err := IdentityV2AuthTag(psk, exporter, changedSalt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(tag, changedTag) {
		t.Fatal("authentication tag is not bound to the Snell salt")
	}
}

func TestSnellV4ExporterIdentityFollowsSalt(t *testing.T) {
	var raw bytes.Buffer
	psk := []byte("password")
	exporter := make([]byte, IdentityExporterLength)
	writer, err := newV4Writer(&raw, psk)
	if err != nil {
		t.Fatal(err)
	}
	writer.identityExporter = exporter
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	wire := raw.Bytes()
	magicStart := v4SaltSize
	magicEnd := magicStart + len(identityWireMagicV2)
	identityEnd := magicEnd + IdentityHeaderLength
	tagEnd := identityEnd + IdentityAuthTagLength
	if len(wire) < tagEnd {
		t.Fatalf("identity frame too short: %d", len(wire))
	}
	if string(wire[magicStart:magicEnd]) != identityWireMagicV2 {
		t.Fatalf("identity magic = %q", wire[magicStart:magicEnd])
	}
	wantTag, err := IdentityV2AuthTag(psk, exporter, wire[:v4SaltSize])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[identityEnd:tagEnd], wantTag) {
		t.Fatal("identity authentication tag mismatch")
	}
}
