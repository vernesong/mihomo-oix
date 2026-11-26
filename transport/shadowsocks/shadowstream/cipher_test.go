package shadowstream

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST SP 800-38A F.3.13: fixed wire bytes distinguish CFB from CTR or AEAD.
func TestAESCFBWireCompatibility(t *testing.T) {
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	key := decode("2b7e151628aed2a6abf7158809cf4f3c")
	iv := decode("000102030405060708090a0b0c0d0e0f")
	plaintext := decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	ciphertext := decode("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6")
	c, err := AESCFB(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunkSize := range []int{1, 7, 16, 17, 64} {
		enc, dec := c.Encrypter(iv), c.Decrypter(iv)
		got := bytes.Clone(plaintext)
		for start := 0; start < len(got); start += chunkSize {
			end := min(start+chunkSize, len(got))
			enc.XORKeyStream(got[start:end], got[start:end])
		}
		if !bytes.Equal(got, ciphertext) {
			t.Fatalf("CFB ciphertext changed with chunk size %d", chunkSize)
		}
		for start := 0; start < len(got); start += chunkSize {
			end := min(start+chunkSize, len(got))
			dec.XORKeyStream(got[start:end], got[start:end])
		}
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("CFB decryption changed with chunk size %d", chunkSize)
		}
	}
}
