package snell

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	IdentityAuthTagLength  = 16
	IdentityExporterLength = 32
	IdentityExporterLabel  = "EXPORTER-Dler-Snell-Identity-v2"
	identityV2RootLabel    = "oix/snell-ech/2/auth-root"
	identityWireMagicV2    = "DLSNID02"
)

func IdentityV2HeaderFromPSK(psk []byte) []byte {
	root := identityV2Root(psk)
	expanded := identityV2Expand(root, "identity")
	return append([]byte(nil), expanded[:IdentityHeaderLength]...)
}

func IdentityV2AuthTag(psk, exporter, salt []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("snell identity psk is empty")
	}
	if len(exporter) != IdentityExporterLength {
		return nil, fmt.Errorf("snell identity exporter length %d", len(exporter))
	}
	if len(salt) != v4SaltSize {
		return nil, fmt.Errorf("snell identity salt length %d", len(salt))
	}

	root := identityV2Root(psk)
	authKey := identityV2Expand(root, "authentication")
	identity := IdentityV2HeaderFromPSK(psk)
	mac := hmac.New(sha256.New, authKey[:])
	_, _ = mac.Write([]byte(identityWireMagicV2))
	_, _ = mac.Write(exporter)
	_, _ = mac.Write(salt)
	_, _ = mac.Write(identity)
	return append([]byte(nil), mac.Sum(nil)[:IdentityAuthTagLength]...), nil
}

func identityV2Root(psk []byte) [sha256.Size]byte {
	salt := sha256.Sum256([]byte(identityV2RootLabel))
	mac := hmac.New(sha256.New, salt[:])
	_, _ = mac.Write(psk)
	var root [sha256.Size]byte
	copy(root[:], mac.Sum(nil))
	return root
}

func identityV2Expand(root [sha256.Size]byte, info string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, root[:])
	_, _ = mac.Write([]byte(info))
	_, _ = mac.Write([]byte{1})
	var expanded [sha256.Size]byte
	copy(expanded[:], mac.Sum(nil))
	return expanded
}
