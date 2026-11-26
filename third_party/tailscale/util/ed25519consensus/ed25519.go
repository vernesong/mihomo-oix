// Copyright 2016 The Go Authors. All rights reserved.
// Copyright 2016 Henry de Valence. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ed25519consensus implements Ed25519 verification according to ZIP215.
package ed25519consensus

import (
	"crypto/ed25519"
	"crypto/sha512"

	"github.com/metacubex/edwards25519"
)

// Verify reports whether sig is a valid signature of message by publicKey,
// using precisely-specified validation criteria (ZIP 215) suitable for use in
// consensus-critical contexts.
func Verify(publicKey ed25519.PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != ed25519.PublicKeySize {
		return false
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false
	}

	A, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return false
	}
	A.Negate(A)

	h := sha512.New()
	h.Write(sig[:32])
	h.Write(publicKey[:])
	h.Write(message)
	var digest [64]byte
	h.Sum(digest[:0])

	hReduced, err := new(edwards25519.Scalar).SetUniformBytes(digest[:])
	if err != nil {
		return false
	}

	checkR, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}

	s, err := new(edwards25519.Scalar).SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	R := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(hReduced, A, s)
	p := new(edwards25519.Point).Subtract(R, checkR)
	p.MultByCofactor(p)
	return p.Equal(edwards25519.NewIdentityPoint()) == 1
}
