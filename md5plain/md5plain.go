// Package md5plain provides verification of
// plain md5 digests of passwords without salt.
//
// Note that md5 is considered cryptographically broken
// and should not be used for new applications.
// This package is only provided for legacy applications
// that wish to migrate away from md5 to newer hashing methods.
package md5plain

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/zitadel/passwap/verifier"
)

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (v *Verifier) Validate(digest string) (verifier.Result, error) {
	_, err := hex.DecodeString(digest)
	if err != nil {
		return verifier.Skip, fmt.Errorf("md5plain parse: %w", err)
	}
	return verifier.OK, nil
}

// Verify an plain md5 digest without salt.
// Digest must be hex encoded.
//
// Note that md5 digests do not have an identifier.
// Therefore it might be that Verify accepts any hex encoded string
// but fails password verification.
func (v *Verifier) Verify(digest, password string) (verifier.Result, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		return verifier.Skip, fmt.Errorf("md5plain parse: %w", err)
	}
	sum := md5.Sum([]byte(password))
	res := subtle.ConstantTimeCompare(sum[:], decoded)

	return verifier.Result(res), nil
}
