// Package phpass provides verification of
// passwords hashed using the PHPass algorithm.
//
// Note that PHPass is based on MD5 and is considered weak by modern standards.
// This package is only provided for legacy applications
// that wish to migrate away from PHPass to newer hashing methods.
package phpass

import (
	"crypto/md5"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/zitadel/passwap/internal/encoding"
	"github.com/zitadel/passwap/verifier"
)

const (
	IdentifierP = "$P$"
	IdentifierH = "$H$"

	Format = "%s$%s"
)

// Verify checks if the given password matches the provided PHPass hash.
func Verify(hash, password string) (verifier.Result, error) {
	var identifier string

	if strings.HasPrefix(hash, IdentifierP) {
		identifier = IdentifierP
	} else if strings.HasPrefix(hash, IdentifierH) {
		identifier = IdentifierH
	} else {
		return verifier.Skip, errors.New("invalid identifier")
	}

	if len(hash) < 34 {
		return verifier.Skip, errors.New("invalid phpass hash length")
	}

	// Extract rounds and salt
	rounds := encoding.DecodeInt6(hash[3])
	if rounds < 7 || rounds > 31 {
		return verifier.Skip, errors.New("invalid rounds factor")
	}
	salt := hash[4:12]

	res := crypt(password, salt, rounds, identifier)

	match := subtle.ConstantTimeCompare([]byte(res), []byte(hash))

	return verifier.Result(match), nil
}

func crypt(password, salt string, rounds int, identifier string) string {
	hash := md5.New()
	hash.Write([]byte(salt + password))

	digest := hash.Sum(nil)
	for i := 0; i < 1<<uint(rounds); i++ {
		hash.Reset()
		hash.Write(digest)
		hash.Write([]byte(password))
		digest = hash.Sum(nil)
	}

	return identifier + string(encoding.EncodeInt6(rounds)) + salt + string(encoding.EncodeCrypt3(digest[:16]))
}

var Verifier = verifier.VerifyFunc(Verify)
