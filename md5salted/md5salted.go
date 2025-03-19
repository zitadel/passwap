// Package md5salted provides hashing and verification of
// md5 encoded passwords prefixed or suffixed with salt.
//
// Note that md5 is considered cryptographically broken
// and should not be used for new applications.
// This package is only provided for legacy applications
// that wish to migrate away from md5 to newer hashing methods.
package md5salted

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/zitadel/passwap/verifier"
)

const (
	Identifier         = "md5salted"
	IdentifierSuffixed = Identifier + "-suffix"
	IdentifierPrefixed = Identifier + "-prefix"
	Prefix             = "$" + Identifier

	Format = "$%s$%s$%s"
)

var scanFormat = strings.ReplaceAll(Format, "$", " ")

type checker struct {
	salt          string
	hash          string
	saltpasswfunc func(string) []byte
}

func (c *checker) setSaltPasswFunc(id string) {
	switch id {
	case IdentifierPrefixed:
		c.saltpasswfunc = func(passw string) []byte {
			return []byte(c.salt + passw)
		}
	case IdentifierSuffixed:
		c.saltpasswfunc = func(passw string) []byte {
			return []byte(passw + c.salt)
		}
	default:
		c.saltpasswfunc = nil
	}
}

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix) {
		return nil, nil
	}

	// scanning needs a space separated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")
	var c checker
	var id string
	_, err := fmt.Sscanf(encoded, scanFormat, &id, &c.salt, &c.hash)
	if err != nil {
		return nil, fmt.Errorf("md5salted parse: %w", err)
	}
	c.setSaltPasswFunc(id)
	if c.saltpasswfunc == nil {
		return nil, fmt.Errorf("md5salted unknown identifier: %s", id)
	}
	return &c, nil
}

func (c *checker) verify(password string) (verifier.Result, error) {
	checksum := md5.Sum(c.saltpasswfunc(password))
	decoded, err := base64.StdEncoding.DecodeString(c.hash)
	if err != nil {
		return verifier.Skip, err
	}

	return verifier.Result(
		subtle.ConstantTimeCompare(checksum[:], decoded),
	), nil
}

// Verify parses encoded and verifies password against the checksum.
func Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password)
}

var Verifier = verifier.VerifyFunc(Verify)
