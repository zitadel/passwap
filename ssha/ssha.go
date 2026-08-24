// Package ssha provides verification of (Salted) SHA encoded passwords,
// using the `{SCHEME}base64(...)` notation described in RFC 2307.
//
// This is the format commonly used by OpenLDAP's userPassword attribute
// and by Zope's SHA1PasswordManager / SSHAPasswordManager. It is provided
// so that applications can migrate users away from OpenLDAP, Zope and
// similar systems to a stronger hashing algorithm.
//
// For salted schemes ("SSHA", "SSHA256", "SSHA384", "SSHA512") the digest
// is computed over password+salt and the (variable length) salt is
// appended to the digest before base64 encoding. Unsalted schemes ("SHA",
// "SHA256", "SHA384", "SHA512") are plain, single iteration digests of the
// password, without salt.
//
// Note that a single iteration of SHA-1/SHA-2 is considered too weak for
// new applications. This package therefore only provides a Verifier, to
// allow migration to a stronger algorithm.
package ssha

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"

	"github.com/zitadel/passwap/verifier"
)

const (
	IdentifierSHA     = "{SHA}"
	IdentifierSSHA    = "{SSHA}"
	IdentifierSHA256  = "{SHA256}"
	IdentifierSSHA256 = "{SSHA256}"
	IdentifierSHA384  = "{SHA384}"
	IdentifierSSHA384 = "{SSHA384}"
	IdentifierSHA512  = "{SHA512}"
	IdentifierSSHA512 = "{SSHA512}"
)

type scheme struct {
	identifier string
	salted     bool
	newHash    func() hash.Hash
	size       int
}

// Order does not matter for correctness, as every identifier is
// terminated by a closing brace, so none of them is a prefix of another.
var schemes = []scheme{
	{IdentifierSSHA, true, sha1.New, sha1.Size},
	{IdentifierSSHA256, true, sha256.New, sha256.Size},
	{IdentifierSSHA384, true, sha512.New384, sha512.Size384},
	{IdentifierSSHA512, true, sha512.New, sha512.Size},
	{IdentifierSHA, false, sha1.New, sha1.Size},
	{IdentifierSHA256, false, sha256.New, sha256.Size},
	{IdentifierSHA384, false, sha512.New384, sha512.Size384},
	{IdentifierSHA512, false, sha512.New, sha512.Size},
}

type checker struct {
	scheme scheme
	digest []byte
	salt   []byte
}

func parse(encoded string) (*checker, error) {
	for _, s := range schemes {
		if !strings.HasPrefix(encoded, s.identifier) {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, s.identifier))
		if err != nil {
			return nil, fmt.Errorf("ssha parse: %w", err)
		}
		if len(decoded) < s.size {
			return nil, fmt.Errorf("ssha parse: %s digest too short", s.identifier)
		}
		if !s.salted && len(decoded) != s.size {
			return nil, fmt.Errorf("ssha parse: %s digest length mismatch", s.identifier)
		}
		return &checker{
			scheme: s,
			digest: decoded[:s.size],
			salt:   decoded[s.size:],
		}, nil
	}
	return nil, nil
}

func (c *checker) verify(password string) verifier.Result {
	h := c.scheme.newHash()
	h.Write([]byte(password))
	h.Write(c.salt)
	sum := h.Sum(nil)

	return verifier.Result(subtle.ConstantTimeCompare(sum, c.digest))
}

type Verifier struct{}

func NewVerifier() *Verifier {
	return &Verifier{}
}

func (*Verifier) Validate(encoded string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	return verifier.OK, nil
}

// Verify parses encoded and verifies password against the checksum.
func (*Verifier) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	return c.verify(password), nil
}
