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

const (
	DefaultMinRounds = 7
	DefaultMaxRounds = 31
)

type ValidationOpts struct {
	MinRounds int
	MaxRounds int
}

var DefaultValidationOpts = &ValidationOpts{
	MinRounds: DefaultMinRounds,
	MaxRounds: DefaultMaxRounds,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return DefaultValidationOpts
	}
	if opts.MinRounds == 0 {
		opts.MinRounds = DefaultMinRounds
	}
	if opts.MaxRounds == 0 {
		opts.MaxRounds = DefaultMaxRounds
	}
	return opts
}

type Verifier struct {
	opts *ValidationOpts
}

func NewVerifier(opts *ValidationOpts) *Verifier {
	return &Verifier{
		opts: checkValidationOpts(opts),
	}
}

func (v *Verifier) Validate(encoded string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	err = c.validate(v.opts)
	if err != nil {
		return verifier.Fail, err
	}
	return verifier.OK, nil
}

const HashLength = 34

// Verify checks if the given password matches the provided PHPass hash.
func (v *Verifier) Verify(hash, password string) (verifier.Result, error) {
	c, err := parse(hash)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	res := c.verify([]byte(password))
	return verifier.Result(res), nil
}

type checker struct {
	hash       []byte
	identifier []byte
	salt       []byte
	rounds     int
}

func parse(encoded string) (*checker, error) {
	c := &checker{
		hash: []byte(encoded),
	}

	if strings.HasPrefix(encoded, IdentifierP) {
		c.identifier = []byte(IdentifierP)
	} else if strings.HasPrefix(encoded, IdentifierH) {
		c.identifier = []byte(IdentifierH)
	} else {
		return nil, errors.New("invalid identifier")
	}

	if len(encoded) != HashLength {
		return nil, errors.New("invalid phpass hash length")
	}

	// Extract rounds and salt
	c.rounds = encoding.DecodeInt6(encoded[3])
	c.salt = []byte(encoded[4:12])
	return c, nil
}

func (c *checker) validate(opts *ValidationOpts) error {
	if c.rounds < opts.MinRounds || c.rounds > opts.MaxRounds {
		return &verifier.BoundsError{
			Algorithm: "phpass" + string(c.identifier),
			Param:     "rounds",
			Min:       opts.MinRounds,
			Max:       opts.MaxRounds,
			Actual:    c.rounds,
		}
	}
	return nil
}

func (c *checker) verify(password []byte) verifier.Result {
	hash := md5.New()
	hash.Write(append(c.salt, password...))

	digest := hash.Sum(nil)
	for i := 0; i < 1<<uint(c.rounds); i++ {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		digest = hash.Sum(nil)
	}
	out := make([]byte, HashLength)
	copy(out, c.identifier)
	out[3] = encoding.EncodeInt6(c.rounds)
	copy(out[4:12], c.salt)
	encodedDigest := encoding.EncodeCrypt3(digest[:16])
	copy(out[12:], encodedDigest)

	return verifier.Result(subtle.ConstantTimeCompare(out, c.hash))
}
