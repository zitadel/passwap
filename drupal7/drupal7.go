// Package drupal provides verification of
// passwords hashed using the Drupal 7 password hashing method.
//
// This verifier handles Drupal 7 password hashes that start with $S$ and uses
// SHA-512 with a custom iteration count and base64 encoding scheme.
// Note that while more secure than traditional MD5,
// this is still considered a legacy algorithm for modern applications.
// See original implementation at https://api.drupal.org/api/drupal/includes!password.inc/function/_password_crypt/7.x
package drupal7

import (
	"bytes"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/zitadel/passwap/internal/encoding"
	"github.com/zitadel/passwap/verifier"
)

const (
	Identifier = "$S$"
	HashLength = 55
	Format     = "%s%s%s%s"
)

const (
	DefaultMinIterations = 1000
	DefaultMaxIterations = 500000
)

type checker struct {
	iterations int
	salt       []byte
	hash       []byte
}

func parse(hash string) (*checker, error) {
	if !strings.HasPrefix(hash, Identifier) {
		return nil, errors.New("invalid identifier")
	}
	if len(hash) != HashLength {
		return nil, errors.New("invalid drupal hash length")
	}
	hashB := []byte(hash)

	// Components from the hash
	// Format: $S$ + iteration_char + 8_char_salt + 43_char_hash
	iterations := getIterationCount(hash[3]) // Character at position 3
	if iterations == -1 {
		return nil, errors.New("invalid iteration character")
	}
	return &checker{
		iterations: iterations,
		salt:       bytes.Clone(hashB[4:12]), // Characters 4-11 (8 chars)
		hash:       bytes.Clone(hashB[12:]),  // Rest is the hash (43 chars)
	}, nil
}

func (c *checker) verify(password string) verifier.Result {
	computedHashPortion := hashPassword([]byte(password), c.salt, c.iterations)
	// Compare only the hash portion (truncate computed hash to match stored length)
	if len(computedHashPortion) > len(c.hash) {
		computedHashPortion = computedHashPortion[:len(c.hash)]
	}
	match := subtle.ConstantTimeCompare(computedHashPortion, c.hash)
	return verifier.Result(match)
}

type ValidationOpts struct {
	MinIterations int
	MaxIterations int
}

var DefaultValidationOpts = &ValidationOpts{
	MinIterations: DefaultMinIterations,
	MaxIterations: DefaultMaxIterations,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return DefaultValidationOpts
	}
	if opts.MinIterations <= 0 {
		opts.MinIterations = DefaultMinIterations
	}
	if opts.MaxIterations <= 0 {
		opts.MaxIterations = DefaultMaxIterations
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

func (v *Verifier) Validate(hash string) (verifier.Result, error) {
	c, err := parse(hash)
	if err != nil || c == nil {
		return verifier.Skip, fmt.Errorf("drupal7 parse: %w", err)
	}
	if c.iterations < v.opts.MinIterations || c.iterations > v.opts.MaxIterations {
		return verifier.Fail, &verifier.BoundsError{
			Algorithm: "Drupal 7",
			Param:     "iterations",
			Min:       v.opts.MinIterations,
			Max:       v.opts.MaxIterations,
			Actual:    c.iterations,
		}
	}
	return verifier.OK, nil
}

// Verify checks if the given password matches the provided Drupal 7 password hash.
func (v *Verifier) Verify(hash, password string) (verifier.Result, error) {
	c, err := parse(hash)
	if err != nil || c == nil {
		return verifier.Skip, fmt.Errorf("drupal7 parse: %w", err)
	}
	return c.verify(password), nil
}

// getIterationCount extracts the iteration count from the hash character
func getIterationCount(char byte) int {
	alphabet := "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	index := strings.IndexByte(alphabet, char)
	if index == -1 {
		return -1
	}
	return 1 << uint(index)
}

// hashPassword implements Drupal's password hashing algorithm
func hashPassword(password, salt []byte, iterations int) []byte {
	// Initial hash: SHA-512(salt + password)
	hash := sha512.New()
	hash.Write(append(salt, password...))
	digest := hash.Sum(nil)

	// Iterate: SHA-512(previous_hash + password)
	for i := 0; i < iterations; i++ {
		hash.Reset()
		hash.Write(digest)
		hash.Write(password)
		digest = hash.Sum(nil)
	}

	// Use crypt3 encoding
	return encoding.EncodeCrypt3(digest)
}
