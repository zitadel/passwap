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
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/zitadel/passwap/verifier"
)

const (
	Identifier = "$S$"
	HashLength = 55
	Format     = "%s%s%s%s"
)

// Verify checks if the given password matches the provided Drupal 7 password hash.
func Verify(hash, password string) (verifier.Result, error) {
	if !strings.HasPrefix(hash, Identifier) {
		return verifier.Skip, errors.New("invalid identifier")
	}

	if len(hash) != HashLength {
		return verifier.Skip, errors.New("invalid drupal hash length")
	}

	// Components from the hash
	// Format: $S$ + iteration_char + 8_char_salt + 43_char_hash
	iterationChar := hash[3]          // Character at position 3
	salt := hash[4:12]                // Characters 4-11 (8 chars)
	storedHashPortion := hash[12:]    // Rest is the hash (43 chars)

	// Get iteration count from the character
	iterations := getIterationCount(iterationChar)
	if iterations == -1 {
		return verifier.Skip, errors.New("invalid iteration character")
	}

	// Hash the provided password with the same salt and iterations
	computedHashPortion := hashPassword(password, salt, iterations)

	// Compare only the hash portion (truncate computed hash to match stored length)
	if len(computedHashPortion) > len(storedHashPortion) {
		computedHashPortion = computedHashPortion[:len(storedHashPortion)]
	}

	match := subtle.ConstantTimeCompare([]byte(computedHashPortion), []byte(storedHashPortion))

	return verifier.Result(match), nil
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
func hashPassword(password, salt string, iterations int) string {
	// Initial hash: SHA-512(salt + password)
	hash := sha512.New()
	hash.Write([]byte(salt + password))
	digest := hash.Sum(nil)

	// Iterate: SHA-512(previous_hash + password)
	for i := 0; i < iterations; i++ {
		hash.Reset()
		hash.Write(digest)
		hash.Write([]byte(password))
		digest = hash.Sum(nil)
	}

	// Use Drupal's custom base64 encoding (which is the same as crypt3)
	return drupalBase64Encode(digest)
}

// drupalBase64Encode implements Drupal's custom base64 encoding
func drupalBase64Encode(input []byte) string {
	const alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	output := ""
	count := len(input)
	i := 0

	for i < count {
		value := int(input[i])
		i++
		output += string(alphabet[value&0x3f])

		if i < count {
			value |= int(input[i]) << 8
		}
		output += string(alphabet[(value>>6)&0x3f])

		if i >= count {
			break
		}
		i++

		if i < count {
			value |= int(input[i]) << 16
		}
		output += string(alphabet[(value>>12)&0x3f])

		if i >= count {
			break
		}
		i++

		output += string(alphabet[(value>>18)&0x3f])
	}

	return output
}

var Verifier = verifier.VerifyFunc(Verify)
