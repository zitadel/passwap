// Package md5 provides hashing and verification of
// md5Crypt encoded passwords with salt.
// [The algorithm](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.md5_crypt.html#algorithm)
// builds hashes through multiple digest iterations
// with shuffles of password and salt.
//
// Note that md5 is considered cryptographically broken
// and should not be used for new applications.
// This package is only provided for legacy applications
// that wish to migrate away from md5 to newer hashing methods.
package md5

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strings"

	"github.com/zitadel/passwap/internal/encoding"
	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
)

const (
	Identifier = "1"
	Prefix     = "$" + Identifier + "$"

	// Format of the Modular Crypt Format, as used by passlib.
	// See https://passlib.readthedocs.io/en/stable/lib/passlib.hash.md5_crypt.html#format
	Format = Prefix + "%s$%s"
)

var swaps = [md5.Size]int{12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11}

// checksum implements https://passlib.readthedocs.io/en/stable/lib/passlib.hash.md5_crypt.html#algorithm
func checksum(password, salt []byte) []byte {
	digest := md5.New()
	digest.Write(password)
	digest.Write(salt)
	digest.Write(password)
	hash := digest.Sum(nil)

	digest.Reset()
	digest.Write(password)
	digest.Write([]byte(Prefix))
	digest.Write(salt)

	for i := 0; i < len(password); i++ {
		digest.Write([]byte{hash[i%16]})
	}

	for i := len(password); i != 0; i >>= 1 {
		if i&1 == 0 {
			digest.Write(password[0:1])
			continue
		}
		digest.Write([]byte{0})
	}

	hash = digest.Sum(nil)

	for i := 0; i < 1000; i++ {
		digest.Reset()

		if i&1 == 1 {
			digest.Write(password)
		} else {
			digest.Write(hash)
		}

		if i%3 != 0 {
			digest.Write(salt)
		}

		if i%7 != 0 {
			digest.Write(password)
		}

		if i&1 == 0 {
			digest.Write(password)
		} else {
			digest.Write(hash)
		}

		hash = digest.Sum(nil)
	}

	swapped := make([]byte, md5.Size)

	for i, j := range swaps {
		swapped[i] = hash[j]
	}

	return encoding.EncodeCrypt3(swapped)
}

// 6 saltbytes result in 8 characters of encoded salt.
const saltBytes = 6

func hash(r io.Reader, password string) (string, error) {
	salt, err := salt.New(r, saltBytes)
	if err != nil {
		return "", fmt.Errorf("md5: %w", err)
	}

	encSalt := encoding.EncodeCrypt3(salt)

	checksum := checksum([]byte(password), encSalt)
	return fmt.Sprintf(Format, encSalt, checksum), nil
}

var scanFormat = strings.ReplaceAll(Format, "$", " ")

type checker struct {
	checksum []byte
	salt     []byte
}

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix) {
		return nil, nil
	}

	// scanning needs a space separated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")
	var c checker

	_, err := fmt.Sscanf(encoded, scanFormat, &c.salt, &c.checksum)
	if err != nil {
		return nil, fmt.Errorf("md5 parse: %w", err)
	}

	return &c, nil
}

func (c *checker) verify(password string) verifier.Result {
	checksum := checksum([]byte(password), c.salt)

	return verifier.Result(
		subtle.ConstantTimeCompare(checksum, c.checksum),
	)
}

// Verify parses encoded and verfies password against the checksum.
func Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password), nil
}

// Hasher provides an md5 hasher which always obtains
// a salt of 6 random bytes, resulting in 8 encoded characters.
// md5 is considered crypgraphically broken and this hasher
// should not be used in new applications.
// It is only provided for legacy applications that really
// depend on md5.
type Hasher struct{}

// Hash implements passwap.Hasher.
func (Hasher) Hash(password string) (string, error) {
	return hash(rand.Reader, password)
}

// Verify implements passwap.Verifier
func (Hasher) Verify(encoded, password string) (verifier.Result, error) {
	return Verify(encoded, password)
}

// Verifier for md5.
var Verifier = verifier.VerifyFunc(Verify)
