// Package scrypt provides salt generation, hashing
// and verification for x/crypto/scrypt.
package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/muhlemmer/passwap/internal/salt"
	"github.com/muhlemmer/passwap/verifier"
	"golang.org/x/crypto/scrypt"
)

// Identifiers and prefixes that describe and
// scrypt encoded hash string.
const (
	Identifier       = "scrypt"
	Identifier_Linux = "7"
	Prefix           = "$" + Identifier + "$"
	Prefix_Linux     = "$" + Identifier_Linux + "$"
)

type Params struct {
	// N, R, P are the cost parameters used
	// by scrypt.Key:
	// https://pkg.go.dev/golang.org/x/crypto/scrypt#Key
	N int
	R int
	P int

	// Lengths for key output and desired salt.
	KeyLen  int
	SaltLen uint32
}

// Format of the Modular Crypt Format, as used by passlib.
// See https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html#format-algorithm
const Format = "$%s$ln=%d,r=%d,p=%d$%s$%s"

var scanFormat = strings.ReplaceAll(Format, "$", " ")

type checker struct {
	Params

	hash []byte
	salt []byte
}

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix) && !strings.HasPrefix(encoded, Prefix_Linux) {
		return nil, nil
	}

	var (
		id   string
		ln   int
		salt string
		hash string
		c    checker
	)

	// scanning needs a space seperated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")

	_, err := fmt.Sscanf(encoded, scanFormat, &id, &ln, &c.R, &c.P, &salt, &hash)
	if err != nil {
		return nil, fmt.Errorf("scrypt parse: %w", err)
	}

	c.N = 1 << ln

	c.salt, err = base64.RawStdEncoding.Strict().DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("scrypt parse salt: %w", err)
	}

	c.hash, err = base64.RawStdEncoding.Strict().DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("scrypt parse hash: %w", err)
	}

	c.KeyLen = len(c.hash)
	c.SaltLen = uint32(len(c.salt))

	return &c, nil
}

func (c *checker) verify(pw string) (verifier.Result, error) {
	hash, err := scrypt.Key([]byte(pw), c.salt, c.N, c.R, c.P, c.KeyLen)
	if err != nil {
		return verifier.Fail, err
	}
	res := subtle.ConstantTimeCompare(hash, c.hash)

	return verifier.Result(res), nil
}

type Hasher struct {
	p    Params
	rand io.Reader
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	salt, err := salt.New(h.rand, h.p.SaltLen)
	if err != nil {
		return "", fmt.Errorf("scrypt: %w", err)
	}

	hash, err := scrypt.Key([]byte(password), salt, h.p.N, h.p.R, h.p.P, h.p.KeyLen)
	if err != nil {
		return "", err
	}

	ln := int(math.Log2(float64(h.p.N)))

	return fmt.Sprintf(Format,
		Identifier, ln, h.p.R, h.p.P,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// Verify implements passwap.Verifier
func (h *Hasher) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	res, err := c.verify(password)
	if err != nil || res == 0 {
		return verifier.Fail, err
	}

	if h.p != c.Params {
		return verifier.NeedUpdate, nil
	}

	return verifier.OK, nil
}

func New(p Params) *Hasher {
	return &Hasher{
		p:    p,
		rand: rand.Reader,
	}
}

// Verify parses encoded and uses its scrypt parameters
// to verify password against its hash.
// Either the result of Fail or OK is returned,
// or an error if parsing fails.
func Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password)
}

// Verifier for Scrypt.
var Verifier = verifier.VerifyFunc(Verify)
