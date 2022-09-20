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

const (
	Identifier       = "scrypt"
	Identifier_Linux = "7"
)

type Params struct {
	N       int
	R       int
	P       int
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

	if id != Identifier && id != Identifier_Linux {
		return nil, fmt.Errorf("scrypt: unknown identifier %s", id)
	}

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
	v, err := parse(encoded)
	if err != nil {
		return verifier.Fail, err
	}

	res, err := v.verify(password)
	if err != nil || res == 0 {
		return verifier.Fail, err
	}

	if h.p != v.Params {
		return verifier.NeedUpdate, nil
	}

	return verifier.OK, nil
}

// ID implements passwap.Verifier
func (*Hasher) ID() string { return Identifier }

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
	v, err := parse(encoded)
	if err != nil {
		return verifier.Fail, err
	}

	return v.verify(password)
}

// Verifiers supported by this package.
var (
	Scrypt = verifier.NewFunc(Identifier, Verify)
)
