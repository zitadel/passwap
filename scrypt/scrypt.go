// Package scrypt provides salt generation, hashing
// and verification for x/crypto/scrypt.
package scrypt

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
)

// Identifiers and prefixes that describe and
// scrypt encoded hash string.
const (
	Identifier       = "scrypt"
	Identifier_Linux = "7"
	Prefix           = "$" + Identifier + "$"
	Prefix_Linux     = "$" + Identifier_Linux + "$"
)

// Defaults for scrypt validation options.
const (
	DefaultMinLN = 14
	DefaultMaxLN = 20
	DefaultMinR  = 8
	DefaultMaxR  = 32
	DefaultMinP  = 1
	DefaultMaxP  = 16
)

// Params holds the cost parameters for scrypt hashing.
// See [scrypt.Key]
type Params struct {
	LN int // log2 of N, the CPU/memory cost parameter
	R  int
	P  int

	// Lengths for key output and desired salt.
	KeyLen  int
	SaltLen uint32
}

var (
	RecommendedParams = Params{
		LN:      15,
		R:       8,
		P:       1,
		KeyLen:  32,
		SaltLen: 16,
	}
)

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
		salt string
		hash string
		c    checker
	)

	// scanning needs a space separated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")

	_, err := fmt.Sscanf(encoded, scanFormat, &id, &c.LN, &c.R, &c.P, &salt, &hash)
	if err != nil {
		return nil, fmt.Errorf("scrypt parse: %w", err)
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

var (
	ErrRxPTooLarge = errors.New("scrypt: r*p value larger than 2^30")
)

func (c *checker) validate(opts *ValidationOpts) error {
	if c.LN < opts.MinLN || c.LN > opts.MaxLN {
		return &verifier.BoundsError{
			Algorithm: Identifier,
			Param:     "LN",
			Min:       opts.MinLN,
			Max:       opts.MaxLN,
			Actual:    c.LN,
		}
	}
	if c.R < opts.MinR || c.R > opts.MaxR {
		return &verifier.BoundsError{
			Algorithm: Identifier,
			Param:     "R",
			Min:       opts.MinR,
			Max:       opts.MaxR,
			Actual:    c.R,
		}
	}
	if c.P < opts.MinP || c.P > opts.MaxP {
		return &verifier.BoundsError{
			Algorithm: Identifier,
			Param:     "P",
			Min:       opts.MinP,
			Max:       opts.MaxP,
			Actual:    c.P,
		}
	}

	// Check if r * p is too large, see [scrypt.Key] documentation.
	if c.R*c.P > (1 << 30) {
		return ErrRxPTooLarge
	}

	return nil
}

func (c *checker) verify(pw string) (verifier.Result, error) {
	hash, err := scrypt.Key([]byte(pw), c.salt, 1<<c.LN, c.R, c.P, c.KeyLen)
	if err != nil {
		return verifier.Fail, err
	}
	res := subtle.ConstantTimeCompare(hash, c.hash)

	return verifier.Result(res), nil
}

type Hasher struct {
	p    Params
	opts *ValidationOpts
	rand io.Reader
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	salt, err := salt.New(h.rand, h.p.SaltLen)
	if err != nil {
		return "", fmt.Errorf("scrypt: %w", err)
	}

	hash, err := scrypt.Key([]byte(password), salt, 1<<h.p.LN, h.p.R, h.p.P, h.p.KeyLen)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(Format,
		Identifier, h.p.LN, h.p.R, h.p.P,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func (h *Hasher) Validate(encoded string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	err = c.validate(h.opts)
	if err != nil {
		return verifier.Fail, err
	}
	return verifier.OK, nil
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

func New(p Params, opts *ValidationOpts) *Hasher {
	return &Hasher{
		opts: checkValidationOpts(opts),
		p:    p,
		rand: rand.Reader,
	}
}

type ValidationOpts struct {
	MinLN int // log2 of N, the CPU/memory cost parameter
	MaxLN int // log2 of N, the CPU/memory cost parameter
	MinR  int
	MaxR  int
	MinP  int
	MaxP  int
}

var DefaultValidationOpts = &ValidationOpts{
	MinLN: DefaultMinLN,
	MaxLN: DefaultMaxLN,
	MinR:  DefaultMinR,
	MaxR:  DefaultMaxR,
	MinP:  DefaultMinP,
	MaxP:  DefaultMaxP,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return DefaultValidationOpts
	}
	if opts.MinLN <= 0 {
		opts.MinLN = DefaultValidationOpts.MinLN
	}
	if opts.MaxLN <= 0 {
		opts.MaxLN = DefaultValidationOpts.MaxLN
	}
	if opts.MinR <= 0 {
		opts.MinR = DefaultValidationOpts.MinR
	}
	if opts.MaxR <= 0 {
		opts.MaxR = DefaultValidationOpts.MaxR
	}
	if opts.MinP <= 0 {
		opts.MinP = DefaultValidationOpts.MinP
	}
	if opts.MaxP <= 0 {
		opts.MaxP = DefaultValidationOpts.MaxP
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

// Verify parses encoded and uses its scrypt parameters
// to verify password against its hash.
// Either the result of Fail or OK is returned,
// or an error if parsing fails.
func (v *Verifier) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password)
}
