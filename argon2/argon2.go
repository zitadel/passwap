// Package argon2 provides salt generation, hashing
// and verification for x/crypto/argon2.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
)

// Argon2 identifiers
const (
	Identifier_i  = "argon2i"
	Identifier_d  = "argon2d" // Unsupported
	Identifier_id = "argon2id"
	Prefix        = "$argon2"
)

// Validation defaults
const (
	DefaultMinTime    = 1
	DefaultMaxTime    = 10
	DefaultMinMemory  = 8 * 1024
	DefaultMaxMemory  = 512 * 1024
	DefaultMinThreads = 1
	DefaultMaxThreads = 16
)

// Params are used for all argon2 modes.
type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
	SaltLen uint32

	id string
}

var (
	RecommendedIParams = Params{
		Time:    3,
		Memory:  32 * 1024,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
	RecommendedIDParams = Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 4,
		KeyLen:  32,
		SaltLen: 16,
	}
)

// Format of the PHC string format for argon2.
// See https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md.
const Format = "$%s$v=%d$m=%d,t=%d,p=%d$%s$%s"

// scanning needs a space separated string, instead of dollar signs.
var scanFormat = strings.ReplaceAll(Format, "$", " ")

var (
	ErrArgon2d       = errors.New("argon2d is not supported")
	ErrArgon2Version = fmt.Errorf("argon2: version required %x", argon2.Version)
)

type hashFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

type checker struct {
	Params

	hash []byte
	salt []byte

	hf hashFunc
}

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix) {
		return nil, nil
	}

	var (
		version int
		salt    string
		hash    string
		c       checker
	)

	// scanning needs a space separated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")

	_, err := fmt.Sscanf(encoded, scanFormat, &c.id, &version, &c.Memory, &c.Time, &c.Threads, &salt, &hash)
	if err != nil {
		return nil, fmt.Errorf("argon2 parse: %w", err)
	}

	switch c.id {
	case Identifier_i:
		c.hf = argon2.Key
	case Identifier_id:
		c.hf = argon2.IDKey
	case Identifier_d:
		return nil, ErrArgon2d
	default:
		return nil, fmt.Errorf("argon2: unknown identifier %s", c.id)
	}

	if version != argon2.Version {
		return nil, fmt.Errorf("%w, %x received", ErrArgon2Version, version)
	}

	c.salt, err = base64.RawStdEncoding.Strict().DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("argon2 parse salt: %w", err)
	}

	c.hash, err = base64.RawStdEncoding.Strict().DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("argon2 parse hash: %w", err)
	}

	c.KeyLen = uint32(len(c.hash))
	c.SaltLen = uint32(len(c.salt))

	return &c, nil
}

func (c *checker) validate(opts *ValidationOpts) error {
	if c.Time < opts.MinTime || c.Time > opts.MaxTime {
		return &verifier.BoundsError{
			Algorithm: "argon2",
			Param:     "time",
			Min:       int(opts.MinTime),
			Max:       int(opts.MaxTime),
			Actual:    int(c.Time),
		}
	}
	if c.Memory < opts.MinMemory || c.Memory > opts.MaxMemory {
		return &verifier.BoundsError{
			Algorithm: "argon2",
			Param:     "memory",
			Min:       int(opts.MinMemory),
			Max:       int(opts.MaxMemory),
			Actual:    int(c.Memory),
		}
	}
	if c.Threads < opts.MinThreads || c.Threads > opts.MaxThreads {
		return &verifier.BoundsError{
			Algorithm: "argon2",
			Param:     "threads",
			Min:       int(opts.MinThreads),
			Max:       int(opts.MaxThreads),
			Actual:    int(c.Threads),
		}
	}
	return nil
}

func (c *checker) verify(pw string) verifier.Result {
	hash := c.hf([]byte(pw), c.salt, c.Time, c.Memory, c.Threads, c.KeyLen)
	res := subtle.ConstantTimeCompare(hash, c.hash)

	return verifier.Result(res)
}

type Hasher struct {
	opts *ValidationOpts
	p    Params
	rand io.Reader
	hf   hashFunc
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	salt, err := salt.New(h.rand, h.p.SaltLen)
	if err != nil {
		return "", fmt.Errorf("argon2: %w", err)
	}

	hash := h.hf([]byte(password), salt, h.p.Time, h.p.Memory, h.p.Threads, h.p.KeyLen)

	return fmt.Sprintf(Format,
		h.p.id, argon2.Version, h.p.Memory, h.p.Time, h.p.Threads,
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

	res := c.verify(password)
	if res == 0 {
		return verifier.Fail, nil
	}

	if h.p != c.Params {
		return verifier.NeedUpdate, nil
	}

	return verifier.OK, nil
}

func NewArgon2i(p Params, opts *ValidationOpts) *Hasher {
	p.id = Identifier_i

	return &Hasher{
		opts: checkValidationOpts(opts),
		p:    p,
		rand: rand.Reader,
		hf:   argon2.Key,
	}
}

func NewArgon2id(p Params, opts *ValidationOpts) *Hasher {
	p.id = Identifier_id

	return &Hasher{
		opts: checkValidationOpts(opts),
		p:    p,
		rand: rand.Reader,
		hf:   argon2.IDKey,
	}
}

type ValidationOpts struct {
	MinTime    uint32
	MaxTime    uint32
	MinMemory  uint32
	MaxMemory  uint32
	MinThreads uint8
	MaxThreads uint8
}

var DefaultValidationOpts = &ValidationOpts{
	MinTime:    DefaultMinTime,
	MaxTime:    DefaultMaxTime,
	MinMemory:  DefaultMinMemory,
	MaxMemory:  DefaultMaxMemory,
	MinThreads: DefaultMinThreads,
	MaxThreads: DefaultMaxThreads,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return DefaultValidationOpts
	}
	if opts.MinTime == 0 {
		opts.MinTime = DefaultMinTime
	}
	if opts.MaxTime == 0 {
		opts.MaxTime = DefaultMaxTime
	}
	if opts.MinMemory == 0 {
		opts.MinMemory = DefaultMinMemory
	}
	if opts.MaxMemory == 0 {
		opts.MaxMemory = DefaultMaxMemory
	}
	if opts.MinThreads == 0 {
		opts.MinThreads = DefaultMinThreads
	}
	if opts.MaxThreads == 0 {
		opts.MaxThreads = DefaultMaxThreads
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

// Verify parses encoded and uses its argon2 parameters
// to verify password against its hash.
// Either the result of Fail or OK is returned,
// or an error if parsing fails.
//
// Note that argon2d is not supported by upstream
// and therefore not by this package.
// ErrArgon2d is returned when an argon2d identifier is in
// the encoded string.
func (v *Verifier) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password), nil
}
