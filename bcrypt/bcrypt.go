package bcrypt

import (
	"bytes"
	"errors"

	"github.com/zitadel/passwap/verifier"
	"golang.org/x/crypto/bcrypt"
)

// Identifier and prefix used by Bcrypt
const (
	Identifier = "2"
	Prefix     = "$" + Identifier
)

// Versions of the Bcrypt implementation.
var (
	Versions = [...]byte{'a', 'b', 'y'}
)

const (
	DefaultMinCost = bcrypt.MinCost
	DefaultMaxCost = bcrypt.MaxCost
	DefaultCost    = bcrypt.DefaultCost
)

// hasBcryptVersion checks for the Bcrypt Prefix
// and all of the declared Versions or the
// Prefix used for the first version of Bcrypt.
func hasBcryptVersion(encoded []byte) bool {
	if !bytes.HasPrefix(encoded, []byte(Prefix)) {
		return false
	}

	for _, v := range Versions {
		if v == encoded[2] {
			return true
		}
	}

	return false
}

type checker struct {
	cost int
}

func parse(encoded []byte) (*checker, error) {
	encodedB := []byte(encoded)
	if !hasBcryptVersion(encodedB) {
		return nil, errors.New("not a bcrypt version")
	}
	cost, err := bcrypt.Cost(encodedB)
	if err != nil {
		return nil, err
	}
	return &checker{
		cost: cost,
	}, nil
}

func (c *checker) validate(opts *ValidationOpts) error {
	if c.cost < opts.MinCost || c.cost > opts.MaxCost {
		return &verifier.BoundsError{
			Algorithm: "bcrypt",
			Param:     "cost",
			Min:       opts.MinCost,
			Max:       opts.MaxCost,
			Actual:    c.cost,
		}
	}
	return nil
}

// compareHashAndPassword wraps bcrypt.CompareHashAndPassword
// in order to translate bcrypt package errors to Results and errors
// compatible with this project.
func compareHashAndPassword(encoded, password []byte) (verifier.Result, error) {
	err := bcrypt.CompareHashAndPassword(encoded, password)
	if err == nil {
		return verifier.OK, nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return verifier.Fail, nil
	}

	switch err.(type) {
	case bcrypt.InvalidHashPrefixError:
		return verifier.Skip, err
	case bcrypt.HashVersionTooNewError:
		return verifier.Skip, err
	default:
		return verifier.Fail, err
	}
}

// Hasher hashes and verifies bcrypt passwords.
type Hasher struct {
	opts *ValidationOpts
	cost int
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	encoded, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

func (h *Hasher) Validate(encoded string) (verifier.Result, error) {
	c, err := parse([]byte(encoded))
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	err = c.validate(checkValidationOpts(h.opts))
	if err != nil {
		return verifier.Fail, err
	}
	return verifier.OK, nil
}

// Verify implements passwap.Verifier
func (h *Hasher) Verify(encoded, password string) (verifier.Result, error) {
	encodedB := []byte(encoded)
	c, err := parse(encodedB)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	result, err := compareHashAndPassword(encodedB, []byte(password))
	if err != nil || result != verifier.OK {
		return result, err
	}

	if c.cost != h.cost {
		result = verifier.NeedUpdate
	}

	return result, nil
}

// New will return a Hasher with cost as bcrypt parameter.
func New(cost int, opts *ValidationOpts) *Hasher {
	return &Hasher{
		opts: checkValidationOpts(opts),
		cost: cost,
	}
}

type ValidationOpts struct {
	MinCost int
	MaxCost int
}

var DefaultValidationOpts = ValidationOpts{
	MinCost: DefaultMinCost,
	MaxCost: DefaultMaxCost,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return &DefaultValidationOpts
	}
	if opts.MinCost == 0 {
		opts.MinCost = DefaultMinCost
	}
	if opts.MaxCost == 0 {
		opts.MaxCost = DefaultMaxCost
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
	c, err := parse([]byte(encoded))
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	err = c.validate(v.opts)
	if err != nil {
		return verifier.Fail, err
	}
	return verifier.OK, nil
}

// Verify parses encoded and uses its bcrypt parameters
// to verify password against its hash.
func (v *Verifier) Verify(encoded, password string) (verifier.Result, error) {
	encodedB := []byte(encoded)
	if !hasBcryptVersion(encodedB) {
		return verifier.Skip, nil
	}

	return compareHashAndPassword(encodedB, []byte(password))
}
