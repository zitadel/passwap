package bcrypt

import (
	"bytes"

	"github.com/muhlemmer/passwap/verifier"
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
	MinCost     = bcrypt.MinCost
	MaxCost     = bcrypt.MaxCost
	DefaultCost = bcrypt.DefaultCost
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

// Verify implements passwap.Verifier
func (h *Hasher) Verify(encoded, password string) (verifier.Result, error) {
	encodedB := []byte(encoded)
	if !hasBcryptVersion(encodedB) {
		return verifier.Skip, nil
	}

	cost, err := bcrypt.Cost(encodedB)
	if err != nil {
		return verifier.Skip, err
	}

	result, err := compareHashAndPassword(encodedB, []byte(password))
	if err != nil || result != verifier.OK {
		return result, err
	}

	if cost != h.cost {
		result = verifier.NeedUpdate
	}

	return result, nil
}

// New will return a Hasher with cost as bcrypt parameter.
func New(cost int) *Hasher {
	return &Hasher{
		cost: cost,
	}
}

// Verify parses encoded and uses its bcrypt parameters
// to verify password against its hash.
func Verify(encoded, password string) (verifier.Result, error) {
	encodedB := []byte(encoded)
	if !hasBcryptVersion(encodedB) {
		return verifier.Skip, nil
	}

	return compareHashAndPassword(encodedB, []byte(password))
}

// Verifier for Bcrypt.
var Verifier = verifier.VerifyFunc(Verify)
