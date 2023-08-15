/*
Package passwap provides a unified implementation between
different password hashing algorithms in the Go ecosystem.
It allows for easy swapping between algorithms,
using the same API for all of them.

Passwords hashed with passwap, using a certain algorithm
and parameters can be stored in a database.
If at a later moment paramers or even the algorithm is changed,
passwap is still able to verify the "outdated" hashes and
automatically return an updated hash when applicable.
Only when an updated hash is returned, the record in the database
needs to be updated.
*/
package passwap

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zitadel/passwap/verifier"
)

var (
	ErrPasswordMismatch = errors.New("passwap: password does not match hash")
	ErrPasswordNoChange = errors.New("passwap: new password same as old password")
	ErrNoVerifier       = errors.New("passwap: no verifier found for encoded string")
)

// Hasher is capable of creating new hashes of passwords,
// and verify passwords against existing hashes created by itself.
type Hasher interface {
	verifier.Verifier
	Hash(password string) (encoded string, err error)
}

// Swapper is capable of creating new hashes of passwords and
// verify passwords against existing hashes for which it has
// verifiers configured.
// Swapper also updates hashes that are not created by
// the main hasher or use outdated cost parameters.
type Swapper struct {
	h         Hasher
	verifiers []verifier.Verifier
}

// NewSwapper with Hasher used for creating new hashes and
// primary verifier. Suplemental verifiers can be provided
// and will be used as fallback.
func NewSwapper(h Hasher, verifiers ...verifier.Verifier) *Swapper {
	allV := make([]verifier.Verifier, 1, len(verifiers)+1)
	allV[0] = h
	allV = append(allV, verifiers...)

	s := &Swapper{
		h:         h,
		verifiers: allV,
	}

	return s
}

// SkipErrors is only returned when multiple
// Verifiers matched an encoding string,
// but encountered an error decoding it.
type SkipErrors []error

func (e SkipErrors) Error() string {
	strs := make([]string, len(e))
	for i := 0; i < len(e); i++ {
		strs[i] = e[i].Error()
	}

	return fmt.Sprintf("passwap multiple parse errors: %s", strings.Join(strs, "; "))
}

// Verify a password against an existing encoded hash,
// using the configured Hasher or one of the Verifiers.
//
// ErrNoVerifier is returned if no matching Verifier is found
// for the encoded string. ErrPasswordMismatch
// when the password hash doesn't match the encoded hash.
// When multiple Verifiers match and encounter an error during
// decoding, a SkipErrors is returned containing all those errors
// is returned.
//
// If the used Verifier is different from the the current
// Hasher or the cost parameters differ, an updated encoded hash
// string is returned for the same (valid) password.
// In all other cases updated remains empty.
// When updated is not empty, it must be stored untill next use.
func (s *Swapper) Verify(encoded, password string) (updated string, err error) {
	return s.verifyAndUpdate(encoded, password, password)
}

// VerifyAndUpdate operates like [Verify], only it always returns a new encoded
// hash of newPassword, if oldPassword passes verification.
// An error is returned of newPassword equals oldPassword.
func (s *Swapper) VerifyAndUpdate(encoded, oldPassword, newPassword string) (updated string, err error) {
	if oldPassword == newPassword {
		return "", ErrPasswordNoChange
	}
	return s.verifyAndUpdate(encoded, oldPassword, newPassword)
}

// verifyAndUpdate operates like documented for [Verify].
// When oldPassword and newPassword are not equal, an update is
// always triggered.
func (s *Swapper) verifyAndUpdate(encoded, oldPassword, newPassword string) (updated string, err error) {
	var errs SkipErrors

	for i, v := range s.verifiers {
		result, err := v.Verify(encoded, oldPassword)

		switch result {
		case verifier.Fail:
			if err != nil {
				return "", fmt.Errorf("passwap: %w", err)
			}
			return "", ErrPasswordMismatch

		case verifier.OK:
			if i == 0 && oldPassword == newPassword {
				return "", nil
			}

			// the first Verifier is the Hasher.
			// Any other Verifier should trigger an update.
			return s.Hash(newPassword)

		case verifier.NeedUpdate:
			return s.Hash(newPassword)

		case verifier.Skip:
			if err != nil {
				errs = append(errs, err)
			}
			continue

		default:
			return "", fmt.Errorf("passwap: (BUG) verifier %d returned invalid result N %d", i, result)
		}
	}

	switch len(errs) {
	case 0:
		return "", ErrNoVerifier

	case 1:
		return "", fmt.Errorf("passwap: %w", errs[0])

	default:
		return "", errs
	}
}

// Hash returns a new encoded password hash using the
// configured Hasher.
func (s *Swapper) Hash(password string) (encoded string, err error) {
	return s.h.Hash(password)
}
