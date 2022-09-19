/*
Package passwap provides a unified implementation between
different password hashing algorithms.
It allows for easy swapping between algorithms,
using the same API for all of them.

Passwords hashed with passwap, using a certain algorithm
and parameters can be stored in a database.
If at a later moment paramers or even the algorithm is changed,
passwap is still able to verify the "outdated" hashes and
automatically return an updated hash when applicable.
Only when an updated hash is returned, the record in the database
needs to be updated.

Resulting password hashes are encoded using dollar sign ($)
notation. It's origin lies in Glibc, but there is no clear
standard on the matter For passwap it is choosen to follow
suit with python's passlib identifiers to be (hopefully)
as portable as possible. Suplemental information can be found:

Glibc: https://man.archlinux.org/man/crypt.5;

Passlib "Modular Crypt Format": https://passlib.readthedocs.io/en/stable/modular_crypt_format.html;

Password Hashing Competition string format: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md;
*/
package passwap

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/muhlemmer/passwap/verifier"
)

var (
	ErrPasswordMismatch = errors.New("passwap: password does not match hash")
	ErrNoIdentifier     = errors.New("passwap: can't parse identifier from encoded string")
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
	id        string
	h         Hasher
	verifiers verifier.IDMap
}

// NewSwapper with Hasher used for creating new hashes and
// primary verifier. Suplemental verifiers can be provided
// and will be used when a hash's identifier does not match
// the Hasher's ID().
func NewSwapper(h Hasher, verifiers ...verifier.Verifier) *Swapper {
	s := &Swapper{
		id:        h.ID(),
		h:         h,
		verifiers: verifier.NewIDMap(verifiers),
	}

	return s
}

var idRe = regexp.MustCompile(`^\$(.*?)\$`)

func (s *Swapper) assertVerifier(encoded string) (v verifier.Verifier, needUpdate bool, err error) {
	matches := idRe.FindStringSubmatch(encoded)
	if len(matches) < 2 || matches[1] == "" {
		return nil, false, ErrNoIdentifier
	}
	id := matches[1]

	if id == s.id {
		return s.h, false, nil
	}

	if v, ok := s.verifiers[id]; ok {
		return v, true, nil
	}

	return nil, false, fmt.Errorf("passwap: unknown verifier %s", id)
}

// Verify a password against an existing encoded hash,
// using the configured Hasher or one of the Verifiers.
//
// An error is returned if no matching Verifier is found,
// the encoded string is malformed or ErrPasswordMismatch
// when the password hash doesn't match the encoded hash.
//
// If the used Verifier is different from the the current
// Hasher or the cost parameters differ, an updated encoded hash
// string is returned for the same (valid) password.
// In all other cases updated remains empty.
// When updated is not empty, it must be stored untill next use.
func (s *Swapper) Verify(encoded, password string) (updated string, err error) {
	v, needUpdate, err := s.assertVerifier(encoded)
	if err != nil {
		return "", err
	}

	result, err := v.Verify(encoded, password)
	if err != nil {
		return "", fmt.Errorf("passwap: %w", err)
	}

	switch result {
	case verifier.Fail:
		return "", ErrPasswordMismatch

	case verifier.OK:
		break

	case verifier.NeedUpdate:
		needUpdate = true

	default:
		return "", fmt.Errorf("passwap: (BUG) verifier %s returned invalid result N %d", v.ID(), result)
	}

	if needUpdate {
		return s.Hash(password)
	}
	return "", nil
}

// Hash returns a new encoded password hash using the
// configured Hasher.
func (s *Swapper) Hash(password string) (encoded string, err error) {
	return s.h.Hash(password)
}
