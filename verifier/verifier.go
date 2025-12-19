// Package verifier provides types and interfaces
// for building verifiers, used by passwap.
package verifier

import (
	"fmt"
)

// Result of a password verification.
//
//go:generate stringer -type=Result
type Result int

const (
	// Fail is returned when the passwords don't match
	// or an error was encountered in the process.
	Fail Result = iota

	// OK is returned when the passwords match
	// and no further action is required.
	OK

	// NeedUpdate is returned when the passwords match
	// however the passed data is outdated and
	// needs to be updated in the database to the latest version.
	// The latest version is obtainable by calling Hasher.Hash(password)
	NeedUpdate

	// Skip is returned when a verifier is unable
	// to parse the encoded string.
	Skip
)

// Verifier is capable of verifying passwords against an existing
// encoded hash string. Implementations are typically responsible
// for parsing such string and the format in use.
// Within the passwap project we aim to only use dollar sign `$` notation.
//
// A Verifier should return the [Skip] result when it is unable to parse the
// encoded string. It may return an error if one was encountered during parsing,
// but should try to prevent this by early checking if the encoded string
// is indeed in the format expected.
type Verifier interface {
	// Validate checks if the encoded string can be handled by this Verifier.
	// The verifier may check if the parameters used in the encoded string
	// are within acceptable bounds.
	// If the parameters are out of bounds, it returns [Fail] and
	// an error of type [*verifier.BoundsError].
	Validate(encoded string) (Result, error)
	// Verify the hashed password against the encoded hash.
	Verify(encoded, password string) (Result, error)
}

// BoundsError is returned when a parameter is out of the configured bounds.
type BoundsError struct {
	Algorithm string
	Param     string
	Min       int
	Max       int
	Actual    int
}

func (e *BoundsError) Error() string {
	return fmt.Sprintf("verifier: %s parameter %s out of bounds: expected %d - %d, got %d",
		e.Algorithm, e.Param, e.Min, e.Max, e.Actual)
}
