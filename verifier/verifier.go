// Package verifier provides types and interfaces
// for building verifiers, used by passwap.
package verifier

// Result of a password verification.
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
)

// Verifier is capable of verifying passwords against an existing
// encoded hash string. Implementations are typically responsible
// for parsing such string and the format in use.
// Within the passwap project we aim to only use dollar sign `$`` notation.
type Verifier interface {
	// Verify the hashed password against the encoded hash.
	Verify(encoded, password string) (Result, error)

	// ID returns the string identifier for this verifier.
	ID() string
}

type funcVerifier struct {
	id string
	f  func(encoded, password string) (Result, error)
}

func (v *funcVerifier) Verify(encoded, password string) (Result, error) {
	return v.f(encoded, password)
}

func (v *funcVerifier) ID() string { return v.id }

func NewFunc(id string, f func(encoded, password string) (Result, error)) Verifier {
	return &funcVerifier{id, f}
}

// IDMap of string identifiers that match against a Verifier.
// Passwap uses regex to extract the identifier from the encoded string,
// and asserts the Verifier using this map.
type IDMap map[string]Verifier

// NewIDMap builds an IDMap from passed Verifiers.
func NewIDMap(verifiers []Verifier) IDMap {
	m := make(IDMap, len(verifiers))

	for _, v := range verifiers {
		m[v.ID()] = v
	}

	return m
}
