// Package sha2 provides hashing and verification of
// SHA-256 and SHA-512 encoded passwords with salt based on crypt(3).
// [The algorithm](https://www.akkadia.org/drepper/SHA-crypt.txt)
// builds hashes through multiple digest iterations
// with shuffles of password and salt.
package sha2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"github.com/zitadel/passwap/internal/encoding"
	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
)

const (
	Sha256Identifier = "$5$"
	Sha512Identifier = "$6$"
	SaltLenMin       = 1
	SaltLenMax       = 16
	RoundsMin        = 1000
	RoundsMax        = 999999999
	RoundsDefault    = 5000
)

func createHash(is512 bool, password, salt []byte, rounds int) []byte {
	if len(salt) > 16 {
		salt = salt[0:16]
	}

	var hash hash.Hash
	if is512 {
		hash = sha512.New()
	} else {
		hash = sha256.New()
	}
	digest := createDigest(hash, password, salt, calcRounds(rounds))

	return []byte(createOutputString(is512, digest, salt, calcRounds(rounds)))
}

func calcRounds(rounds int) int {
	if rounds < RoundsMin {
		return RoundsMin
	}
	if rounds > RoundsMax {
		return RoundsMax
	}
	return rounds
}

// Follows the algorithm steps 1 - 21 outlined in https://www.akkadia.org/drepper/SHA-crypt.txt
func createDigest(hash hash.Hash, password, salt []byte, rounds int) []byte {
	// steps 4 - 6 (we start with digest B because it is more convenient)
	hash.Write(password)
	hash.Write(salt)
	hash.Write(password)
	digestB := hash.Sum(nil)

	// steps 1 - 3
	hash.Reset()
	hash.Write(password)
	hash.Write(salt)

	// step 9 - 10
	passwordLength := len(password)
	hash.Write(repeatBytesToSize(digestB, passwordLength))

	// step 11
	for i := passwordLength; i != 0; i >>= 1 {
		if i&1 == 1 {
			hash.Write(digestB)
		} else {
			hash.Write(password)
		}
	}

	// step 12
	digestA := hash.Sum(nil)

	// step 13 - 15
	hash.Reset()
	for i := 0; i < len(password); i++ {
		hash.Write(password)
	}
	digestDP := hash.Sum(nil)

	// step 16
	sequenceP := repeatBytesToSize(digestDP, passwordLength)

	// step 17 - 19
	hash.Reset()
	for i := 0; i < (16 + int(digestA[0])); i++ {
		hash.Write(salt)
	}
	digestDS := hash.Sum(nil)

	// step 20
	sequenceS := repeatBytesToSize(digestDS, len(salt))

	// step 21
	digestC := digestA

	for i := 0; i < rounds; i++ {
		hash.Reset()
		if i%2 != 0 { // step 21.b
			hash.Write(sequenceP)
		} else { // step 21.c
			hash.Write(digestC)
		}
		if i%3 != 0 { // step 21.d
			hash.Write(sequenceS)
		}
		if i%7 != 0 { // step 21.e
			hash.Write(sequenceP)
		}
		if i%2 != 0 { // step 21.f
			hash.Write(digestC)
		} else { // step 21.g
			hash.Write(sequenceP)
		}
		digestC = hash.Sum(nil)
	}
	return digestC
}

func createOutputString(is512 bool, digest, salt []byte, rounds int) string {
	var builder strings.Builder

	builder.WriteString("$")
	if is512 {
		builder.WriteString("6")
	} else {
		builder.WriteString("5")
	}
	builder.WriteString("$")
	builder.WriteString(fmt.Sprintf("rounds=%d", rounds))
	builder.WriteString("$")
	builder.WriteString(string(salt))
	builder.WriteString("$")

	var transposed []byte
	if is512 {
		transposed = transpose(digest, transposeMap512)
	} else {
		transposed = transpose(digest, transposeMap256)
	}
	builder.WriteString(string(encoding.EncodeCrypt3(transposed)))
	return builder.String()
}

func transpose(input []byte, transposeMap []int) []byte {
	result := make([]byte, len(transposeMap))
	for i, off := range transposeMap {
		if off < len(input) {
			result[i] = input[off]
		}
	}
	return result
}

func repeatBytesToSize(input []byte, size int) []byte {
	repeats := 1 + (size-1)/len(input)
	return bytes.Repeat(input, repeats)[:size]
}

var (
	transposeMap256 = []int{20, 10, 0, 11, 1, 21, 2, 22, 12, 23, 13, 3, 14, 4, 24, 5, 25, 15, 26, 16, 6, 17, 7, 27, 8, 28, 18, 29, 19, 9, 30, 31}

	transposeMap512 = []int{
		42, 21, 0, 1, 43, 22, 23, 2, 44, 45, 24, 3, 4, 46, 25, 26,
		5, 47, 48, 27, 6, 7, 49, 28, 29, 8, 50, 51, 30, 9, 10, 52,
		31, 32, 11, 53, 54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
		16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40, 41, 20, 62, 63,
	}
)

type checker struct {
	use512 bool
	rounds int
	hash   []byte
	salt   []byte
}

func parse(hash string) (*checker, error) {
	parts := strings.Split(hash, "$")
	partsLen := len(parts) - 1
	if partsLen < 3 || partsLen > 4 {
		return nil, fmt.Errorf("invalid format")
	}

	if parts[1] != "5" && parts[1] != "6" {
		return nil, fmt.Errorf("invalid identifier")
	}

	var checker checker

	checker.use512 = parts[1] == "6"

	i := 2
	if strings.HasPrefix(parts[2], "rounds=") {
		rounds, err := strconv.Atoi(strings.TrimPrefix(parts[2], "rounds="))
		if err != nil {
			return nil, fmt.Errorf("invalid rounds value")
		}
		checker.rounds = rounds
		i++
	} else {
		checker.rounds = RoundsDefault
	}

	checker.salt = []byte(parts[i])
	checker.hash = []byte(hash)
	return &checker, nil
}

func (c *checker) validate(opts *ValidationOpts) error {
	if c.use512 {
		if c.rounds < opts.MinSha512Rounds || c.rounds > opts.MaxSha512Rounds {
			return &verifier.BoundsError{
				Algorithm: "SHA-512",
				Param:     "rounds",
				Min:       opts.MinSha512Rounds,
				Max:       opts.MaxSha512Rounds,
				Actual:    c.rounds,
			}
		}
	} else {
		if c.rounds < opts.MinSha256Rounds || c.rounds > opts.MaxSha256Rounds {
			return &verifier.BoundsError{
				Algorithm: "SHA-256",
				Param:     "rounds",
				Min:       opts.MinSha256Rounds,
				Max:       opts.MaxSha256Rounds,
				Actual:    c.rounds,
			}
		}
	}
	return nil
}

func (c *checker) verify(password string) verifier.Result {
	passwordHash := createHash(c.use512, []byte(password), c.salt, c.rounds)
	res := subtle.ConstantTimeCompare(passwordHash, c.hash)

	return verifier.Result(res)
}

// Hasher hashes and verifies crypt(3) style SHA256 and SHA512 passwords.
type Hasher struct {
	opts   *ValidationOpts
	use512 bool
	rounds int
	rand   io.Reader
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	salt, err := salt.New(h.rand, 16)
	if err != nil {
		return "", fmt.Errorf("sha2: %w", err)
	}

	encSalt := encoding.EncodeCrypt3(salt)
	encoded := createHash(h.use512, []byte(password), encSalt, h.rounds)

	return string(encoded), nil
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
		return verifier.Fail, err
	}

	if h.rounds != c.rounds {
		return verifier.NeedUpdate, nil
	}

	return verifier.OK, nil
}

func New256(rounds int, opts *ValidationOpts) *Hasher {
	return &Hasher{
		opts:   checkValidationOpts(opts),
		use512: false,
		rounds: rounds,
		rand:   rand.Reader,
	}
}
func New512(rounds int, opts *ValidationOpts) *Hasher {
	return &Hasher{
		opts:   checkValidationOpts(opts),
		use512: true,
		rounds: rounds,
		rand:   rand.Reader,
	}
}

type ValidationOpts struct {
	MinSha256Rounds int
	MaxSha256Rounds int
	MinSha512Rounds int
	MaxSha512Rounds int
}

var DefaultValidationOpts = &ValidationOpts{
	MinSha256Rounds: RoundsMin,
	MaxSha256Rounds: RoundsMax,
	MinSha512Rounds: RoundsMin,
	MaxSha512Rounds: RoundsMax,
}

func checkValidationOpts(opts *ValidationOpts) *ValidationOpts {
	if opts == nil {
		return DefaultValidationOpts
	}
	if opts.MinSha256Rounds <= 0 {
		opts.MinSha256Rounds = RoundsMin
	}
	if opts.MaxSha256Rounds <= 0 {
		opts.MaxSha256Rounds = RoundsMax
	}
	if opts.MinSha512Rounds <= 0 {
		opts.MinSha512Rounds = RoundsMin
	}
	if opts.MaxSha512Rounds <= 0 {
		opts.MaxSha512Rounds = RoundsMax
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

// Verify parses encoded and uses its parameters
// to verify password against its hash.
func (v *Verifier) Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}
	return c.verify(password), nil
}
