// Package pbkdf2 provides salt generation, hashing and verification for x/crypto/pbkdf2.
// RFC 8018 / PKCS #5 v2.1 specification allows use of all five FIPS Approved Hash Functions
// SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 for HMAC.
// All of the above are supported by the Verifier or through specific
// constuctor functions of the Hasher.
package pbkdf2

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"strings"

	"github.com/zitadel/passwap/internal/encoding"
	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
	"golang.org/x/crypto/pbkdf2"
)

// Identifiers and prefixes that describe a
// pbkdf2 encoded hash string.
const (
	IdentifierSHA1   = "pbkdf2"
	IdentifierSHA224 = IdentifierSHA1 + "-sha224"
	IdentifierSHA256 = IdentifierSHA1 + "-sha256"
	IdentifierSHA384 = IdentifierSHA1 + "-sha384"
	IdentifierSHA512 = IdentifierSHA1 + "-sha512"

	Prefix = "$" + IdentifierSHA1
)

func hashFuncForIdentifier(id string) func() hash.Hash {
	switch id {
	case IdentifierSHA1:
		return sha1.New
	case IdentifierSHA224:
		return sha256.New224
	case IdentifierSHA256:
		return sha256.New
	case IdentifierSHA384:
		return sha512.New384
	case IdentifierSHA512:
		return sha512.New
	default:
		return nil
	}
}

// Params are used for all hasher modes.
type Params struct {
	Rounds  uint32
	KeyLen  uint32
	SaltLen uint32

	id string
}

// Recommended parameters are based on passlib's defaults.
var (
	RecommendedSHA1Params = Params{
		Rounds:  290000,
		KeyLen:  sha1.Size,
		SaltLen: 16,
	}
	RecommendedSHA224Params = Params{
		Rounds:  290000,
		KeyLen:  sha256.Size224,
		SaltLen: 16,
	}
	RecommendedSHA256Params = Params{
		Rounds:  290000,
		KeyLen:  sha256.Size,
		SaltLen: 16,
	}
	RecommendedSHA384Params = Params{
		Rounds:  290000,
		KeyLen:  sha512.Size384,
		SaltLen: 16,
	}
	RecommendedSHA512Params = Params{
		Rounds:  290000,
		KeyLen:  sha512.Size,
		SaltLen: 16,
	}
)

// Format of the Modular Crypt Format, as used by passlib.
// See https://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html#format-algorithm
const Format = "$%s$%d$%s$%s"

var scanFormat = strings.ReplaceAll(Format, "$", " ")

type checker struct {
	Params

	hash []byte
	salt []byte

	hf func() hash.Hash
}

func parse(encoded string) (*checker, error) {
	if !strings.HasPrefix(encoded, Prefix) {
		return nil, nil
	}

	var (
		salt string
		hash string
		c    checker
	)

	// scanning needs a space separated string, instead of dollar signs.
	encoded = strings.ReplaceAll(encoded, "$", " ")

	_, err := fmt.Sscanf(encoded, scanFormat, &c.id, &c.Rounds, &salt, &hash)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 parse: %w", err)
	}

	if c.hf = hashFuncForIdentifier(c.id); c.hf == nil {
		return nil, fmt.Errorf("pbkdf2: unknown hash identifier %s", c.id)
	}

	c.salt, err = encoding.Pbkdf2B64.Strict().DecodeString(salt)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 parse salt: %w", err)
	}

	c.hash, err = encoding.Pbkdf2B64.Strict().DecodeString(hash)
	if err != nil {
		return nil, fmt.Errorf("pbkdf2 parse hash: %w", err)
	}

	c.KeyLen = uint32(len(c.hash))
	c.SaltLen = uint32(len(c.salt))

	return &c, nil
}

func (c *checker) verify(pw string) verifier.Result {
	hash := pbkdf2.Key([]byte(pw), c.salt, int(c.Rounds), int(c.KeyLen), c.hf)
	res := subtle.ConstantTimeCompare(hash, c.hash)

	return verifier.Result(res)
}

type Hasher struct {
	p    Params
	rand io.Reader
	hf   func() hash.Hash
}

// Hash implements passwap.Hasher.
func (h *Hasher) Hash(password string) (string, error) {
	salt, err := salt.New(h.rand, h.p.SaltLen)
	if err != nil {
		return "", fmt.Errorf("pbkdf2: %w", err)
	}

	hash := pbkdf2.Key([]byte(password), salt, int(h.p.Rounds), int(h.p.KeyLen), h.hf)

	return fmt.Sprintf(Format,
		h.p.id, h.p.Rounds,
		encoding.Pbkdf2B64.EncodeToString(salt),
		encoding.Pbkdf2B64.EncodeToString(hash),
	), nil
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

func newHasher(p Params, id string) *Hasher {
	p.id = id
	return &Hasher{
		p:    p,
		rand: rand.Reader,
		hf:   hashFuncForIdentifier(id),
	}
}

// NewSHA1 returns a pbkdf2 SHA1 Hasher.
func NewSHA1(p Params) *Hasher {
	return newHasher(p, IdentifierSHA1)
}

// NewSHA224 returns a pbkdf2 SHA224 Hasher.
func NewSHA224(p Params) *Hasher {
	return newHasher(p, IdentifierSHA224)
}

// NewSHA256 returns a pbkdf2 SHA256 Hasher.
func NewSHA256(p Params) *Hasher {
	return newHasher(p, IdentifierSHA256)
}

// NewSHA384 returns a pbkdf2 SHA384 Hasher.
func NewSHA384(p Params) *Hasher {
	return newHasher(p, IdentifierSHA384)
}

// NewSHA512 returns a pbkdf2 SHA512 Hasher.
func NewSHA512(p Params) *Hasher {
	return newHasher(p, IdentifierSHA512)
}

// Verify parses encoded and uses its pbkdf2 parameters
// to verify password against its hash.
// The HMAC message authentication scheme is taken from the encoded string.
// Currently SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 are suppored.
func Verify(encoded, password string) (verifier.Result, error) {
	c, err := parse(encoded)
	if err != nil || c == nil {
		return verifier.Skip, err
	}

	return c.verify(password), nil
}

var Verifier = verifier.VerifyFunc(Verify)
