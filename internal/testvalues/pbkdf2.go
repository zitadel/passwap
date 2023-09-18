package testvalues

import (
	"github.com/zitadel/passwap/internal/encoding"
)

// pbkdf2 test values generated with passlib_pbkdf2.py
const (
	Pbkdf2Rounds        = 12
	Pbkdf2Sha1KeyLen    = 20
	Pbkdf2Sha256KeyLen  = 32
	Pbkdf2Sha512KeyLen  = 64
	Pbkdf2Sha1Encoded   = `$pbkdf2$12$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`
	Pbkdf2Sha256Encoded = `$pbkdf2-sha256$12$cmFuZG9tc2FsdGlzaGFyZA$OFvEcLOIPFd/oq8egf10i.qJLI7A8nDjPLnolCWarQY`
	Pbkdf2Sha512Encoded = `$pbkdf2-sha512$12$cmFuZG9tc2FsdGlzaGFyZA$e297piXvkpYxoYQAWD9zn1aKXCo3XmR91Xn9/WEGsHXU/7xaQzCV9upu4T5Jntq6AiZ6YX0diXnY7Ju5TEfUMA`
)

// manually created to test decoding of standard encoding with padding
const (
	Pbkdf2Sha256StdEncoded        = `$pbkdf2-sha256$12$cmFuZG9tc2FsdGlzaGFyZA$OFvEcLOIPFd/oq8egf10i+qJLI7A8nDjPLnolCWarQY`
	Pbkdf2Sha256StdEncodedPadding = `$pbkdf2-sha256$12$cmFuZG9tc2FsdGlzaGFyZA==$OFvEcLOIPFd/oq8egf10i+qJLI7A8nDjPLnolCWarQY=`
)

var (
	Pbkdf2Sha1Hash   = parseBase64HashComponent(encoding.Pbkdf2B64, Pbkdf2Sha1Encoded, 4)
	Pbkdf2Sha256Hash = parseBase64HashComponent(encoding.Pbkdf2B64, Pbkdf2Sha256Encoded, 4)
	Pbkdf2Sha512Hash = parseBase64HashComponent(encoding.Pbkdf2B64, Pbkdf2Sha512Encoded, 4)
)
