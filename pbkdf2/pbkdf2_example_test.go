package pbkdf2_test

import (
	"fmt"

	"github.com/zitadel/passwap/pbkdf2"
)

func ExampleParseParams() {
	const encoded = "$pbkdf2-sha256$12$cmFuZG9tc2FsdGlzaGFyZA$OFvEcLOIPFd/oq8egf10i.qJLI7A8nDjPLnolCWarQY"

	// Read the cost parameters without verifying a password,
	// for example to estimate the work a Verify will need.
	p, err := pbkdf2.ParseParams(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Printf("rounds: %d, key: %d bytes, salt: %d bytes\n",
		p.Rounds, p.KeyLen, p.SaltLen)
	// Output: rounds: 12, key: 32 bytes, salt: 16 bytes
}
