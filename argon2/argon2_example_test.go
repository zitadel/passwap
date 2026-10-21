package argon2_test

import (
	"fmt"

	"github.com/zitadel/passwap/argon2"
)

func ExampleParseParams() {
	const encoded = "$argon2id$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$DYojYpnUWSMmTtrkVXyaNWVGxLmGe1n8VJBPDdFkbjU"

	// Read the cost parameters without verifying a password,
	// for example to estimate the memory a Verify will need.
	p, err := argon2.ParseParams(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Printf("memory: %d KiB, time: %d, threads: %d, key: %d bytes, salt: %d bytes\n",
		p.Memory, p.Time, p.Threads, p.KeyLen, p.SaltLen)
	// Output: memory: 4096 KiB, time: 3, threads: 1, key: 32 bytes, salt: 16 bytes
}
