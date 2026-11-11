package scrypt_test

import (
	"fmt"

	"github.com/zitadel/passwap/scrypt"
)

func ExampleParseParams() {
	const encoded = "$scrypt$ln=16,r=8,p=1$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ"

	// Read the cost parameters without verifying a password,
	// for example to estimate the memory a Verify will need.
	p, err := scrypt.ParseParams(encoded)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ln: %d, r: %d, p: %d, key: %d bytes, salt: %d bytes\n",
		p.LN, p.R, p.P, p.KeyLen, p.SaltLen)
	// Output: ln: 16, r: 8, p: 1, key: 32 bytes, salt: 16 bytes
}
