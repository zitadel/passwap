package testvalues

import "encoding/hex"

// Argon2 values generated with argon2.bash
const (
	Argon2Time      = 3
	Argon2Memory    = 4096
	Argon2Threads   = 1
	Argon2iHex      = `60cbe8f0052836d9ca606a9e383aee0a31dd8846e5d6928bd8cb18cbd56053f1`
	Argon2idHex     = `0d8a236299d45923264edae4557c9a356546c4b9867b59fc54904f0dd1646e35`
	Argon2iEncoded  = `$argon2i$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$YMvo8AUoNtnKYGqeODruCjHdiEbl1pKL2MsYy9VgU/E`
	Argon2dEncoded  = `$argon2d$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$CB0Du96aj3fQVcVSqb0LIA6Z6fpStjzjVkaC3RlpK9A`
	Argon2idEncoded = `$argon2id$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$DYojYpnUWSMmTtrkVXyaNWVGxLmGe1n8VJBPDdFkbjU`
)

var (
	Argon2iHash  []byte
	Argon2idHash []byte
)

func init() {
	var err error

	Argon2iHash, err = hex.DecodeString(Argon2iHex)
	if err != nil {
		panic(err)
	}

	Argon2idHash, err = hex.DecodeString(Argon2idHex)
	if err != nil {
		panic(err)
	}
}
