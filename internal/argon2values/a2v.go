package argon2values

import "encoding/hex"

const (
	Time       = 3
	Memory     = 4096
	Threads    = 1
	Password   = "password"
	Salt       = "randomsaltishard"
	KeyLen     = 32
	SaltLen    = uint32(len(Salt))
	Hex_i      = `60cbe8f0052836d9ca606a9e383aee0a31dd8846e5d6928bd8cb18cbd56053f1`
	Hex_id     = `0d8a236299d45923264edae4557c9a356546c4b9867b59fc54904f0dd1646e35`
	Encoded_i  = `$argon2i$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$YMvo8AUoNtnKYGqeODruCjHdiEbl1pKL2MsYy9VgU/E`
	Encoded_d  = `$argon2d$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$CB0Du96aj3fQVcVSqb0LIA6Z6fpStjzjVkaC3RlpK9A`
	Encoded_id = `$argon2id$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$DYojYpnUWSMmTtrkVXyaNWVGxLmGe1n8VJBPDdFkbjU`
)

var (
	Hash_i  []byte
	Hash_id []byte
)

func init() {
	var err error

	Hash_i, err = hex.DecodeString(Hex_i)
	if err != nil {
		panic(err)
	}

	Hash_id, err = hex.DecodeString(Hex_id)
	if err != nil {
		panic(err)
	}
}
