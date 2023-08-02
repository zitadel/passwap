package testvalues

import (
	"encoding/base64"
	"io"
	"strings"
)

// Commonly used values
const (
	Password = "password"
	Salt     = "randomsaltishard"
	KeyLen   = 32
	SaltLen  = uint32(len(Salt))
)

func SaltReader() io.Reader {
	return strings.NewReader(Salt)
}

func parseBase64HashComponent(encoding *base64.Encoding, encoded string, pos int) []byte {
	nodes := strings.Split(encoded, "$")
	hash, err := encoding.Strict().DecodeString(nodes[pos])
	if err != nil {
		panic(err)
	}
	return hash
}
