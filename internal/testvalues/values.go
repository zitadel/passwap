package testvalues

import (
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
