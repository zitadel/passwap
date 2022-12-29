package testvalues

import (
	"bytes"
)

const (
	MD5Encoded = `$1$kJ4QkJaQ$3EbD/pJddrq5HW3mpZ4KZ1`
	MD5SaltRaw = "pepper"
	MD5Salt    = "kJ4QkJaQ"
)

var MD5Checksum []byte

func init() {
	MD5Checksum = bytes.Split([]byte(MD5Encoded), []byte("$"))[3]
}
