package testvalues

import (
	"bytes"
)

const (
	MD5Encoded  = `$1$kJ4QkJaQ$3EbD/pJddrq5HW3mpZ4KZ1`
	MD5SaltRaw  = "pepper"
	MD5Salt     = "kJ4QkJaQ"
	MD5PlainHex = `5f4dcc3b5aa765d61d8327deb882cf99`
)

var MD5Checksum []byte

func init() {
	MD5Checksum = bytes.Split([]byte(MD5Encoded), []byte("$"))[3]
}
