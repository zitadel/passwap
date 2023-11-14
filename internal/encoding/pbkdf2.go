package encoding

import (
	"encoding/base64"
	"strings"
)

const encodePbkdf2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

// Pbkdf2B64 is an alternative base64 encoding used by pbkdf2.
// Basically it's `+` replaced by `.`.
// https://passlib.readthedocs.io/en/stable/lib/passlib.utils.binary.html#passlib.utils.binary.ab64_encode
var Pbkdf2B64 = base64.NewEncoding(encodePbkdf2).WithPadding(base64.NoPadding)

// AutoDecodePbkdf2 decodes a base64 encoded string in the
// Pbkdf alternative format or [base64.RawStdEncoding].
// Any padding is removed from the encoded string
func AutoDecodePbkdf2(encoded string) ([]byte, error) {
	encoding := Pbkdf2B64
	if strings.ContainsRune(encoded, '+') {
		encoding = base64.RawStdEncoding
	}
	return encoding.DecodeString(strings.TrimRight(encoded, "="))
}
