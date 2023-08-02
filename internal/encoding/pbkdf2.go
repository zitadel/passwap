package encoding

import "encoding/base64"

const encodePbkdf2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"

// Pbkdf2B64 is an alternative base64 encoding used by pbkdf2.
// Bassicaly it's `+` replaced by `.`.
// https://passlib.readthedocs.io/en/stable/lib/passlib.utils.binary.html#passlib.utils.binary.ab64_encode
var Pbkdf2B64 = base64.NewEncoding(encodePbkdf2).WithPadding(base64.NoPadding)
