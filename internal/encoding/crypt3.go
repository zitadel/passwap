package encoding

const crypt3Encoding = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// crypt(3) uses a slightly different Base64 scheme. Also called hash64 in PassLib
func EncodeCrypt3(raw []byte) []byte {
	dest := make([]byte, 0, (len(raw)*8+6-1)/6)

	v := uint(0)
	bits := uint(0)

	for _, b := range raw {
		v |= (uint(b) << bits)

		for bits = bits + 8; bits > 6; bits -= 6 {
			dest = append(dest, crypt3Encoding[v&63])
			v >>= 6
		}
	}
	dest = append(dest, crypt3Encoding[v&63])
	return dest
}
