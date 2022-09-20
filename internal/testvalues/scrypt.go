package testvalues

import (
	"encoding/base64"
	"strings"
)

// Scrypt test values generated with scrypt.py
const (
	ScryptN       = 65536
	ScryptR       = 8
	ScryptP       = 1
	ScryptEncoded = `$scrypt$ln=16,r=8,p=1$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`
)

var (
	ScryptHash []byte
)

func init() {
	nodes := strings.Split(ScryptEncoded, "$")

	var err error

	ScryptHash, err = base64.RawStdEncoding.Strict().DecodeString(nodes[4])
	if err != nil {
		panic(err)
	}
}
