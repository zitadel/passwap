package verifier_test

import (
	"testing"

	"github.com/muhlemmer/passwap/argon2"
	"github.com/muhlemmer/passwap/verifier"
)

func TestNewIDMap(t *testing.T) {
	verifiers := []verifier.Verifier{
		argon2.Argon2i,
		argon2.Argon2id,
	}

	m := verifier.NewIDMap(verifiers)

	for _, v := range verifiers {
		if _, ok := m[v.ID()]; !ok {
			t.Errorf("NewIDMap: %s missing", v.ID())
		}
	}

	res, err := m[argon2.Identifier_id].Verify(
		`$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$sohxEThr7t72cOKoCEfcb3z65EHDVEOEKBlabLm3h+s`,
		"foobar",
	)
	if err != nil {
		t.Fatal(err)
	}

	if res != verifier.OK {
		t.Errorf("Verifier() = %s, want %s", res, verifier.OK)
	}
}
