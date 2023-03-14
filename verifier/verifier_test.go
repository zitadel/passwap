package verifier_test

import (
	"testing"

	"github.com/zitadel/passwap/argon2"
	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

func TestVerifyFunc_Verify(t *testing.T) {
	v := verifier.VerifyFunc(argon2.Verify)
	result, err := v.Verify(tv.Argon2idEncoded, tv.Password)
	if err != nil {
		t.Fatal(err)
	}
	if result != verifier.OK {
		t.Errorf("VerifyFunc = %s, want %s", result, verifier.OK)
	}
}
