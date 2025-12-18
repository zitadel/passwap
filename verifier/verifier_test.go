package verifier_test

import (
	"testing"

	"github.com/zitadel/passwap/verifier"
)

func TestBoundsError(t *testing.T) {
	err := &verifier.BoundsError{
		Algorithm: "test-algo",
		Param:     "test-param",
		Min:       1,
		Max:       10,
		Actual:    20,
	}

	expectedMsg := "verifier: test-algo parameter test-param out of bounds: expected 1 - 10, got 20"
	if err.Error() != expectedMsg {
		t.Errorf("BoundsError.Error() = %q, want %q", err.Error(), expectedMsg)
	}
}
