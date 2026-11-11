package scrypt

import (
	"errors"
	"strings"
	"testing"

	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

func TestParseParams(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    Params
		wantErr error
	}{
		{
			name:    "scrypt",
			encoded: tv.ScryptEncoded,
			want:    testParams,
		},
		{
			name:    "linux",
			encoded: strings.ReplaceAll(tv.ScryptEncoded, "scrypt", "7"),
			want:    testParams,
		},
		{
			name:    "other algorithm",
			encoded: tv.Argon2idEncoded,
			wantErr: verifier.ErrNoMatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseParams(tt.encoded)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParseParams() error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseParams() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
