package argon2

import (
	"errors"
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
			name:    "argon2i",
			encoded: tv.Argon2iEncoded,
			want: Params{
				Time:    tv.Argon2Time,
				Memory:  tv.Argon2Memory,
				Threads: tv.Argon2Threads,
				KeyLen:  tv.KeyLen,
				SaltLen: tv.SaltLen,
				id:      Identifier_i,
			},
		},
		{
			name:    "argon2id",
			encoded: tv.Argon2idEncoded,
			want:    testParams,
		},
		{
			name:    "argon2d",
			encoded: tv.Argon2dEncoded,
			wantErr: ErrArgon2d,
		},
		{
			name:    "other algorithm",
			encoded: tv.ScryptEncoded,
			wantErr: verifier.ErrNoMatch,
		},
		{
			name:    "malformed",
			encoded: "$argon2!!!",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseParams(tt.encoded)
			if tt.want != (Params{}) {
				if err != nil {
					t.Fatalf("ParseParams() error = %v, want nil", err)
				}
				if got != tt.want {
					t.Errorf("ParseParams() = %+v, want %+v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("ParseParams() error = nil, want error")
			}
			if got != (Params{}) {
				t.Errorf("ParseParams() = %+v, want zero Params on error", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseParams() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && errors.Is(err, verifier.ErrNoMatch) {
				t.Errorf("ParseParams() error = %v, must not be ErrNoMatch", err)
			}
		})
	}
}
