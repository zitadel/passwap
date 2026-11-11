package argon2

import (
	"errors"
	"testing"

	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

func TestParseParams(t *testing.T) {
	recommended, err := NewArgon2id(RecommendedIDParams, nil).Hash(tv.Password)
	if err != nil {
		t.Fatal(err)
	}
	withoutID := testParams
	withoutID.id = ""

	tests := []struct {
		name    string
		encoded string
		want    Params
		wantErr error
	}{
		{
			name:    "argon2i",
			encoded: tv.Argon2iEncoded,
			want:    withoutID,
		},
		{
			name:    "argon2id",
			encoded: tv.Argon2idEncoded,
			want:    withoutID,
		},
		{
			name:    "equals the params it was made with",
			encoded: recommended,
			want:    RecommendedIDParams,
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
