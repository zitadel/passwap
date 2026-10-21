package pbkdf2

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
			name:    "sha1",
			encoded: tv.Pbkdf2Sha1Encoded,
			want:    testParamsSha1,
		},
		{
			name:    "sha256",
			encoded: tv.Pbkdf2Sha256Encoded,
			want:    testParamsSha256,
		},
		{
			name:    "sha256 standard encoding with padding",
			encoded: tv.Pbkdf2Sha256StdEncodedPadding,
			want:    testParamsSha256,
		},
		{
			name:    "sha512",
			encoded: tv.Pbkdf2Sha512Encoded,
			want:    testParamsSha512,
		},
		{
			name:    "other algorithm",
			encoded: tv.ScryptEncoded,
			wantErr: verifier.ErrNoMatch,
		},
		{
			name:    "malformed",
			encoded: "$pbkdf2$!!!!",
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
