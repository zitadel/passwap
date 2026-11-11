package pbkdf2

import (
	"errors"
	"testing"

	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

func TestParseParams(t *testing.T) {
	recommended, err := NewSHA256(RecommendedSHA256Params, nil).Hash(tv.Password)
	if err != nil {
		t.Fatal(err)
	}
	withoutID := func(p Params) Params {
		p.id = ""
		return p
	}

	tests := []struct {
		name    string
		encoded string
		want    Params
		wantErr error
	}{
		{
			name:    "sha1",
			encoded: tv.Pbkdf2Sha1Encoded,
			want:    withoutID(testParamsSha1),
		},
		{
			name:    "sha256",
			encoded: tv.Pbkdf2Sha256Encoded,
			want:    withoutID(testParamsSha256),
		},
		{
			name:    "sha256 standard encoding with padding",
			encoded: tv.Pbkdf2Sha256StdEncodedPadding,
			want:    withoutID(testParamsSha256),
		},
		{
			name:    "sha512",
			encoded: tv.Pbkdf2Sha512Encoded,
			want:    withoutID(testParamsSha512),
		},
		{
			name:    "equals the params it was made with",
			encoded: recommended,
			want:    RecommendedSHA256Params,
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
