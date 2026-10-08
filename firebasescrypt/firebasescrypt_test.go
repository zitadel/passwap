package firebasescrypt

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

const defaultParams = "ln=14,r=8"

func encode(params, salt, hash, saltSeparator, signerKey string) string {
	return Prefix + strings.Join([]string{params, salt, hash, saltSeparator, signerKey}, "$")
}

func encodeParams(params string) string {
	return encode(params, tv.FirebaseScryptSalt, tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey)
}

func urlSafe(s string) string {
	return strings.NewReplacer("+", "-", "/", "_").Replace(s)
}

func noPadding(s string) string {
	return strings.TrimRight(s, "=")
}

// Ory Kratos format of tv.FirebaseScryptEncoded.
var kratosEncoded = "$firescrypt$" + strings.Join([]string{
	"ln=14,r=8,p=1", tv.FirebaseScryptSalt, tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey,
}, "$")

func TestVerifier_Verify(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		password string
		want     verifier.Result
		wantErr  bool
	}{
		{
			name:     "firebase sample",
			encoded:  tv.FirebaseScryptEncoded,
			password: tv.FirebaseScryptPassword,
			want:     verifier.OK,
		},
		{
			name:     "empty salt separator",
			encoded:  tv.FirebaseScryptEncodedNoSaltSeparator,
			password: tv.FirebaseScryptPassword,
			want:     verifier.OK,
		},
		{
			name:     "non default params",
			encoded:  tv.FirebaseScryptEncodedLowCost,
			password: tv.FirebaseScryptPassword,
			want:     verifier.OK,
		},
		{
			name:     "wrong password",
			encoded:  tv.FirebaseScryptEncoded,
			password: "wrong",
			want:     verifier.Fail,
		},
		{
			name:     "wrong hash",
			encoded:  encode(defaultParams, tv.FirebaseScryptSalt, "m"+tv.FirebaseScryptHash[1:], tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey),
			password: tv.FirebaseScryptPassword,
			want:     verifier.Fail,
		},
		{
			name: "url safe base64",
			encoded: encode(defaultParams,
				urlSafe(tv.FirebaseScryptSalt), urlSafe(tv.FirebaseScryptHash),
				urlSafe(tv.FirebaseScryptSaltSeparator), urlSafe(tv.FirebaseScryptSignerKey),
			),
			password: tv.FirebaseScryptPassword,
			want:     verifier.OK,
		},
		{
			name: "no padding",
			encoded: encode(defaultParams,
				noPadding(tv.FirebaseScryptSalt), noPadding(tv.FirebaseScryptHash),
				noPadding(tv.FirebaseScryptSaltSeparator), noPadding(tv.FirebaseScryptSignerKey),
			),
			password: tv.FirebaseScryptPassword,
			want:     verifier.OK,
		},
		{
			name:     "scrypt key error",
			encoded:  encodeParams("ln=0,r=8"),
			password: tv.FirebaseScryptPassword,
			want:     verifier.Fail,
			wantErr:  true,
		},
		{
			name:     "skip bcrypt",
			encoded:  "$2y$12$hXUrnqdq1RIIYZ2HPytIIe5lXdIvbhqrTvdPsSF7o.jFh817Z6lwm",
			password: tv.FirebaseScryptPassword,
			want:     verifier.Skip,
		},
		{
			name:     "skip kratos format",
			encoded:  kratosEncoded,
			password: tv.FirebaseScryptPassword,
			want:     verifier.Skip,
		},
	}
	v := NewVerifier(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v.Verify(tt.encoded, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Verifier.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	tests := []struct {
		name      string
		opts      *ValidationOpts
		encoded   string
		want      verifier.Result
		wantParam string
	}{
		{
			name:    "firebase sample",
			encoded: tv.FirebaseScryptEncoded,
			want:    verifier.OK,
		},
		{
			name: "non default params, wide opts",
			opts: &ValidationOpts{
				MinLN: 10,
				MaxLN: 14,
				MinR:  4,
				MaxR:  8,
			},
			encoded: tv.FirebaseScryptEncodedLowCost,
			want:    verifier.OK,
		},
		{
			name:      "LN below min",
			encoded:   encodeParams("ln=13,r=8"),
			want:      verifier.Fail,
			wantParam: "LN",
		},
		{
			name:      "LN above max",
			encoded:   encodeParams("ln=15,r=8"),
			want:      verifier.Fail,
			wantParam: "LN",
		},
		{
			name:      "R below min",
			encoded:   encodeParams("ln=14,r=7"),
			want:      verifier.Fail,
			wantParam: "R",
		},
		{
			name:      "R above max",
			encoded:   encodeParams("ln=14,r=9"),
			want:      verifier.Fail,
			wantParam: "R",
		},
		{
			name:    "skip kratos format",
			encoded: kratosEncoded,
			want:    verifier.Skip,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewVerifier(tt.opts).Validate(tt.encoded)
			if got != tt.want {
				t.Errorf("Verifier.Validate() = %v, want %v", got, tt.want)
			}
			if tt.wantParam == "" {
				if err != nil {
					t.Errorf("Verifier.Validate() error = %v", err)
				}
				return
			}
			var bounds *verifier.BoundsError
			if !errors.As(err, &bounds) {
				t.Fatalf("Verifier.Validate() error = %v, want %T", err, bounds)
			}
			if bounds.Algorithm != Identifier || bounds.Param != tt.wantParam {
				t.Errorf("Verifier.Validate() bounds error for %s %s, want %s %s", bounds.Algorithm, bounds.Param, Identifier, tt.wantParam)
			}
		})
	}
}

func TestVerifier_malformed(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{
			name:    "too few parts",
			encoded: Prefix + strings.Join([]string{defaultParams, tv.FirebaseScryptSalt, tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator}, "$"),
		},
		{
			name:    "too many parts",
			encoded: tv.FirebaseScryptEncoded + "$foo",
		},
		{
			name:    "params scan error",
			encoded: encodeParams("ln=foo,r=8"),
		},
		{
			name:    "params with p",
			encoded: encodeParams("ln=14,r=8,p=1"),
		},
		{
			name:    "params not canonical",
			encoded: encodeParams("ln=014,r=+8"),
		},
		{
			name:    "negative ln",
			encoded: encodeParams("ln=-1,r=8"),
		},
		{
			name:    "salt error",
			encoded: encode(defaultParams, "!!!", tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey),
		},
		{
			name:    "hash error",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, "!!!", tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey),
		},
		{
			name:    "salt separator error",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, tv.FirebaseScryptHash, "!!!", tv.FirebaseScryptSignerKey),
		},
		{
			name:    "signer key error",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator, "!!!"),
		},
		{
			name:    "empty hash",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, "", tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey),
		},
		{
			name:    "empty signer key",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, tv.FirebaseScryptHash, tv.FirebaseScryptSaltSeparator, ""),
		},
		{
			name:    "hash and signer key length differ",
			encoded: encode(defaultParams, tv.FirebaseScryptSalt, tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSaltSeparator, tv.FirebaseScryptSignerKey),
		},
	}
	v := NewVerifier(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v.Validate(tt.encoded)
			if err == nil || got != verifier.Skip {
				t.Errorf("Verifier.Validate() = %v, %v, want %v and an error", got, err, verifier.Skip)
			}
			got, err = v.Verify(tt.encoded, tv.FirebaseScryptPassword)
			if err == nil || got != verifier.Skip {
				t.Errorf("Verifier.Verify() = %v, %v, want %v and an error", got, err, verifier.Skip)
			}
		})
	}
}

func Test_checkValidationOpts(t *testing.T) {
	tests := []struct {
		name string
		opts *ValidationOpts
		want *ValidationOpts
	}{
		{
			name: "nil opts",
			want: DefaultValidationOpts,
		},
		{
			name: "empty opts",
			opts: &ValidationOpts{},
			want: DefaultValidationOpts,
		},
		{
			name: "partial opts",
			opts: &ValidationOpts{
				MinLN: 10,
				MaxR:  9,
			},
			want: &ValidationOpts{
				MinLN: 10,
				MaxLN: DefaultMaxLN,
				MinR:  DefaultMinR,
				MaxR:  9,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before ValidationOpts
			if tt.opts != nil {
				before = *tt.opts
			}
			got := checkValidationOpts(tt.opts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkValidationOpts() = %+v, want %+v", got, tt.want)
			}
			if tt.opts != nil && *tt.opts != before {
				t.Errorf("checkValidationOpts() mutated opts to %+v, want %+v", *tt.opts, before)
			}
		})
	}
}
