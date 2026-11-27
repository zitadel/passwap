package ssha

import (
	"reflect"
	"testing"

	"github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

// Test values generated with the Go standard library crypto/sha1,
// crypto/sha256 and crypto/sha512 packages, using salt "salt".
const (
	Password = "Test1000!"

	SHAEncoded     = "{SHA}zkbpMJnJm26pSNwLH8VN1EHqa/w="
	SSHAEncoded    = "{SSHA}yxWZXy/5ITWPd3Lvedk7yUASFfBzYWx0"
	SHA256Encoded  = "{SHA256}e1LJ7NS8EeE5DqREJ5yU0n1xpNu2kcotxl6XvY9kVqQ="
	SSHA256Encoded = "{SSHA256}U8KWFscrf6wlt6/Q9e0oQmeWFluqaqL0TbbO0EhZKL5zYWx0"
	SHA384Encoded  = "{SHA384}33ONcPYPqzSsF8AsvGnI1VCpT+gCXcH5L5yl0qfbTL55HboMjsvZC7+EYdwAl99z"
	SSHA384Encoded = "{SSHA384}aeKvmu3YhytWWcalwjHOt7NumBH3dmIowiWhiojx0QWW6WYuRjxPXFjrVrLvgLmJc2FsdA=="
	SHA512Encoded  = "{SHA512}lva7IDajagCj80luf1Nh/r/PaYeYbw14lO2SakO639hc0UY9choH8Qt3/StzUwU97QR5xoF0u14RISWcXcMDAw=="
	SSHA512Encoded = "{SSHA512}fHGvmFmkmkzIzC3Kwyk/TE7YeiNj8oR+w0RfYQUFuHNHTiELaNeMU2sGZduMB7N3T79sAQTeaxT/6lQiPs/pMnNhbHQ="
)

func Test_parse(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		wantNil bool
		wantErr bool
	}{
		{
			name:    "not ssha",
			encoded: testvalues.EncodedBcrypt2b,
			wantNil: true,
		},
		{
			name:    "not ssha",
			encoded: testvalues.MD5Encoded,
			wantNil: true,
		},
		{
			name:    "decode error",
			encoded: "{SSHA}~~~~~~",
			wantErr: true,
		},
		{
			name:    "too short",
			encoded: "{SSHA}Zm9v",
			wantErr: true,
		},
		{
			name:    "unsalted length mismatch",
			encoded: "{SHA}" + "zkbpMJnJm26pSNwLH8VN1EHqa/xzYWx0",
			wantErr: true,
		},
		{
			name:    "success SHA",
			encoded: SHAEncoded,
		},
		{
			name:    "success SSHA",
			encoded: SSHAEncoded,
		},
		{
			name:    "success SHA256",
			encoded: SHA256Encoded,
		},
		{
			name:    "success SSHA256",
			encoded: SSHA256Encoded,
		},
		{
			name:    "success SHA384",
			encoded: SHA384Encoded,
		},
		{
			name:    "success SSHA384",
			encoded: SSHA384Encoded,
		},
		{
			name:    "success SHA512",
			encoded: SHA512Encoded,
		},
		{
			name:    "success SSHA512",
			encoded: SSHA512Encoded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("parse() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parse() = nil, want non-nil")
			}
		})
	}
}

func Test_checker_verify(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		password string
		want     verifier.Result
	}{
		{"success SHA", SHAEncoded, Password, verifier.OK},
		{"wrong password SHA", SHAEncoded, "foobar", verifier.Fail},
		{"success SSHA", SSHAEncoded, Password, verifier.OK},
		{"wrong password SSHA", SSHAEncoded, "foobar", verifier.Fail},
		{"success SHA256", SHA256Encoded, Password, verifier.OK},
		{"wrong password SHA256", SHA256Encoded, "foobar", verifier.Fail},
		{"success SSHA256", SSHA256Encoded, Password, verifier.OK},
		{"wrong password SSHA256", SSHA256Encoded, "foobar", verifier.Fail},
		{"success SHA384", SHA384Encoded, Password, verifier.OK},
		{"wrong password SHA384", SHA384Encoded, "foobar", verifier.Fail},
		{"success SSHA384", SSHA384Encoded, Password, verifier.OK},
		{"wrong password SSHA384", SSHA384Encoded, "foobar", verifier.Fail},
		{"success SHA512", SHA512Encoded, Password, verifier.OK},
		{"wrong password SHA512", SHA512Encoded, "foobar", verifier.Fail},
		{"success SSHA512", SSHA512Encoded, Password, verifier.OK},
		{"wrong password SSHA512", SSHA512Encoded, "foobar", verifier.Fail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := parse(tt.encoded)
			if err != nil || c == nil {
				t.Fatalf("parse() error = %v, checker = %v", err, c)
			}
			if got := c.verify(tt.password); got != tt.want {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "not ssha",
			encoded: testvalues.EncodedBcrypt2b,
			want:    verifier.Skip,
		},
		{
			name:    "parse error",
			encoded: "{SSHA}~~~~~~",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "success",
			encoded: SSHAEncoded,
			want:    verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier()
			got, err := v.Validate(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Verify(t *testing.T) {
	tests := []struct {
		name     string
		encoded  string
		password string
		want     verifier.Result
		wantErr  bool
	}{
		{
			name:    "decode error",
			encoded: "{SSHA}~~~~~~",
			wantErr: true,
			want:    verifier.Skip,
		},
		{
			name:     "wrong prefix",
			encoded:  testvalues.ScryptEncoded,
			password: Password,
			want:     verifier.Skip,
		},
		{
			name:     "wrong password",
			encoded:  SSHAEncoded,
			password: "foobar",
			want:     verifier.Fail,
		},
		{
			name:     "success",
			encoded:  SSHAEncoded,
			password: Password,
			want:     verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier()
			got, err := v.Verify(tt.encoded, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
