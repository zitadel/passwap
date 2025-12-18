package phpass

import (
	"reflect"
	"testing"

	"github.com/zitadel/passwap/verifier"
)

func Test_checkValidationOpts(t *testing.T) {
	tests := []struct {
		name string
		opts *ValidationOpts
		want *ValidationOpts
	}{
		{
			name: "nil opts returns default",
			opts: nil,
			want: DefaultValidationOpts,
		},
		{
			name: "zero fields set to default",
			opts: &ValidationOpts{},
			want: DefaultValidationOpts,
		},
		{
			name: "partial fields set",
			opts: &ValidationOpts{MinRounds: 10},
			want: &ValidationOpts{MinRounds: 10, MaxRounds: DefaultMaxRounds},
		},
		{
			name: "all fields set",
			opts: &ValidationOpts{MinRounds: 8, MaxRounds: 20},
			want: &ValidationOpts{MinRounds: 8, MaxRounds: 20},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkValidationOpts(tt.opts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkValidationOpts() = %v, want %v", got, tt.want)
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
			name:    "valid hash",
			encoded: "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0",
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name:    "malformed hash",
			encoded: "$X$912345678WhEyvy1YWzT4647jzeOmo0",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "invalid rounds (too low)",
			encoded: "$P$112345678si5M0DDyPpmRCmcltU/YW/",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "invalid rounds (too high)",
			encoded: "$P$Z12345678si5M0DDyPpmRCmcltU/YW/",
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &ValidationOpts{
				MinRounds: 8,
				MaxRounds: 30,
			}
			v := NewVerifier(opts)
			got, err := v.Validate(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verifier.Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

//test cases taken from passlib

func TestVerifier_Verify(t *testing.T) {
	tests := []struct {
		password string
		hash     string
	}{
		{"test12345", "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0"},
		{"test1", "$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00"},
		{"123456", "$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1"},
		{"123456", "$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1"},
		{"thisisalongertestPW", "$P$912345678LIjjb6PhecupozNBmDndU0"},
		{"JohnRipper", "$P$612345678si5M0DDyPpmRCmcltU/YW/"},
		{"JohnRipper", "$H$712345678WhEyvy1YWzT4647jzeOmo0"},
		{"JohnRipper", "$P$B12345678L6Lpt4BxNotVIMILOa9u81"},
		{"", "$P$7JaFQsPzJSuenezefD/3jHgt5hVfNH0"},
		{"compL3X!", "$P$FiS0N5L672xzQx1rt1vgdJQRYKnQM9/"},
	}

	for _, tc := range tests {
		t.Run(tc.password, func(t *testing.T) {
			v := NewVerifier(nil)
			result, err := v.Verify(tc.hash, tc.password)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != verifier.OK {
				t.Errorf("password verification failed for hash: %s", tc.hash)
			}
		})
	}
}

func TestVerifyMalformedHashes(t *testing.T) {
	test := []string{
		"$P$712345678",                       // Too short
		"$X$912345678WhEyvy1YWzT4647jzeOmo0", // Invalid prefix
		"$P$912345678X@badSalt",              // Invalid salt chars
	}

	for _, hash := range test {
		t.Run(hash, func(t *testing.T) {
			v := NewVerifier(nil)
			result, err := v.Verify(hash, "irrelevant")
			if err == nil {
				t.Errorf("expected error for malformed hash: %s", hash)
			}
			if result != verifier.Skip {
				t.Errorf("expected Skip for malformed hash: %s, got %v", hash, result)
			}
		})
	}
}

func TestVerifyIncorrectPassword(t *testing.T) {
	incorrectTests := []struct {
		password string
		hash     string
	}{
		{"wrongpassword", "$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0"},
		{"12345", "$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1"},
		{"notJohnRipper", "$P$612345678si5M0DDyPpmRCmcltU/YW/"},
	}

	for _, tc := range incorrectTests {
		t.Run(tc.password, func(t *testing.T) {
			v := NewVerifier(nil)
			result, err := v.Verify(tc.hash, tc.password)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != verifier.Fail {
				t.Errorf("expected Failure for incorrect password, got %v", result)
			}
		})
	}
}
