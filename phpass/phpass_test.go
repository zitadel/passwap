package phpass

import (
	"testing"

	"github.com/zitadel/passwap/verifier"
)

//test cases taken from passlib

func TestVerify(t *testing.T) {
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
			result, err := Verify(tc.hash, tc.password)
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
		"$P$1IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0", // Rounds too low
		"$P$cIQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0", // Rounds too hight
		"$P$912345678X@badSalt",              // Invalid salt chars
	}

	for _, hash := range test {
		t.Run(hash, func(t *testing.T) {
			result, err := Verify(hash, "irrelevant")
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
			result, err := Verify(tc.hash, tc.password)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if result != verifier.Fail {
				t.Errorf("expected Failure for incorrect password, got %v", result)
			}
		})
	}
}
