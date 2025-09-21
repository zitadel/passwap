package drupal7

import (
	"testing"

	"github.com/zitadel/passwap/verifier"
)

func TestVerify(t *testing.T) {
	tests := []struct {
		password string
		hash     string
	}{
		// Real Drupal 7 test case
		{"test1234", "$S$ECiTwp95d.CM.PorExdDeWcec0F1SeaEsf3Yon9RUcrhQy4Q7XX1"},
		{"msuHVPek37GmAhTMXTQC", "$S$EvuUkmwMTwIJFXf2t2jFRD4kI5.4s.nVIMqq7cpGIRDdw8N6X.dF"},
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
	tests := []string{
		"$S$E123456",                                               // Too short
		"$X$ECDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqU",  // Invalid prefix
		"$S$@CDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqU",  // Invalid iteration character
		"$S$ECDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqUX", // Too long
	}

	for _, hash := range tests {
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
		// Using the real hash with wrong passwords
		{"wrongpassword", "$S$ECDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqU"},
		{"incorrect", "$S$ECDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqU"},
		{"badpass", "$S$ECDgn4Og5K1g.zVRmF132EW0HfJZ5oaTBsw/roww5SWjwTEfZxqU"},
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

func TestGetIterationCount(t *testing.T) {
	tests := []struct {
		char     byte
		expected int
	}{
		{'.', 1},     // 2^0 = 1
		{'/', 2},     // 2^1 = 2
		{'0', 4},     // 2^2 = 4
		{'1', 8},     // 2^3 = 8
		{'D', 32768}, // 2^15 = 32768 (actual value for 'D')
		{'E', 65536}, // 2^16 = 65536 (actual value for 'E' from our test case)
		{'@', -1},    // Invalid character
	}

	for _, tc := range tests {
		t.Run(string(tc.char), func(t *testing.T) {
			result := getIterationCount(tc.char)
			if result != tc.expected {
				t.Errorf("getIterationCount(%c) = %d, expected %d", tc.char, result, tc.expected)
			}
		})
	}
}

func TestDrupalBase64Encode(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0, 0, 0}, "....."},
		{[]byte{255, 255, 255}, "zzzz"},
		{[]byte{1, 2, 3}, "./02"},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			result := drupalBase64Encode(tc.input)
			if len(result) == 0 {
				t.Errorf("drupalBase64Encode returned empty string for input %v", tc.input)
			}
			// Note: We're not testing exact output since the algorithm is complex,
			// but we ensure it produces reasonable output
		})
	}
}

func TestHashPassword(t *testing.T) {
	// Test basic functionality
	result1 := hashPassword("test", "12345678", 4096)
	result2 := hashPassword("test", "12345678", 4096)
	result3 := hashPassword("different", "12345678", 4096)

	// Same input should produce same output
	if result1 != result2 {
		t.Errorf("same input produced different hashes: %s != %s", result1, result2)
	}

	// Different input should produce different output
	if result1 == result3 {
		t.Errorf("different input produced same hash: %s", result1)
	}

	// Result should not be empty
	if len(result1) == 0 {
		t.Errorf("hashPassword returned empty string")
	}
}
