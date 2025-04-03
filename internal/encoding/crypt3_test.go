package encoding

import (
	"reflect"
	"testing"
)

func TestEncodeCrypt3(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want []byte
	}{
		{
			name: "Empty input",
			raw:  []byte{},
			want: []byte{'.'},
		},
		{
			name: "Single byte",
			raw:  []byte{255},
			want: []byte{'z', '1'},
		},
		{
			name: "Two bytes",
			raw:  []byte{255, 255},
			want: []byte{'z', 'z', 'D'},
		},
		{
			name: "Three bytes",
			raw:  []byte{255, 255, 255},
			want: []byte{'z', 'z', 'z', 'z'},
		},
		{
			name: "Patterned input",
			raw:  []byte{0, 1, 2, 3, 4, 5, 6, 7},
			want: []byte{'.', '2', 'U', '.', '1', 'E', 'E', '/', '4', 'Q', '.'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeCrypt3(tt.raw)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EncodeCrypt3() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeInt6(t *testing.T) {
	tests := []struct {
		input byte
		want  int
	}{
		{'A', 12},
		{'z', 63},
		{'0', 2},
		{'.', 0},
		{'/', 1},
	}

	for _, tc := range tests {
		t.Run(string(tc.input), func(t *testing.T) {
			got := DecodeInt6(tc.input)
			if got != tc.want {
				t.Errorf("DecodeInt6(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestEncodeInt6(t *testing.T) {
	tests := []struct {
		input int
		want  byte
	}{
		{12, 'A'},
		{63, 'z'},
		{2, '0'},
		{0, '.'},
		{1, '/'},
	}

	for _, tc := range tests {
		t.Run(string(tc.want), func(t *testing.T) {
			got := EncodeInt6(tc.input)
			if got != tc.want {
				t.Errorf("EncodeInt6(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
