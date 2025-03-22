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
