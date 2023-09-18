package encoding

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestAutoDecodePbkdf2(t *testing.T) {
	in := []byte{255, 255, 255, 254, 254, 254, 253, 253, 253, 250}

	type args struct {
		encoded string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Standard, no padding",
			args: args{
				encoded: base64.RawStdEncoding.EncodeToString(in),
			},
			want: in,
		},
		{
			name: "Standard, padding",
			args: args{
				encoded: base64.StdEncoding.EncodeToString(in),
			},
			want: in,
		},
		{
			name: "pbkdf2, no padding",
			args: args{
				encoded: Pbkdf2B64.EncodeToString(in),
			},
			want: in,
		},
		{
			name: "pbkdf2, padding",
			args: args{
				encoded: Pbkdf2B64.WithPadding(base64.StdPadding).EncodeToString(in),
			},
			want: in,
		},
		{
			name: "decode erorr",
			args: args{
				encoded: "~~~",
			},
			want:    []byte{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Log(tt.args.encoded)
			got, err := AutoDecodePbkdf2(tt.args.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("AutoDecodePbkdf2() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AutoDecodePbkdf2() = %v, want %v", got, tt.want)
			}
		})
	}
}
