package md5plain

import (
	"reflect"
	"testing"

	"github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

func TestVerify(t *testing.T) {
	type args struct {
		hash     string
		password string
	}
	tests := []struct {
		name    string
		args    args
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "decode error",
			args:    args{"!!!", testvalues.Password},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "wrong password",
			args: args{testvalues.MD5PlainHex, "foobar"},
			want: verifier.Fail,
		},
		{
			name: "success",
			args: args{testvalues.MD5PlainHex, testvalues.Password},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.hash, tt.args.password)
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
