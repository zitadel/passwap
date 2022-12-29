package md5

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/muhlemmer/passwap/internal/salt"
	"github.com/muhlemmer/passwap/internal/testvalues"
	"github.com/muhlemmer/passwap/verifier"
)

func Test_checksum(t *testing.T) {
	hash := checksum([]byte(testvalues.Password), []byte(testvalues.MD5Salt))

	if !bytes.Equal(hash, testvalues.MD5Checksum) {
		t.Errorf("checksum() =\n%s\nwant\n%s", hash, testvalues.MD5Checksum)
	}
}

func Test_hash(t *testing.T) {
	type args struct {
		r        io.Reader
		password string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name:    "salt error",
			args:    args{salt.ErrReader{}, testvalues.Password},
			wantErr: true,
		},
		{
			name: "success",
			args: args{strings.NewReader(testvalues.MD5SaltRaw), testvalues.Password},
			want: testvalues.MD5Encoded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hash(tt.args.r, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parse(t *testing.T) {
	type args struct {
		encoded string
	}
	tests := []struct {
		name    string
		args    args
		want    *checker
		wantErr bool
	}{
		{
			name: "not md5",
			args: args{testvalues.EncodedBcrypt2b},
		},
		{
			name:    "scan error",
			args:    args{"$1$foo"},
			wantErr: true,
		},
		{
			name: "success",
			args: args{testvalues.MD5Encoded},
			want: &checker{
				checksum: []byte(testvalues.MD5Checksum),
				salt:     []byte(testvalues.MD5Salt),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.args.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_checker_verify(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name string
		args args
		want verifier.Result
	}{
		{
			name: "success",
			args: args{testvalues.Password},
			want: verifier.OK,
		},
		{
			name: "wrong password",
			args: args{"foobar"},
			want: verifier.Fail,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &checker{
				checksum: []byte(testvalues.MD5Checksum),
				salt:     []byte(testvalues.MD5Salt),
			}
			if got := c.verify(tt.args.password); got != tt.want {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		encoded  string
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
			args:    args{"$1$foo", testvalues.Password},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "wrong prefix",
			args: args{testvalues.ScryptEncoded, testvalues.Password},
			want: verifier.Skip,
		},
		{
			name: "wrong password",
			args: args{testvalues.MD5Encoded, "foobar"},
			want: verifier.Fail,
		},
		{
			name: "success",
			args: args{testvalues.MD5Encoded, testvalues.Password},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.encoded, tt.args.password)
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

func TestHasher(t *testing.T) {
	var h Hasher

	encoded, err := h.Hash("foobar")
	if err != nil {
		t.Fatal(err)
	}
	result, err := h.Verify(encoded, "foobar")
	if err != nil {
		t.Fatal(err)
	}
	if result != verifier.OK {
		t.Errorf("Hasher.Verify() = %s, want %s", result, verifier.OK)
	}
}
