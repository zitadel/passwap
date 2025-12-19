package md5salted

import (
	"reflect"
	"testing"

	"github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

const (
	Password          = "Test1000!"
	SaltEncoded       = "c2FsdA=="
	MD5SaltedSHash    = "R58+SD/95ORa9VZ9BPS5FA=="
	MD5SaltedPHash    = "0M2MYNUmNumHqqQ+kmuTUQ=="
	MD5SaltedEncodedS = "$md5salted-suffix$c2FsdA==$R58+SD/95ORa9VZ9BPS5FA=="
	MD5SaltedEncodedP = "$md5salted-prefix$c2FsdA==$0M2MYNUmNumHqqQ+kmuTUQ=="
)

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
			name: "not md5",
			args: args{testvalues.MD5Encoded},
		},
		{
			name:    "scan error",
			args:    args{"$md5salted$foo"},
			wantErr: true,
		},
		{
			name:    "wrong identifier",
			args:    args{"$md5salted-unknown$foo$foo"},
			wantErr: true,
		},
		{
			name: "success suffix",
			args: args{MD5SaltedEncodedS},
			want: &checker{
				hash: MD5SaltedSHash,
				salt: SaltEncoded,
			},
		},
		{
			name: "success prefix",
			args: args{MD5SaltedEncodedP},
			want: &checker{
				hash: MD5SaltedPHash,
				salt: SaltEncoded,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.args.encoded)
			if !tt.wantErr && got == nil && err == nil {
				return
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil && tt.want != nil {
				if got.salt != tt.want.salt || got.hash != tt.want.hash || got.saltpasswfunc == nil {
					t.Errorf("parse() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_checker_verify(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		want    verifier.Result
		encoded string
	}{
		{
			name:    "success suffix",
			args:    args{Password},
			want:    verifier.OK,
			encoded: MD5SaltedEncodedS,
		},
		{
			name:    "success prefix",
			args:    args{Password},
			want:    verifier.OK,
			encoded: MD5SaltedEncodedP,
		},
		{
			name:    "hash decode error",
			args:    args{Password},
			want:    verifier.Skip,
			encoded: "$md5salted-prefix$c2FsdA==$~~~~~~~",
		},
		{
			name:    "wrong password suffix",
			args:    args{"foobar"},
			want:    verifier.Fail,
			encoded: MD5SaltedEncodedS,
		},
		{
			name:    "wrong password prefix",
			args:    args{"foobar"},
			want:    verifier.Fail,
			encoded: MD5SaltedEncodedP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, _ := parse(tt.encoded)
			got, _ := parsed.verify(tt.args.password)
			if got != tt.want {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	type args struct {
		encoded string
	}
	tests := []struct {
		name    string
		args    args
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "not md5salted",
			args:    args{testvalues.EncodedBcrypt2b},
			want:    verifier.Skip,
			wantErr: false,
		},
		{
			name:    "parse error",
			args:    args{"$md5salted$foo"},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "success",
			args:    args{MD5SaltedEncodedS},
			want:    verifier.OK,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier()
			got, err := v.Validate(tt.args.encoded)
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
			args:    args{"$md5salted$salt$foo", Password},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "wrong prefix",
			args: args{testvalues.ScryptEncoded, Password},
			want: verifier.Skip,
		},
		{
			name: "wrong password suffix",
			args: args{MD5SaltedEncodedS, "foobar"},
			want: verifier.Fail,
		},
		{
			name: "success suffix",
			args: args{MD5SaltedEncodedS, Password},
			want: verifier.OK,
		},
		{
			name: "wrong password prefix",
			args: args{MD5SaltedEncodedP, "foobar"},
			want: verifier.Fail,
		},
		{
			name: "success prefix",
			args: args{MD5SaltedEncodedP, Password},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier()
			got, err := v.Verify(tt.args.encoded, tt.args.password)
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
