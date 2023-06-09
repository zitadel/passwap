package argon2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/passwap/internal/salt"
	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
	"golang.org/x/crypto/argon2"
)

var (
	testParams = Params{
		Time:    tv.Argon2Time,
		Memory:  tv.Argon2Memory,
		Threads: tv.Argon2Threads,
		KeyLen:  tv.KeyLen,
		SaltLen: tv.SaltLen,
		id:      Identifier_id,
	}
)

func Test_parse(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    *checker
		wantErr bool
	}{
		{
			"success i",
			tv.Argon2iEncoded,
			&checker{
				Params: Params{
					Time:    3,
					Memory:  4096,
					Threads: 1,
					KeyLen:  32,
					SaltLen: 16,
					id:      Identifier_i,
				},
				hash: tv.Argon2iHash,
				salt: []byte(tv.Salt),
			},
			false,
		},
		{
			"success id",
			tv.Argon2idEncoded,
			&checker{
				Params: Params{
					Time:    3,
					Memory:  4096,
					Threads: 1,
					KeyLen:  32,
					SaltLen: 16,
					id:      Identifier_id,
				},
				hash: tv.Argon2idHash,
				salt: []byte(tv.Salt),
			},
			false,
		},
		{
			"skip",
			"foobar",
			nil,
			false,
		},
		{
			"scan error",
			"$argon2!!!",
			nil,
			true,
		},
		{
			"d error",
			tv.Argon2dEncoded,
			nil,
			true,
		},
		{
			"unknown id",
			strings.ReplaceAll(tv.Argon2iEncoded, "argon2i", "argon2x"),
			nil,
			true,
		},
		{
			"version error",
			`$argon2i$v=16$m=4096,t=3,p=1$c2FsdHNhbHQ$MA1lJTML3jy8LJyr9lIP/68/omuHWSRxKjeWC0d0a5k`,
			nil,
			true,
		},
		{
			"salt decode error",
			`$argon2i$v=19$m=4096,t=3,p=1$########$MA1lJTML3jy8LJyr9lIP/68/omuHWSRxKjeWC0d0a5k`,
			nil,
			true,
		},
		{
			"hash decode error",
			`$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$######`,
			nil,
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want != nil {
				t.Log(
					strings.ReplaceAll(fmt.Sprint(got.hash), " ", ", "),
				)

				if !reflect.DeepEqual(got.Params, tt.want.Params) {
					t.Errorf("parse() Params =\n%v\nwant\n%v", got.Params, tt.want.Params)
				}
				if !bytes.Equal(got.hash, tt.want.hash) {
					t.Errorf("parse() hash =\n%v\nwant\n%v", got.hash, tt.want.hash)
				}
				if !bytes.Equal(got.salt, tt.want.salt) {
					t.Errorf("parse() salt =\n%v\nwant\n%v", got.salt, tt.want.salt)
				}
			} else if got != nil {
				t.Errorf("parse() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func Test_checker_verify(t *testing.T) {
	c := checker{
		Params: testParams,
		hash:   tv.Argon2iHash,
		salt:   []byte(tv.Salt),
		hf:     argon2.Key,
	}

	tests := []struct {
		pw   string
		want verifier.Result
	}{
		{
			"spanac",
			verifier.Fail,
		},
		{
			tv.Password,
			verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.want.String(), func(t *testing.T) {
			if got := c.verify(tt.pw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_Hash(t *testing.T) {
	tests := []struct {
		name    string
		h       Hasher
		want    string
		wantErr bool
	}{
		{
			name: "salt error",
			h: Hasher{
				p:    testParams,
				rand: salt.ErrReader{},
				hf:   argon2.IDKey,
			},
			wantErr: true,
		},
		{
			name: "success",
			h: Hasher{
				p:    testParams,
				rand: strings.NewReader(tv.Salt),
				hf:   argon2.IDKey,
			},
			want: tv.Argon2idEncoded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Hash(tv.Password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Hasher.Hash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_Verify(t *testing.T) {
	type args struct {
		encoded  string
		password string
	}
	tests := []struct {
		name    string
		h       Hasher
		args    args
		want    verifier.Result
		wantErr bool
	}{
		{
			"parse error",
			Hasher{
				p:    testParams,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				"$argon2!!!",
				tv.Password,
			},
			verifier.Skip,
			true,
		},
		{
			"wrong password",
			Hasher{
				p:    testParams,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				tv.Argon2idEncoded,
				"spanac",
			},
			verifier.Fail,
			false,
		},
		{
			"update",
			Hasher{
				p: Params{
					Time:    tv.Argon2Time,
					Memory:  32 * 1024,
					Threads: tv.Argon2Threads,
					KeyLen:  tv.KeyLen,
					SaltLen: tv.SaltLen,
				},
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				tv.Argon2idEncoded,
				tv.Password,
			},
			verifier.NeedUpdate,
			false,
		},
		{
			"success",
			Hasher{
				p:    testParams,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				tv.Argon2idEncoded,
				tv.Password,
			},
			verifier.OK,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Verify(tt.args.encoded, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Hasher.Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher(t *testing.T) {
	tests := [...]func(Params) *Hasher{
		NewArgon2i, NewArgon2id,
	}

	for _, tt := range tests {
		h := tt(testParams)
		t.Run(h.p.id, func(t *testing.T) {
			hash, err := h.Hash(tv.Password)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.Verify(hash, tv.Password)
			if err != nil {
				t.Fatal(err)
			}
			if res != verifier.OK {
				t.Errorf("Hasher.Verify() = %s, want %s", res, verifier.OK)
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
			"parse error",
			args{"$argon2!!", tv.Password},
			verifier.Skip,
			true,
		},
		{
			"success",
			args{tv.Argon2idEncoded, tv.Password},
			verifier.OK,
			false,
		},
		{
			"fail",
			args{tv.Argon2idEncoded, "spanac"},
			verifier.Fail,
			false,
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
