package argon2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"testing"

	av "github.com/muhlemmer/passwap/internal/argon2values"
	"github.com/muhlemmer/passwap/internal/salt"
	"github.com/muhlemmer/passwap/verifier"
	"golang.org/x/crypto/argon2"
)

var (
	testParams = Params{
		Time:    av.Time,
		Memory:  av.Memory,
		Threads: av.Threads,
		KeyLen:  av.KeyLen,
		SaltLen: av.SaltLen,
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
			av.Encoded_i,
			&checker{
				Params: Params{
					Time:    3,
					Memory:  4096,
					Threads: 1,
					KeyLen:  32,
					SaltLen: 16,
				},
				hash: av.Hash_i,
				salt: []byte(av.Salt),
			},
			false,
		},
		{
			"success id",
			av.Encoded_id,
			&checker{
				Params: Params{
					Time:    3,
					Memory:  4096,
					Threads: 1,
					KeyLen:  32,
					SaltLen: 16,
				},
				hash: av.Hash_id,
				salt: []byte(av.Salt),
			},
			false,
		},
		{
			"scan error",
			"foobar",
			nil,
			true,
		},
		{
			"d error",
			av.Encoded_d,
			nil,
			true,
		},
		{
			"unknown id error",
			`$foobar$v=19$m=4096,t=3,p=1$c2FsdHNhbHQ$MA1lJTML3jy8LJyr9lIP/68/omuHWSRxKjeWC0d0a5k`,
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
		hash:   av.Hash_i,
		salt:   []byte(av.Salt),
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
			av.Password,
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
				id:   Identifier_id,
				rand: salt.ErrReader{},
				hf:   argon2.IDKey,
			},
			wantErr: true,
		},
		{
			name: "success",
			h: Hasher{
				p:    testParams,
				id:   Identifier_id,
				rand: strings.NewReader(av.Salt),
				hf:   argon2.IDKey,
			},
			want: av.Encoded_id,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.Hash(av.Password)
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
				id:   Identifier_i,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				"foobar",
				av.Password,
			},
			verifier.Fail,
			true,
		},
		{
			"wrong password",
			Hasher{
				p:    testParams,
				id:   Identifier_i,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				av.Encoded_i,
				"spanac",
			},
			verifier.Fail,
			false,
		},
		{
			"update",
			Hasher{
				p: Params{
					Time:    av.Time,
					Memory:  32 * 1024,
					Threads: av.Threads,
					KeyLen:  av.KeyLen,
					SaltLen: av.SaltLen,
				},
				id:   Identifier_i,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				av.Encoded_i,
				av.Password,
			},
			verifier.NeedUpdate,
			false,
		},
		{
			"success",
			Hasher{
				p:    testParams,
				id:   Identifier_i,
				rand: rand.Reader,
				hf:   argon2.Key,
			},
			args{
				av.Encoded_i,
				av.Password,
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

func TestHasher_ID(t *testing.T) {
	h := Hasher{
		p:    testParams,
		id:   Identifier_id,
		rand: rand.Reader,
		hf:   argon2.Key,
	}

	if id := h.ID(); id != Identifier_id {
		t.Errorf("Hasher.ID = %s, want %s", id, Identifier_id)
	}
}

func TestHasher(t *testing.T) {
	tests := [...]func(Params) *Hasher{
		NewArgon2i, NewArgon2id,
	}

	for _, tt := range tests {
		h := tt(testParams)
		t.Run(h.id, func(t *testing.T) {
			hash, err := h.Hash(av.Password)
			if err != nil {
				t.Fatal(err)
			}

			res, err := h.Verify(hash, av.Password)
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
			args{"spanac", av.Password},
			verifier.Fail,
			true,
		},
		{
			"success",
			args{av.Encoded_id, av.Password},
			verifier.OK,
			false,
		},
		{
			"fail",
			args{av.Encoded_id, "spanac"},
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
