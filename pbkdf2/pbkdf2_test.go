package pbkdf2

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/passwap/internal/salt"
	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

var (
	testParamsSha1 = Params{
		Rounds:  tv.Pbkdf2Rounds,
		SaltLen: tv.SaltLen,
		KeyLen:  tv.Pbkdf2Sha1KeyLen,
		id:      IdentifierSHA1,
	}
	testParamsSha256 = Params{
		Rounds:  tv.Pbkdf2Rounds,
		SaltLen: tv.SaltLen,
		KeyLen:  tv.Pbkdf2Sha256KeyLen,
		id:      IdentifierSHA256,
	}
	testParamsSha512 = Params{
		Rounds:  tv.Pbkdf2Rounds,
		SaltLen: tv.SaltLen,
		KeyLen:  tv.Pbkdf2Sha512KeyLen,
		id:      IdentifierSHA512,
	}
)

func Test_hashFuncForIdentifier(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want func() hash.Hash
	}{
		{
			name: "empty arg",
			id:   "",
			want: nil,
		},
		{
			name: "wrong arg",
			id:   "foo",
			want: nil,
		},
		{
			name: IdentifierSHA1,
			id:   IdentifierSHA1,
			want: sha1.New,
		},
		{
			name: IdentifierSHA224,
			id:   IdentifierSHA224,
			want: sha256.New224,
		},
		{
			name: IdentifierSHA256,
			id:   IdentifierSHA256,
			want: sha256.New,
		},
		{
			name: IdentifierSHA384,
			id:   IdentifierSHA384,
			want: sha512.New384,
		},
		{
			name: IdentifierSHA512,
			id:   IdentifierSHA512,
			want: sha512.New,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashFuncForIdentifier(tt.id)
			if tt.want == nil {
				if got != nil {
					t.Error("hashFuncForIdentifier() not nil")
				}
				return
			}
			if !reflect.DeepEqual(got(), tt.want()) {
				t.Errorf("hashFuncForIdentifier() = %v, want %v", got(), tt.want())
			}
		})
	}
}

func Test_parse(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    *checker
		wantErr bool
	}{
		{
			name:    "success sha1",
			encoded: tv.Pbkdf2Sha1Encoded,
			want: &checker{
				Params: testParamsSha1,
				hash:   tv.Pbkdf2Sha1Hash,
				salt:   []byte(tv.Salt),
				hf:     sha1.New,
			},
		},
		{
			name:    "success sha256",
			encoded: tv.Pbkdf2Sha256Encoded,
			want: &checker{
				Params: testParamsSha256,
				hash:   tv.Pbkdf2Sha256Hash,
				salt:   []byte(tv.Salt),
				hf:     sha256.New,
			},
			wantErr: false,
		},
		{
			name:    "success sha512",
			encoded: tv.Pbkdf2Sha512Encoded,
			want: &checker{
				Params: testParamsSha512,
				hash:   tv.Pbkdf2Sha512Hash,
				salt:   []byte(tv.Salt),
				hf:     sha512.New,
			},
			wantErr: false,
		},
		{
			name:    "success std encoding",
			encoded: tv.Pbkdf2Sha256StdEncoded,
			want: &checker{
				Params: testParamsSha256,
				hash:   tv.Pbkdf2Sha256Hash,
				salt:   []byte(tv.Salt),
				hf:     sha256.New,
			},
			wantErr: false,
		},
		{
			name:    "success std encoding with padding",
			encoded: tv.Pbkdf2Sha256StdEncodedPadding,
			want: &checker{
				Params: testParamsSha256,
				hash:   tv.Pbkdf2Sha256Hash,
				salt:   []byte(tv.Salt),
				hf:     sha256.New,
			},
			wantErr: false,
		},
		/*
			SHA-224 and SHA-384 are not implemented in passlib,
			therefore there are no encoded strings to compare with.
			We will only test encode-and-verify cases instead.
		*/
		{
			name:    "wrong prefix",
			encoded: tv.Argon2iEncoded,
			want:    nil,
			wantErr: false,
		},
		{
			name:    "scan error",
			encoded: Prefix + "!!!!",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "unknow hash identifier",
			encoded: strings.ReplaceAll(tv.Pbkdf2Sha256Encoded, "sha256", "sha123"),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "salt decode error",
			encoded: `$pbkdf2$12$~~$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			want:    nil,
			wantErr: true,
		},
		{
			name:    "hash decode error",
			encoded: `$pbkdf2$12$cmFuZG9tc2FsdGlzaGFyZA$~~`,
			want:    nil,
			wantErr: true,
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
				if !reflect.DeepEqual(got.Params, tt.want.Params) {
					t.Errorf("parse() Params =\n%v\nwant\n%v", got.Params, tt.want.Params)
				}
				if !bytes.Equal(got.hash, tt.want.hash) {
					t.Errorf("parse() hash =\n%v\nwant\n%v", got.hash, tt.want.hash)
				}
				if !bytes.Equal(got.salt, tt.want.salt) {
					t.Errorf("parse() salt =\n%v\nwant\n%v", got.salt, tt.want.salt)
				}
				if !reflect.DeepEqual(got.hf(), tt.want.hf()) {
					t.Errorf("parse() hf =\n%v\nwant\n%v", got.hf(), tt.want.hf())
				}
			} else if got != nil {
				t.Errorf("parse() =\n%v\nwant\n%v", got, tt.want)
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
				p:    testParamsSha1,
				rand: salt.ErrReader{},
				hf:   sha1.New,
			},
			wantErr: true,
		},
		{
			name: "sha1",
			h: Hasher{
				p:    testParamsSha1,
				rand: strings.NewReader(tv.Salt),
				hf:   sha1.New,
			},
			want: tv.Pbkdf2Sha1Encoded,
		},
		{
			name: "sha256",
			h: Hasher{
				p:    testParamsSha256,
				rand: strings.NewReader(tv.Salt),
				hf:   sha256.New,
			},
			want: tv.Pbkdf2Sha256Encoded,
		},
		{
			name: "sha512",
			h: Hasher{
				p:    testParamsSha512,
				rand: strings.NewReader(tv.Salt),
				hf:   sha512.New,
			},
			want: tv.Pbkdf2Sha512Encoded,
		},
		/*
			SHA-224 and SHA-384 are not implemented in passlib,
			therefore there are no encoded strings to compare with.
			We will only test encode-and-verify cases instead.
		*/
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

func TestHasher_Validate(t *testing.T) {
	opts := &ValidationOpts{
		MinRounds: 1000,
		MaxRounds: 1000000,
	}
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
			name: "ok",
			args: args{
				encoded: `$pbkdf2$1200$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name: "parse error",
			args: args{
				encoded: Prefix + "!!!",
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "rounds too low",
			args: args{
				encoded: `$pbkdf2$999$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "rounds too high",
			args: args{
				encoded: `$pbkdf2$1000001$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewSHA1(RecommendedSHA1Params, opts)
			got, err := h.Validate(tt.args.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verifier.Validate() = %v, want %v", got, tt.want)
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
			name: "parse error",
			h: Hasher{
				p: testParamsSha1,
			},
			args: args{
				Prefix + "!!!",
				tv.Password,
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "sha1, wrong password",
			h: Hasher{
				p: testParamsSha1,
			},
			args: args{
				tv.Pbkdf2Sha1Encoded,
				"wrong",
			},
			want: verifier.Fail,
		},
		{
			name: "sha256, wrong password",
			h: Hasher{
				p: testParamsSha256,
			},
			args: args{
				tv.Pbkdf2Sha256Encoded,
				"wrong",
			},
			want: verifier.Fail,
		},
		{
			name: "sha512, wrong password",
			h: Hasher{
				p: testParamsSha512,
			},
			args: args{
				tv.Pbkdf2Sha512Encoded,
				"wrong",
			},
			want: verifier.Fail,
		},
		{
			name: "sha1, ok",
			h: Hasher{
				p: testParamsSha1,
			},
			args: args{
				tv.Pbkdf2Sha1Encoded,
				tv.Password,
			},
			want: verifier.OK,
		},
		{
			name: "sha256, ok",
			h: Hasher{
				p: testParamsSha256,
			},
			args: args{
				tv.Pbkdf2Sha256Encoded,
				tv.Password,
			},
			want: verifier.OK,
		},
		{
			name: "sha256, padded, ok",
			h: Hasher{
				p: testParamsSha256,
			},
			args: args{
				tv.Pbkdf2Sha256StdEncodedPadding,
				tv.Password,
			},
			want: verifier.OK,
		},
		{
			name: "sha512, ok",
			h: Hasher{
				p: testParamsSha512,
			},
			args: args{
				tv.Pbkdf2Sha512Encoded,
				tv.Password,
			},
			want: verifier.OK,
		},
		{
			name: "hasher update",
			h: Hasher{
				p: testParamsSha512,
			},
			args: args{
				tv.Pbkdf2Sha1Encoded,
				tv.Password,
			},
			want: verifier.NeedUpdate,
		},
		{
			name: "rounds update",
			h: Hasher{
				p: Params{
					Rounds:  tv.Pbkdf2Rounds + 1,
					SaltLen: tv.SaltLen,
					KeyLen:  tv.Pbkdf2Sha512KeyLen,
					id:      IdentifierSHA512,
				},
			},
			args: args{
				tv.Pbkdf2Sha512Encoded,
				tv.Password,
			},
			want: verifier.NeedUpdate,
		},
		{
			name: "KeyLen update",
			h: Hasher{
				p: Params{
					Rounds:  tv.Pbkdf2Rounds,
					SaltLen: tv.SaltLen,
					KeyLen:  tv.Pbkdf2Sha512KeyLen + 1,
					id:      IdentifierSHA512,
				},
			},
			args: args{
				tv.Pbkdf2Sha512Encoded,
				tv.Password,
			},
			want: verifier.NeedUpdate,
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
	params := Params{
		Rounds:  tv.Pbkdf2Rounds,
		SaltLen: tv.SaltLen,
		KeyLen:  tv.Pbkdf2Sha512KeyLen,
	}
	tests := [...]*Hasher{
		NewSHA1(params, nil),
		NewSHA224(params, nil),
		NewSHA256(params, nil),
		NewSHA384(params, nil),
		NewSHA512(params, nil),
	}
	for _, h := range tests {
		t.Run(h.p.id, func(t *testing.T) {
			hash, err := h.Hash(tv.Password)
			if err != nil {
				t.Fatal(err)
			}
			t.Log(hash)
			if !strings.Contains(hash, h.p.id) {
				t.Errorf("Hasher.Hash() = %s, does not contain %s", hash, h.p.id)
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

func Test_checkValidationOpts(t *testing.T) {
	tests := []struct {
		name string
		opts *ValidationOpts
		want *ValidationOpts
	}{
		{
			name: "nil opts",
			opts: nil,
			want: DefaultValidationOpts,
		},
		{
			name: "empty opts",
			opts: &ValidationOpts{},
			want: DefaultValidationOpts,
		},
		{
			name: "only min set",
			opts: &ValidationOpts{
				MinRounds: 5000,
			},
			want: &ValidationOpts{
				MinRounds: 5000,
				MaxRounds: DefaultValidationOpts.MaxRounds,
			},
		},
		{
			name: "both set",
			opts: &ValidationOpts{
				MinRounds: 2000,
				MaxRounds: 2000000,
			},
			want: &ValidationOpts{
				MinRounds: 2000,
				MaxRounds: 2000000,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkValidationOpts(tt.opts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkValidationOpts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	opts := &ValidationOpts{
		MinRounds: 1000,
		MaxRounds: 1000000,
	}
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
			name: "ok",
			args: args{
				encoded: `$pbkdf2$1200$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name: "parse error",
			args: args{
				encoded: Prefix + "!!!",
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "rounds too low",
			args: args{
				encoded: `$pbkdf2$999$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "rounds too high",
			args: args{
				encoded: `$pbkdf2$1000001$cmFuZG9tc2FsdGlzaGFyZA$mwUqsMixIYMc/0eN4v1.l3SVDpk`,
			},
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(opts)
			got, err := v.Validate(tt.args.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verifier.Validate() = %v, want %v", got, tt.want)
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
			name: "parse error",
			args: args{
				Prefix + "!!!",
				tv.Password,
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "sha1, wrong password",
			args: args{
				tv.Pbkdf2Sha1Encoded,
				"wrong",
			},
			want: verifier.Fail,
		},
		{
			name: "sha256, ok",
			args: args{
				tv.Pbkdf2Sha256Encoded,
				tv.Password,
			},
			want: verifier.OK,
		},
		{
			name: "sha256, padded, ok",
			args: args{
				tv.Pbkdf2Sha256StdEncodedPadding,
				tv.Password,
			},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(nil)
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
