package scrypt

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/muhlemmer/passwap/internal/salt"
	tv "github.com/muhlemmer/passwap/internal/testvalues"
	"github.com/muhlemmer/passwap/verifier"
)

var (
	testParams = Params{
		N:       tv.ScryptN,
		R:       tv.ScryptR,
		P:       tv.ScryptP,
		KeyLen:  tv.KeyLen,
		SaltLen: tv.SaltLen,
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
			name:    "scan error",
			encoded: "foobar",
			wantErr: true,
		},
		{
			name:    "identifier error",
			encoded: strings.ReplaceAll(tv.ScryptEncoded, "scrypt", "foo"),
			wantErr: true,
		},
		{
			name:    "salt error",
			encoded: strings.ReplaceAll(tv.ScryptEncoded, "cmFuZG9tc2FsdGlzaGFyZA", "!!!"),
			wantErr: true,
		},
		{
			name:    "salt error",
			encoded: strings.ReplaceAll(tv.ScryptEncoded, "Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ", "!!!"),
			wantErr: true,
		},
		{
			name:    "succes",
			encoded: tv.ScryptEncoded,
			want: &checker{
				Params: testParams,
				hash:   tv.ScryptHash,
				salt:   []byte(tv.Salt),
			},
		},
		{
			name:    "linux",
			encoded: strings.ReplaceAll(tv.ScryptEncoded, "scrypt", "7"),
			want: &checker{
				Params: testParams,
				hash:   tv.ScryptHash,
				salt:   []byte(tv.Salt),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parse() =\n%v\nwant\n%v", got, tt.want)
			}
		})
	}
}

func Test_checker_verify(t *testing.T) {
	tests := []struct {
		name    string
		N       int
		pw      string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "scrypt error",
			N:       1,
			pw:      tv.Password,
			wantErr: true,
		},
		{
			name: "wrong password",
			pw:   "foo",
			want: verifier.Fail,
		},
		{
			name: "correct password",
			pw:   tv.Password,
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &checker{
				Params: testParams,
				hash:   tv.ScryptHash,
				salt:   []byte(tv.Salt),
			}
			if tt.N != 0 {
				c.Params.N = tt.N
			}

			got, err := c.verify(tt.pw)
			if (err != nil) != tt.wantErr {
				t.Errorf("checker.verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_Hash(t *testing.T) {
	tests := []struct {
		name    string
		N       int
		rand    io.Reader
		want    string
		wantErr bool
	}{
		{
			name:    "salt error",
			rand:    salt.ErrReader{},
			wantErr: true,
		},
		{
			name:    "scrypt error",
			N:       1,
			rand:    tv.SaltReader(),
			wantErr: true,
		},
		{
			name: "succes",
			rand: tv.SaltReader(),
			want: tv.ScryptEncoded,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hasher{
				p:    testParams,
				rand: tt.rand,
			}
			if tt.N != 0 {
				h.p.N = tt.N
			}

			got, err := h.Hash(tv.Password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Hasher.Hash() =\n%v\nwant\n%v", got, tt.want)
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
		p       Params
		args    args
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "parse error",
			p:       testParams,
			args:    args{"foo", tv.Password},
			wantErr: true,
		},
		{
			name: "wrong password",
			p:    testParams,
			args: args{tv.ScryptEncoded, "foo"},
			want: verifier.Fail,
		},
		{
			name: "need update",
			p: Params{
				N:       tv.ScryptN * 2,
				R:       tv.ScryptR,
				P:       tv.ScryptP,
				KeyLen:  tv.KeyLen,
				SaltLen: tv.SaltLen,
			},
			args: args{tv.ScryptEncoded, tv.Password},
			want: verifier.NeedUpdate,
		},
		{
			name: "succes",
			p:    testParams,
			args: args{tv.ScryptEncoded, tv.Password},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hasher{
				p:    tt.p,
				rand: tv.SaltReader(),
			}
			got, err := h.Verify(tt.args.encoded, tt.args.password)
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
	if got := new(Hasher).ID(); got != Identifier {
		t.Errorf("Hasher.ID = %s, want %s", got, Identifier)
	}
}

func TestHasher(t *testing.T) {
	h := New(testParams)
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
			name:    "parse error",
			args:    args{"foo", tv.Password},
			wantErr: true,
		},
		{
			name: "wrong password",
			args: args{tv.ScryptEncoded, "foo"},
			want: verifier.Fail,
		},
		{
			name: "success",
			args: args{tv.ScryptEncoded, tv.Password},
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
