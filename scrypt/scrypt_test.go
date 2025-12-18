package scrypt

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/passwap/internal/salt"
	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
)

var (
	testParams = Params{
		LN:      tv.ScryptLN,
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
			name:    "skip",
			encoded: "foobar",
		},
		{
			name:    "scan error",
			encoded: "$scrypt$!!!!",
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

func TestHasher_Validate(t *testing.T) {
	testOpts := &ValidationOpts{
		MinLN: 4,
		MaxLN: 16,
		MinR:  2,
		MaxR:  6,
		MinP:  4,
		MaxP:  16,
	}
	tests := []struct {
		name    string
		opts    *ValidationOpts
		encoded string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "parse error",
			opts:    testOpts,
			encoded: "$scrypt$!!!!",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "success",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.OK,
		},
		{
			name:    "LN too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=1,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "LN too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=17,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "r too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=1,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "r too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=7,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "p too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=2$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "p too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=17$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "p * r too large",
			opts: &ValidationOpts{
				MaxR: 1 << 30,
				MaxP: 1 << 30,
			},
			encoded: `$scrypt$ln=16,r=33000,p=33000$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(testParams, tt.opts)
			got, err := v.Validate(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
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
			args:    args{"$scrypt$!!!!", tv.Password},
			want:    verifier.Skip,
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
				LN:      tv.ScryptLN + 1,
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

func TestHasher(t *testing.T) {
	h := New(testParams, nil)
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
			name: "partial opts",
			opts: &ValidationOpts{
				MinLN: 10,
			},
			want: &ValidationOpts{
				MinLN: 10,
				MaxLN: DefaultMaxLN,
				MinR:  DefaultMinR,
				MaxR:  DefaultMaxR,
				MinP:  DefaultMinP,
				MaxP:  DefaultMaxP,
			},
		},
		{
			name: "full opts",
			opts: &ValidationOpts{
				MinLN: 10,
				MaxLN: 15,
				MinR:  3,
				MaxR:  5,
				MinP:  6,
				MaxP:  12,
			},
			want: &ValidationOpts{
				MinLN: 10,
				MaxLN: 15,
				MinR:  3,
				MaxR:  5,
				MinP:  6,
				MaxP:  12,
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
	testOpts := &ValidationOpts{
		MinLN: 4,
		MaxLN: 16,
		MinR:  2,
		MaxR:  6,
		MinP:  4,
		MaxP:  16,
	}
	tests := []struct {
		name    string
		opts    *ValidationOpts
		encoded string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "parse error",
			opts:    testOpts,
			encoded: "$scrypt$!!!!",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "success",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.OK,
		},
		{
			name:    "N too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=1,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "N too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=17,r=4,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "r too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=1,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "r too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=7,p=5$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "p too small",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=2$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "p too large",
			opts:    testOpts,
			encoded: `$scrypt$ln=10,r=4,p=17$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "p * r too large",
			opts: &ValidationOpts{
				MaxR: 1 << 30,
				MaxP: 1 << 30,
			},
			encoded: `$scrypt$ln=16,r=33000,p=33000$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ`,
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(tt.opts)
			got, err := v.Validate(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
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
			name:    "parse error",
			args:    args{"$scrypt$!!!!", tv.Password},
			want:    verifier.Skip,
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
