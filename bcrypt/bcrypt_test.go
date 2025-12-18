package bcrypt

import (
	"crypto/rand"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/verifier"
	"golang.org/x/crypto/bcrypt"
)

func Test_hasBcryptVersion(t *testing.T) {
	type args struct {
		encoded string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "wrong prefix",
			args: args{testvalues.Argon2idEncoded},
			want: false,
		},
		{
			name: "version 2a",
			args: args{testvalues.EncodedBcrypt2a},
			want: true,
		},
		{
			name: "version 2b",
			args: args{testvalues.EncodedBcrypt2b},
			want: true,
		},
		{
			name: "version 2y",
			args: args{testvalues.EncodedBcrypt2y},
			want: true,
		},
		{
			name: "unsupported version",
			args: args{strings.ReplaceAll(testvalues.EncodedBcrypt2b, "$2b$", "$2e$")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasBcryptVersion([]byte(tt.args.encoded)); got != tt.want {
				t.Errorf("hasBcryptVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_compareHashAndPassword(t *testing.T) {
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
			name: "success",
			args: args{testvalues.EncodedBcrypt2b, testvalues.Password},
			want: verifier.OK,
		},
		{
			name: "wrong password",
			args: args{testvalues.EncodedBcrypt2b, "foobar"},
			want: verifier.Fail,
		},
		{
			name: "prefix error",
			args: args{
				strings.ReplaceAll(
					testvalues.EncodedBcrypt2b,
					"$2b$", "_2b$",
				),
				testvalues.Password,
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name: "hash version error",
			args: args{
				strings.ReplaceAll(
					testvalues.EncodedBcrypt2b,
					"$2b$", "$3b$",
				),
				testvalues.Password,
			},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "other error",
			args:    args{"$2b$foo", testvalues.Password},
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compareHashAndPassword([]byte(tt.args.encoded), []byte(tt.args.password))
			if (err != nil) != tt.wantErr {
				t.Errorf("compareHashAndPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("compareHashAndPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_Hash(t *testing.T) {
	type args struct {
		password string
	}
	tests := []struct {
		name    string
		args    args
		reader  io.Reader
		wantErr bool
	}{
		{
			name:    "salt error",
			args:    args{testvalues.Password},
			reader:  salt.ErrReader{},
			wantErr: true,
		},
		{
			name:   "success",
			args:   args{testvalues.Password},
			reader: rand.Reader,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(testvalues.BcryptCost, nil)

			oldReader := rand.Reader
			rand.Reader = tt.reader
			defer func() { rand.Reader = oldReader }()

			got, err := h.Hash(tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hasher.Hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				err = bcrypt.CompareHashAndPassword([]byte(got), []byte(tt.args.password))
				if err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHasher_Validate(t *testing.T) {
	opts := &ValidationOpts{
		MinCost: 10,
		MaxCost: 12,
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
			name:    "not bcrypt",
			args:    args{testvalues.ScryptEncoded},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "cost error",
			args:    args{"$2b$foo"},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "cost too low",
			args:    args{`$2b$09$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "cost too high",
			args:    args{`$2b$16$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "valid cost",
			args: args{`$2b$12$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := New(2, opts)
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

func TestHasher_Verify(t *testing.T) {
	type fields struct {
		cost int
	}
	type args struct {
		encoded  string
		password string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "not bcrypt",
			fields:  fields{testvalues.BcryptCost},
			args:    args{testvalues.ScryptEncoded, testvalues.Password},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "cost error",
			fields:  fields{testvalues.BcryptCost},
			args:    args{"$2b$foo", testvalues.Password},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:   "succes 2a",
			fields: fields{testvalues.BcryptCost},
			args:   args{testvalues.EncodedBcrypt2a, testvalues.Password},
			want:   verifier.OK,
		},
		{
			name:   "succes 2b",
			fields: fields{testvalues.BcryptCost},
			args:   args{testvalues.EncodedBcrypt2b, testvalues.Password},
			want:   verifier.OK,
		},
		{
			name:   "succes 2y",
			fields: fields{testvalues.BcryptCost},
			args:   args{testvalues.EncodedBcrypt2y, testvalues.Password},
			want:   verifier.OK,
		},
		{
			name:   "wrong password",
			fields: fields{testvalues.BcryptCost},
			args:   args{testvalues.EncodedBcrypt2b, "foobar"},
			want:   verifier.Fail,
		},
		{
			name:   "update",
			fields: fields{13},
			args:   args{testvalues.EncodedBcrypt2b, testvalues.Password},
			want:   verifier.NeedUpdate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(tt.fields.cost, nil)
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

func Test_checkValidaionOpts(t *testing.T) {
	type args struct {
		opts *ValidationOpts
	}
	tests := []struct {
		name string
		args args
		want *ValidationOpts
	}{
		{
			name: "nil opts",
			args: args{nil},
			want: &DefaultValidationOpts,
		},
		{
			name: "empty opts",
			args: args{&ValidationOpts{}},
			want: &DefaultValidationOpts,
		},
		{
			name: "zero min cost",
			args: args{&ValidationOpts{
				MinCost: 0,
				MaxCost: 15,
			}},
			want: &ValidationOpts{
				MinCost: DefaultValidationOpts.MinCost,
				MaxCost: 15,
			},
		},
		{
			name: "zero max cost",
			args: args{&ValidationOpts{
				MinCost: 10,
				MaxCost: 0,
			}},
			want: &ValidationOpts{
				MinCost: 10,
				MaxCost: DefaultValidationOpts.MaxCost,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkValidaionOpts(tt.args.opts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkValidaionOpts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	opts := &ValidationOpts{
		MinCost: 10,
		MaxCost: 12,
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
			name:    "not bcrypt",
			args:    args{testvalues.ScryptEncoded},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "cost error",
			args:    args{"$2b$foo"},
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "cost too low",
			args:    args{`$2b$09$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "cost too high",
			args:    args{`$2b$16$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name: "valid cost",
			args: args{`$2b$12$bIRGj4QPPoSUMWsJE.4Pk.T1qTpDWz7HhMnuiQhGzGinKPsx/HQdq`},
			want: verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(opts)
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
			name: "not bcrypt",
			args: args{testvalues.ScryptEncoded, testvalues.Password},
			want: verifier.Skip,
		},
		{
			name: "succes 2a",
			args: args{testvalues.EncodedBcrypt2a, testvalues.Password},
			want: verifier.OK,
		},
		{
			name: "succes 2b",
			args: args{testvalues.EncodedBcrypt2b, testvalues.Password},
			want: verifier.OK,
		},
		{
			name: "succes 2y",
			args: args{testvalues.EncodedBcrypt2y, testvalues.Password},
			want: verifier.OK,
		},
		{
			name: "wrong password",
			args: args{testvalues.EncodedBcrypt2b, "foobar"},
			want: verifier.Fail,
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
