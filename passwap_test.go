package passwap

import (
	"errors"
	"reflect"
	"testing"

	"github.com/zitadel/passwap/argon2"
	tv "github.com/zitadel/passwap/internal/testvalues"
	"github.com/zitadel/passwap/scrypt"
	"github.com/zitadel/passwap/verifier"
)

var (
	mockV = verifier.VerifyFunc(func(encoded string, password string) (verifier.Result, error) {
		switch encoded {
		case "$mock$bug":
			return 99, nil
		case "$mock$failErr":
			return verifier.Fail, errors.New("oops!")
		case "$argon2id$multi":
			return verifier.Skip, errors.New("oops!")
		default:
			return verifier.Skip, nil
		}
	})

	testArgon2Params = argon2.Params{
		Time:    tv.Argon2Time,
		Memory:  tv.Argon2Memory,
		Threads: tv.Argon2Threads,
		KeyLen:  tv.KeyLen,
		SaltLen: tv.SaltLen,
	}
	testHasher  = argon2.NewArgon2id(testArgon2Params)
	testSwapper = NewSwapper(testHasher, mockV, scrypt.Verifier)
)

func TestNewSwapper(t *testing.T) {
	want := &Swapper{
		h:         testHasher,
		verifiers: []verifier.Verifier{testHasher, argon2.Verifier},
	}
	if got := NewSwapper(testHasher, argon2.Verifier); !reflect.DeepEqual(got.h, want.h) || len(got.verifiers) != len(want.verifiers) {
		t.Errorf("NewSwapper() = %v, want %v", got, want)
	}
}

func TestMultiError(t *testing.T) {
	const (
		want = "passwap multiple parse errors: foo; bar"
	)

	errs := SkipErrors{errors.New("foo"), errors.New("bar")}
	if got := errs.Error(); got != want {
		t.Errorf("MultiError =\n%s\nwant\n%s", got, want)
	}
}

func TestSwapper_Verify(t *testing.T) {
	gotUpdated, err := testSwapper.Verify(tv.Argon2iEncoded, tv.Password)
	if err != nil {
		t.Errorf("Swapper.Verify() error = %v", err)
		return
	}
	if gotUpdated == "" {
		t.Error("Swapper.Verify() did not return updated")
	}
}

func TestSwapper_VerifyAndUpdate(t *testing.T) {
	type args struct {
		encoded     string
		oldPassword string
		newPassword string
	}
	tests := []struct {
		name        string
		args        args
		wantUpdated bool
		wantErr     error
	}{
		{
			name:    "no update",
			args:    args{tv.Argon2idEncoded, tv.Password, tv.Password},
			wantErr: ErrPasswordNoChange,
		},
		{
			name:        "update",
			args:        args{tv.Argon2idEncoded, tv.Password, "newpassword"},
			wantUpdated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUpdated, err := testSwapper.VerifyAndUpdate(tt.args.encoded, tt.args.oldPassword, tt.args.newPassword)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Swapper.VerifyAndUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotUpdated != "") != tt.wantUpdated {
				t.Errorf("Swapper.VerifyAndUpdate() = %v, want %v", gotUpdated, tt.wantUpdated)
			}
		})
	}
}

func TestSwapper_verifyAndUpdate(t *testing.T) {
	type args struct {
		encoded     string
		oldPassword string
		newPassword string
	}
	tests := []struct {
		name        string
		args        args
		wantUpdated bool
		wantErr     bool
	}{
		{
			name:    "no verifier",
			args:    args{"foobar", tv.Password, tv.Password},
			wantErr: true,
		},
		{
			name:    "argon2 parse error",
			args:    args{"$argon2id$foo", tv.Password, tv.Password},
			wantErr: true,
		},
		{
			name:    "wrong password",
			args:    args{tv.Argon2iEncoded, "foobar", tv.Password},
			wantErr: true,
		},
		{
			name: "ok",
			args: args{tv.Argon2idEncoded, tv.Password, tv.Password},
		},
		{
			name:        "password update",
			args:        args{tv.Argon2idEncoded, tv.Password, "newpassword"},
			wantUpdated: true,
		},
		{
			name:        "argon2 update",
			args:        args{tv.Argon2iEncoded, tv.Password, tv.Password},
			wantUpdated: true,
		},
		{
			name:        "hasher upgrade",
			args:        args{tv.ScryptEncoded, tv.Password, tv.Password},
			wantUpdated: true,
		},
		{
			name:    "fail with error",
			args:    args{`$mock$failErr`, tv.Password, tv.Password},
			wantErr: true,
		},
		{
			name:    "verifier bug",
			args:    args{`$mock$bug`, tv.Password, tv.Password},
			wantErr: true,
		},
		{
			name:    "multiple errors",
			args:    args{"$argon2id$multi", tv.Password, tv.Password},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUpdated, err := testSwapper.verifyAndUpdate(tt.args.encoded, tt.args.oldPassword, tt.args.newPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("Swapper.verifyAndUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotUpdated != "") != tt.wantUpdated {
				t.Errorf("Swapper.verifyAndUpdate() = %v, want %v", gotUpdated, tt.wantUpdated)
			}
		})
	}
}

func TestSwapper(t *testing.T) {
	var (
		updated string
		err     error
	)

	// Use "outdated" argon2i to trigger update
	t.Run("update", func(t *testing.T) {
		updated, err = testSwapper.Verify(tv.Argon2iEncoded, tv.Password)
		if err != nil {
			t.Fatal(err)
		}
		if updated == "" {
			t.Fatal("Swapp.Verify: updated empty")
		}
	})

	// Verify updated hash again, should be valid and without update
	t.Run("no update", func(t *testing.T) {
		updated, err = testSwapper.Verify(updated, tv.Password)
		if err != nil {
			t.Fatal(err)
		}
		if updated != "" {
			t.Fatalf("Swapp.Verify: updated = %s", updated)
		}
	})
}
