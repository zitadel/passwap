package passwap

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"
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

func Example() {
	// Create a new swapper which hashes using bcrypt,
	// verifies and upgrades scrypt.
	passwords := NewSwapper(
		bcrypt.New(bcrypt.DefaultCost),
		scrypt.Verifier,
	)

	// Create an encoded bcrypt hash string of password with salt.
	encoded, err := passwords.Hash("good_password")
	if err != nil {
		panic(err)
	}
	fmt.Println(encoded)
	// $2a$10$eS.mS5Zc5YAJFlImXCpLMu9TxXwKUhgQxsbghlvyVwvwYO/17E2qy

	// Replace the swapper to hash using argon2id,
	// verifies and upgrades scrypt and bcrypt.
	passwords = NewSwapper(
		argon2.NewArgon2id(argon2.RecommendedIDParams),
		bcrypt.Verifier,
		scrypt.Verifier,
	)

	// Attempt to verify encoded bcrypt string with a wrong password.
	// Returns an error and empty "updated"
	if updated, err := passwords.Verify(encoded, "wrong_password"); err != nil {
		fmt.Println(err)
		// passwap: password does not match hash
	} else if updated != "" {
		encoded = updated
	}
	fmt.Println(encoded)
	// $2a$10$eS.mS5Zc5YAJFlImXCpLMu9TxXwKUhgQxsbghlvyVwvwYO/17E2qy
	// encoded is unchanged.

	// Verify encoded bcrypt string with a good password.
	// Returns a new encoded string with argon2id hash
	// of password and new random salt.
	if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
		panic(err)
	} else if updated != "" {
		encoded = updated
	}
	fmt.Println(encoded)
	// $argon2id$v=19$m=65536,t=1,p=4$d6SOdxdIip9BC7sM5H7PUQ$2E7OIz7C1NkMLOsXi5nSe5vfbthdc9N9SWVlArd200E
	// encoded is updated.

	// Verify encoded argon2 string with a good password.
	// "updated" now is empty because the parameters of the Hasher
	// match the one in the encoded string.
	if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
		panic(err)
	} else if updated != "" { // updated is empty, nothing is stored
		encoded = updated
	}
	fmt.Println(encoded)
	// $argon2id$v=19$m=65536,t=1,p=4$d6SOdxdIip9BC7sM5H7PUQ$2E7OIz7C1NkMLOsXi5nSe5vfbthdc9N9SWVlArd200E
	// encoded in unchanged.

	// Replace the swapper again. This time we still
	// use argon2id, but increased the Time parameter.
	passwords = NewSwapper(
		argon2.NewArgon2id(argon2.Params{
			Time:    2,
			Memory:  64 * 1024,
			Threads: 4,
			KeyLen:  32,
			SaltLen: 16,
		}),
		bcrypt.Verifier,
		scrypt.Verifier,
	)

	// Verify encoded argon2id string with a good password.
	// Returns a new encoded string with argon2id hash
	// of password and new random salt,
	// because of paremeter mis-match.
	if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
		panic(err)
	} else if updated != "" {
		encoded = updated
	}
	fmt.Println(encoded)
	// $argon2id$v=19$m=65536,t=2,p=4$44X+dwU+aSS85Kl1qH3/Jg$n/tQoAtx/I/Rt9BXHH9tScshWucltPPmB0HBLVtXCq0
	// encoded is updated.
}
