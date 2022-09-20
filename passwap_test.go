package passwap

import (
	"reflect"
	"testing"

	"github.com/muhlemmer/passwap/argon2"
	tv "github.com/muhlemmer/passwap/internal/testvalues"
	"github.com/muhlemmer/passwap/verifier"
)

var (
	buggyV = verifier.NewFunc("buggy", func(string, string) (verifier.Result, error) {
		return 99, nil
	})
	testArgon2Params = argon2.Params{
		Time:    tv.Argon2Time,
		Memory:  tv.Argon2Memory,
		Threads: tv.Argon2Threads,
		KeyLen:  tv.KeyLen,
		SaltLen: tv.SaltLen,
	}
	testHasher  = argon2.NewArgon2id(testArgon2Params)
	testSwapper = NewSwapper(testHasher, argon2.Argon2i, buggyV)
)

func TestNewSwapper(t *testing.T) {
	want := &Swapper{
		id:        argon2.Identifier_id,
		h:         testHasher,
		verifiers: verifier.IDMap{argon2.Argon2i.ID(): argon2.Argon2i},
	}
	if got := NewSwapper(testHasher, argon2.Argon2i); !reflect.DeepEqual(got, want) {
		t.Errorf("NewSwapper() = %v, want %v", got, want)
	}
}

func TestSwapper_assertVerifier(t *testing.T) {
	tests := []struct {
		name           string
		encoded        string
		want           verifier.Verifier
		wantNeedUpdate bool
		wantErr        bool
	}{
		{
			name:    "No identifier",
			encoded: "foo",
			wantErr: true,
		},
		{
			name:    "primary",
			encoded: tv.Argon2idEncoded,
			want:    testHasher,
		},
		{
			name:           "verifier",
			encoded:        tv.Argon2iEncoded,
			want:           argon2.Argon2i,
			wantNeedUpdate: true,
		},
		{
			name:    "unknown",
			encoded: `$foo$bar`,
			wantErr: true,
		},
		{
			name:    "wrong match",
			encoded: `$$foo$$bar`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, needUpdate, err := testSwapper.assertVerifier(tt.encoded)
			if (err != nil) != tt.wantErr {
				t.Errorf("Swapper.assertVerifier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Swapper.assertVerifier() = %v, want %v", got, tt.want)
			}
			if needUpdate != tt.wantNeedUpdate {
				t.Errorf("Swapper.assertVerifier() needUpdate = %v, want %v", needUpdate, tt.wantNeedUpdate)
			}
		})
	}
}

func TestSwapper_Verify(t *testing.T) {
	type args struct {
		encoded  string
		password string
	}
	tests := []struct {
		name        string
		args        args
		wantUpdated bool
		wantErr     bool
	}{
		{
			name:    "assert error",
			args:    args{"foobar", tv.Password},
			wantErr: true,
		},
		{
			name:    "argon2 parse error",
			args:    args{"$argon2id$foo", tv.Password},
			wantErr: true,
		},
		{
			name:    "wrong password",
			args:    args{tv.Argon2iEncoded, "foobar"},
			wantErr: true,
		},
		{
			name: "ok",
			args: args{tv.Argon2idEncoded, tv.Password},
		},
		{
			name:        "assert update",
			args:        args{tv.Argon2iEncoded, tv.Password},
			wantUpdated: true,
		},
		{
			name: "verifier update",
			args: args{
				`$argon2id$v=19$m=1024,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$XEb5L9sMPxmHWcLjtNCnz0cn826ATCditca7qt3nSxM`,
				tv.Password,
			},
			wantUpdated: true,
		},
		{
			name:    "buggy verifier",
			args:    args{`$buggy$stuff`, tv.Password},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUpdated, err := testSwapper.Verify(tt.args.encoded, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Swapper.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (gotUpdated != "") != tt.wantUpdated {
				t.Errorf("Swapper.Verify() = %v, want %v", gotUpdated, tt.wantUpdated)
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
