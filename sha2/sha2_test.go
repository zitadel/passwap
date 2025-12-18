package sha2

import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/zitadel/passwap/internal/salt"
	"github.com/zitadel/passwap/verifier"
)

// test cases taken from https://www.akkadia.org/drepper/SHA-crypt.txt
func Test_createHash512(t *testing.T) {
	type args struct {
		password string
		salt     string
		rounds   int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "basic",
			args: args{"Hello world!", "saltstring", 5000},
			want: "$6$rounds=5000$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
		},
		{
			name: "10000 rounds and long salt",
			args: args{"Hello world!", "saltstringsaltstring", 10000},
			want: "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.",
		},
		{
			name: "long salt",
			args: args{"This is just a test", "toolongsaltstring", 5000},
			want: "$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0",
		},
		{
			name: "long password and long salt",
			args: args{"a very much longer text to encrypt.  This one even stretches over morethan one line.", "anotherlongsaltstring", 1400},
			want: "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1",
		},
		{
			name: "short salt",
			args: args{"we have a short salt string but not a short password", "short", 77777},
			want: "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0",
		},
		{
			name: "short password",
			args: args{"a short string", "asaltof16chars..", 123456},
			want: "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1",
		},
		{
			name: "low rounds",
			args: args{"the minimum number is still observed", "roundstoolow", 10},
			want: "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := createHash(true, []byte(tt.args.password), []byte(tt.args.salt), tt.args.rounds)
			if !bytes.Equal(hash, []byte(tt.want)) {
				t.Errorf("createHash() = %v, want %v", string(hash), (tt.want))
			}
		})
	}
}

// test cases taken from https://www.akkadia.org/drepper/SHA-crypt.txt
func Test_createHash256(t *testing.T) {
	type args struct {
		password string
		salt     string
		rounds   int
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "basic",
			args: args{"Hello world!", "saltstring", 5000},
			want: "$5$rounds=5000$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5",
		},
		{
			name: "10000 rounds and long salt",
			args: args{"Hello world!", "saltstringsaltstring", 10000},
			want: "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA",
		},
		{
			name: "long salt",
			args: args{"This is just a test", "toolongsaltstring", 5000},
			want: "$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5",
		},
		{
			name: "long password and long salt",
			args: args{"a very much longer text to encrypt.  This one even stretches over morethan one line.", "anotherlongsaltstring", 1400},
			want: "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1",
		},
		{
			name: "short salt",
			args: args{"we have a short salt string but not a short password", "short", 77777},
			want: "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/",
		},
		{
			name: "short password",
			args: args{"a short string", "asaltof16chars..", 123456},
			want: "$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD",
		},
		{
			name: "low rounds",
			args: args{"the minimum number is still observed", "roundstoolow", 10},
			want: "$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := createHash(false, []byte(tt.args.password), []byte(tt.args.salt), tt.args.rounds)
			if !bytes.Equal(hash, []byte(tt.want)) {
				t.Errorf("createHash() = %v, want %v", string(hash), (tt.want))
			}
		})
	}
}

func Test_calcRounds(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{2000, 2000},
		{1000, 1000},
		{999999999, 999999999},
		{4, RoundsMin},
		{1000000000, RoundsMax},
	}

	for _, tt := range tests {
		got := calcRounds(tt.input)
		if got != tt.want {
			t.Errorf("calcRounds() got = %v, want %v", got, tt.want)
		}
	}
}

func Test_parse(t *testing.T) {
	tests := []struct {
		input   string
		use512  bool
		rounds  int
		salt    string
		encoded string
		wantErr bool
	}{
		{"$6$rounds=10000$somesalt$hashvaluehere", true, 10000, "somesalt", "hashvaluehere", false},
		{"$5$saltvalue$hasheddata", false, RoundsDefault, "saltvalue", "hasheddata", false},
		{"$6$salt$encodedhash", true, RoundsDefault, "salt", "encodedhash", false},
		{"$5$rounds=20000$salt$hash", false, 20000, "salt", "hash", false},
		{"$2$rounds=10000$somesalt$hashvaluehere", false, RoundsDefault, "", "", true},  // Invalid identiefier
		{"$6$rounds=abc$salt$hash", false, RoundsDefault, "", "", true},                 // Invalid rounds
		{"$6$salt", false, RoundsDefault, "", "", true},                                 // Missing encoded part
		{"invalidhash", false, RoundsDefault, "", "", true},                             // Completely invalid format
		{"$6$rounds=10000$some$salt$hashvaluehere", false, RoundsDefault, "", "", true}, // Too many $
	}

	for _, tt := range tests {
		c, err := parse(tt.input)

		if (err != nil) != tt.wantErr {
			t.Errorf("parse(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			return
		}

		if c != nil {
			if c.use512 != tt.use512 {
				t.Errorf("parse(%q) use512 = %v, want %v", tt.input, c.use512, tt.use512)
			}

			if c.rounds != tt.rounds {
				t.Errorf("parse(%q) rounds = %v, want %v", tt.input, c.rounds, tt.rounds)
			}

			if string(c.salt) != tt.salt {
				t.Errorf("parse(%q) salt = %q, want %q", tt.input, c.salt, tt.salt)
			}

			if string(c.hash) != tt.input {
				t.Errorf("parse(%q) encoded = %q, want %q", tt.input, c.hash, tt.input)
			}
		}
	}
}

func Test_checker_verify(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     verifier.Result
		wantErr  bool
	}{
		{
			name:     "wrong password",
			password: "foo",
			want:     verifier.Fail,
		},
		{
			name:     "correct password",
			password: "password",
			want:     verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := &checker{
				use512: true,
				rounds: 5000,
				hash:   []byte("$6$rounds=5000$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g."),
				salt:   []byte("salt"),
			}

			if got := checker.verify(tt.password); got != tt.want {
				t.Errorf("checker.verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasher_Hash(t *testing.T) {
	tests := []struct {
		name    string
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
			rand: strings.NewReader("saltsaltsaltsalt"),
			want: "$6$rounds=10000$n34PoBLMgFrQVl4R$7.cb7CLz8wagvy7HkLZ8dcil04pgps4hbri2LxtxwEUvf82JeV07F65sPWlHuwPBoVO6q49Az1vHmyvfmxw6Z/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hasher{
				use512: true,
				rounds: 10000,
				rand:   tt.rand,
			}

			got, err := h.Hash("foobar")
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
	tests := []struct {
		name    string
		encoded string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "parse error",
			encoded: "totallywrongformat",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "valid sha512",
			encoded: "$6$rounds=3$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name:    "valid sha256",
			encoded: "$5$rounds=7$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name:    "sha256 too low rounds",
			encoded: "$5$rounds=1$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha256 too high rounds",
			encoded: "$5$rounds=11$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha512 too low rounds",
			encoded: "$6$rounds=1$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha512 too high rounds",
			encoded: "$6$rounds=11$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &ValidationOpts{
				MinSha256Rounds: 5,
				MaxSha256Rounds: 10,
				MinSha512Rounds: 2,
				MaxSha512Rounds: 5,
			}
			v := New512(1000, opts)
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
	password := "foobar"
	encoded := "$6$rounds=10000$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1"
	tests := []struct {
		name     string
		rounds   int
		encoded  string
		password string
		want     verifier.Result
		wantErr  bool
	}{
		{
			name:     "parse error",
			encoded:  "totallywrongformat",
			password: password,
			rounds:   10000,
			want:     verifier.Skip,
			wantErr:  true,
		},
		{
			name:     "wrong password",
			encoded:  encoded,
			password: "wrong",
			rounds:   10000,
			want:     verifier.Fail,
		},
		{
			name:     "need update",
			encoded:  encoded,
			password: password,
			rounds:   2000,
			want:     verifier.NeedUpdate,
		},
		{
			name:     "succes",
			encoded:  encoded,
			password: password,
			rounds:   10000,
			want:     verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hasher{
				use512: true,
				rounds: tt.rounds,
				rand:   strings.NewReader("saltsaltsaltsalt"),
			}
			got, err := h.Verify(tt.encoded, tt.password)
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

func TestHasher512(t *testing.T) {
	h := New512(5000, nil)
	hash, err := h.Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.Verify(hash, "password")
	if err != nil {
		t.Fatal(err)
	}
	if res != verifier.OK {
		t.Errorf("Hasher.Verify() = %s, want %s", res, verifier.OK)
	}
}

func TestHasher256(t *testing.T) {
	h := New256(5000, nil)
	hash, err := h.Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.Verify(hash, "password")
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
			want: &ValidationOpts{
				MinSha256Rounds: RoundsMin,
				MaxSha256Rounds: RoundsMax,
				MinSha512Rounds: RoundsMin,
				MaxSha512Rounds: RoundsMax,
			},
		},
		{
			name: "partial opts",
			opts: &ValidationOpts{
				MinSha256Rounds: 3,
			},
			want: &ValidationOpts{
				MinSha256Rounds: 3,
				MaxSha256Rounds: RoundsMax,
				MinSha512Rounds: RoundsMin,
				MaxSha512Rounds: RoundsMax,
			},
		},
		{
			name: "full opts",
			opts: &ValidationOpts{
				MinSha256Rounds: 4,
				MaxSha256Rounds: 5000,
				MinSha512Rounds: 5,
				MaxSha512Rounds: 10000,
			},
			want: &ValidationOpts{
				MinSha256Rounds: 4,
				MaxSha256Rounds: 5000,
				MinSha512Rounds: 5,
				MaxSha512Rounds: 10000,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkValidationOpts(tt.opts)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("checkValidationOpts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifier_Validate(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
		want    verifier.Result
		wantErr bool
	}{
		{
			name:    "parse error",
			encoded: "totallywrongformat",
			want:    verifier.Skip,
			wantErr: true,
		},
		{
			name:    "valid sha512",
			encoded: "$6$rounds=3$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name:    "valid sha256",
			encoded: "$5$rounds=7$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.OK,
			wantErr: false,
		},
		{
			name:    "sha256 too low rounds",
			encoded: "$5$rounds=1$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha256 too high rounds",
			encoded: "$5$rounds=11$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha512 too low rounds",
			encoded: "$6$rounds=1$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
		{
			name:    "sha512 too high rounds",
			encoded: "$6$rounds=11$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1",
			want:    verifier.Fail,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &ValidationOpts{
				MinSha256Rounds: 5,
				MaxSha256Rounds: 10,
				MinSha512Rounds: 2,
				MaxSha512Rounds: 5,
			}
			v := NewVerifier(opts)
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
	password := "foobar"
	encoded := "$6$rounds=10000$saltsaltsaltsalt$EZKkFhxaTyiAhcKpFxN09.libqbOVLez7TJLU9i1rGqmCJkU4O5MLKPlNmVFwvj9YM3HTmo.EQeTrTAI01tZz1"

	tests := []struct {
		name     string
		encoded  string
		password string
		want     verifier.Result
		wantErr  bool
	}{
		{
			name:     "parse error",
			encoded:  "totallywrongformat",
			password: password,
			want:     verifier.Skip,
			wantErr:  true,
		},
		{
			name:     "wrong password",
			encoded:  encoded,
			password: "wrong",
			want:     verifier.Fail,
		},
		{
			name:     "success",
			encoded:  encoded,
			password: password,
			want:     verifier.OK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(nil)
			got, err := v.Verify(tt.encoded, tt.password)
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
