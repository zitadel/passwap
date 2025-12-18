package passwap_test

import (
	"fmt"

	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"
)

func Example() {
	bcryptValidationOpts := &bcrypt.ValidationOpts{
		MinCost: 10,
		MaxCost: 16,
	}

	// Create a new swapper which hashes using bcrypt.
	passwords := passwap.NewSwapper(
		bcrypt.New(bcrypt.DefaultCost, bcryptValidationOpts),
	)

	// Create an encoded bcrypt hash string of password with salt.
	encoded, err := passwords.Hash("good_password")
	if err != nil {
		panic(err)
	}
	fmt.Println(encoded)
	// $2a$10$eS.mS5Zc5YAJFlImXCpLMu9TxXwKUhgQxsbghlvyVwvwYO/17E2qy

	// Replace the swapper to hash using argon2id,
	// verifies and upgrades bcrypt.
	argonValidationOpts := &argon2.ValidationOpts{
		MinMemory:  32 * 1024,
		MaxMemory:  512 * 1024,
		MinTime:    1,
		MaxTime:    4,
		MinThreads: 2,
		MaxThreads: 8,
	}
	passwords = passwap.NewSwapper(
		argon2.NewArgon2id(argon2.RecommendedIDParams, argonValidationOpts),
		bcrypt.NewVerifier(bcryptValidationOpts),
	)

	// Verify encoded bcrypt string with a good password.
	// Returns a new encoded string with argon2id hash
	// of password and new random salt.
	if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
		panic(err)
	} else if updated != "" {
		encoded = updated // store in "DB"
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
	passwords = passwap.NewSwapper(
		argon2.NewArgon2id(argon2.Params{
			Time:    2,
			Memory:  64 * 1024,
			Threads: 4,
			KeyLen:  32,
			SaltLen: 16,
		}, argonValidationOpts),
		bcrypt.NewVerifier(bcryptValidationOpts),
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
