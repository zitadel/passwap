# Passwap

[![Go Reference](https://pkg.go.dev/badge/github.com/zitadel/passwap.svg)](https://pkg.go.dev/github.com/zitadel/passwap)
[![Go](https://github.com/zitadel/passwap/actions/workflows/go.yml/badge.svg)](https://github.com/zitadel/passwap/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/zitadel/passwap/branch/main/graph/badge.svg?token=GrPT2nbCjj)](https://codecov.io/gh/zitadel/passwap)
[![Go Report Card](https://goreportcard.com/badge/github.com/zitadel/passwap)](https://goreportcard.com/report/github.com/zitadel/passwap)

Package Passwap provides a unified implementation between
different password hashing algorithms in the Go ecosystem.
It allows for easy swapping between algorithms,
using the same API for all of them.

Passwords hashed with Passwap, using a certain algorithm
and parameters can be stored in a database.
If at a later moment parameters or even the algorithm is changed,
Passwap is still able to verify the "outdated" hashes and
automatically return an updated hash when applicable.
Only when an updated hash is returned, the record in the database
needs to be updated.

## Features

- Secure salt generation (from `crypto/rand`) for all algorithms included.
- Automatic update of passwords.
- Only [depends](go.mod) on the Go standard library and `golang.org/x/{sys,crypto}`.
- The `Hasher` and `Verifier` interfaces allow the use of custom algorithms and
  encoding schemes.

### Algorithms

| Algorithm       | Identifiers                                                        | Secure             |
| --------------- | ------------------------------------------------------------------ | ------------------ |
| [argon2][1]     | argon2i, argon2id                                                  | :heavy_check_mark: |
| [bcrypt][2]     | 2, 2a, 2b, 2y                                                      | :heavy_check_mark: |
| [md5-crypt][3]  | 1                                                                  | :x:                |
| [md5 plain][4]  | Hex encoded string                                                 | :x:                |
| [md5 salted][5] | md5salted-suffix,md5salted-prefix                                  | :x:                |
| [sha2-crypt][6] | 5, 6                                                               | :heavy_check_mark: |
| [scrypt][7]     | scrypt, 7                                                          | :heavy_check_mark: |
| [pbkpdf2][8]    | pbkdf2, pbkdf2-sha224, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512 | :heavy_check_mark: |

[1]: https://pkg.go.dev/github.com/zitadel/passwap/argon2
[2]: https://pkg.go.dev/github.com/zitadel/passwap/bcrypt
[3]: https://pkg.go.dev/github.com/zitadel/passwap/md5
[4]: https://pkg.go.dev/github.com/zitadel/passwap/md5plain
[5]: https://pkg.go.dev/github.com/zitadel/passwap/md5salted
[6]: https://pkg.go.dev/github.com/zitadel/passwap/sha2
[7]: https://pkg.go.dev/github.com/zitadel/passwap/scrypt
[8]: https://pkg.go.dev/github.com/zitadel/passwap/pbkdf2

### Encoding

There is no unified standard for encoding password hashes. Essentially one
would need to store the parameters used, salt and the resulting hash.
As the salt and hash are typically raw bytes, they also need to be converted
to characters, for example using base64.

All of the Passwap supplied algorithms use the dollar sign (`$`) delimited
encoding, aka [Modular Crypt Format](https://passlib.readthedocs.io/en/stable/modular_crypt_format.htm).
This results in a single string containing all of the above for
later password verification.

#### Argon2

Argon2 uses standard raw Base64 encoding (without padding) for salt and hash.
The resulting Modular Crypt Format string looks as follows:

```
$argon2i$v=19$m=4096,t=3,p=1$cmFuZG9tc2FsdGlzaGFyZA$YMvo8AUoNtnKYGqeODruCjHdiEbl1pKL2MsYy9VgU/E
   (1)              (2)               (3)                            (4)
```

1. The identifier, which can be `argon2i` or `argon2id`. `argon2d`, is not supported by Go, and therefore, is not supported by this library either.
2. Cost parameters.
   1. `m` for memory -`4096` KiB in this example.
   2. `t` for time - `3` in this example.
   3. `p` for parallelism (threads) - `1` in this example.
3. Base64 encoded salt.
4. Base64 encoded Argon2 hash output of the password and salt combined.

Changing any of the parameters or salt produces a different hash output.
More information about the parameters can be found in the upstream [Argon2 package documentation](https://pkg.go.dev/golang.org/x/crypto/argon2).

### Bcrypt

Bcrypt uses a custom Base64 encoding with the character set of `[./A-Za-z0-9]` and padding.
The actual formatting is fully implemented by the [Go package](https://pkg.go.dev/golang.org/x/crypto/bcrypt).
The resulting Modular Crypt Format string looks as follows:

```
$2a$12$aLYFkieuqJyeynvptPTxpehSViui5WeAPuR2Xw1wui9CPHEaacmFq
 (1)(2)          (3)                      (4)
```

1. The identifier can be `2a`, `2b` or, `2y`. It indicates the Bcrypt version but is ignored and the same is always produced.
2. The cost parameter that is exponential - `12` in this example.
3. The Base64-encoded salt, always 22 character long.
4. The Base64-encoded Bcrypt hash output of the password and salt combined.

### MD5 Crypt

MD5 Crypt uses its own encoding scheme, which is part of the [hashing algorithm](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.md5_crypt.html#algorithm). It uses a similar alphabet as Base64 but performs an additional shuffling of bytes.
The resulting Modular Crypt Format string looks as follows:

```
$1$kJ4QkJaQ$3EbD/pJddrq5HW3mpZ4KZ1
(1)   (2)           (3)
```

1. The identifier is always `1`
2. Base64-like-encoded salt.
3. Base64-like-encoded MD5 hash output of the password and salt combined.

There is no cost parameter for MD5 because MD5 is old and is considered too light and insecure. It is provided to verify and migrate to a better algorithm. Do not use for new hashes.

### MD5 Plain

MD5 Plain are hex encoded digests of a single iteration of a password without salt.
For example passwap can verify passwords hashed by the following methods:

- `printf "password" | md5sum` on most linux systems.
- PHP's `md5("password")`
- Python3's `hashlib.md5(b"password").hexdigest()`

MD5 is considered cryptographically broken and insecure. Also hashing without salt is a bad idea.
Therefore passwap only supports verification to allow applications to migrate to better methods.

### MD5 Salted

MD5 Salted are base64 encode digest of password+salt (resp. salt+password)
The resulting MD5salted Format string looks as follows:

```
$md5salted-suffix$kJ4QkJaQ$3EbD/pJddrq5HW3mpZ4KZ1
(1)                  (2)          (3)
```

1. The identifier is md5salted-suffix or md5salted-prefix
2. Salt string (will be added to password in exactly this form).
3. Base64-like-encoded MD5 hash output of the password and salt combined (password+salt or salt+password).

There is no cost parameter for MD5 because MD5 is old and is considered too light and insecure. It is provided to verify and migrate to a better algorithm. Do not use for new hashes.

### SHA2 crypt

SHA2 Crypt shares its encoding scheme with MD5 Crypt, but uses SHA-256 or SHA-512 instead of MD5 and uses a different [hashing algorithm](https://www.akkadia.org/drepper/SHA-crypt.txt)
The resulting Modular Crypt Format string looks as follows:

```
$5$rounds=5000$RPvilwjD1ebXJfzg$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5
(1)   (2)           (3)                 (4)
```

1. The identifier is always `5` (SHA-256) or `6` (SHA-512)
2. The cost parameter in rounds, which is a linear value - `5000` in this example. Note that according to the specification this part is optional (in which case the default of 5000 rounds will be used). In this implementation the rounds are always returned, even when they match the default
3. Base64-like-encoded salt.
4. Base64-like-encoded SHA-256/512 hash output of the password and salt combined.

### Scrypt

Scrypt uses standard raw Base64 encoding (no padding) for the salt and hash.
The resulting Modular Crypt Format string looks as follows:

```
$scrypt$ln=16,r=8,p=1$cmFuZG9tc2FsdGlzaGFyZA$Rh+NnJNo1I6nRwaNqbDm6kmADswD1+7FTKZ7Ln9D8nQ
  (1)        (2)              (3)                              (4)
```

1. The identifier is always `scrypt`.
2. Cost parameters:
   1. `ln` is the exponential cost parameter for memory and CPU - `16` in this example.
   2. `r` is the block size for optimal performance of the CPU architecture - `8` in this example.
   3. `p` is to indicate parallelism - `1` in this example.
3. Base64-encoded salt
4. Base64-encoded Scrypt hash output of the password and salt combined.

### PBKDF2

PBKDF2 uses an alternative Base64 encoding, which is based on the standard with `+` replaced by `.`, and it comes without padding. As we've also seen standard encoding with padding in the wild, the verifier will accept alternative standards with or without padding. The Hasher always produces alternative encoding.

The resulting Modular Crypt Format string looks as follows:

```
$pbkdf2-sha256$12$cmFuZG9tc2FsdGlzaGFyZA$OFvEcLOIPFd/oq8egf10i.qJLI7A8nDjPLnolCWarQY
      (1)     (2)         (3)                            (4)
```

1. The identifier is made of 2 parts:
   1. `pbkdf2` is the identifier prefix for the algorithm.
   2. `-sha256` is an optional suffix with dash separator and is the identifier for the hash backend. When omitted, `sha1` is used as a default.
2. The cost parameter in rounds, which is a linear value - `12` in this example.
3. Alternative Base64-encoded salt
4. Alternative Base64 encoded Scrypt hash output of the password and salt combined.

#### Reference

Its origin can be found in
[Glibc](https://man.archlinux.org/man/crypt.5). Passlib for Python is the
most complete implementation and there the
[Modular Crypt Format](https://passlib.readthedocs.io/en/stable/modular_crypt_format.htm)
expands the subject further. Although MCF is superseded by
the [Password Hashing Competition string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md),
passlib still provides the most complete documentation on the format and
encodings used for each algorithm.

Each algorithm supplied by Passwap is compatible with Passlib's encoding
and tested against reference hashes created with Passlib.

## Example

First, we want our application to hash passwords using **bcrypt**,
using the default cost. We will create a `Swapper` for it.
When a user would want to store `good_password` as a password,
it is passed into `passwords.Hash()` and the result is typically
stored in a database. In this case, we keep it just in the `encoded` variable.

```go
passwords := passwap.NewSwapper(
    bcrypt.New(bcrypt.DefaultCost),
)

encoded, err := passwords.Hash("good_password")
if err != nil {
    panic(err)
}
fmt.Println(encoded)
// $2a$10$eS.mS5Zc5YAJFlImXCpLMu9TxXwKUhgQxsbghlvyVwvwYO/17E2qy
```

At this point `encoded` has the value of `$2a$10$eS.mS5Zc5YAJFlImXCpLMu9TxXwKUhgQxsbghlvyVwvwYO/17E2qy`.
It is an encoded string containing the **bcrypt** identifier, cost, salt and hashed password which later
can be used for verification.

At a later moment, you can reconfigure your application to use another hashing algorithm.
This might be because the former is cryptographically broken, customer demand
or just because you can. Next, we will create a new `Swapper` configured to hash using
the **argon2id** algorithm.

We already have users that have created passwords using **bcrypt**.
As hashing is a one-way operation we can't migrate them until they supply
the password again. Therefore we must pass the `bcrypt.Verifier` as well.

Once the user supplies his password again and we need to verify it,
`passwords.Verify()` will return an `updated` encoded string automatically,
because the Swapper figured out that the original `encoded` was created using
a different algorithm.

```go
passwords = passwap.NewSwapper(
    argon2.NewArgon2id(argon2.RecommendedIDParams),
    bcrypt.Verifier,
)
if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
    panic(err)
} else if updated != "" {
    encoded = updated // store in "DB"
}
fmt.Println(encoded)
```

At this point `encoded` will look something like
`$argon2id$v=19$m=65536,t=1,p=4$d6SOdxdIip9BC7sM5H7PUQ$2E7OIz7C1NkMLOsXi5nSe5vfbthdc9N9SWVlArd200E`.

If we would call `passwords.Verify()` again, `updated` returns empty.
That's because `encoded` was created using the same algorithm and parameters.

```go
if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
    panic(err)
} else if updated != "" { // updated is empty, nothing is stored
    encoded = updated
}
fmt.Println(encoded)
// $argon2id$v=19$m=65536,t=1,p=4$d6SOdxdIip9BC7sM5H7PUQ$2E7OIz7C1NkMLOsXi5nSe5vfbthdc9N9SWVlArd200E
```

Now let's say that we upgraded our hardware with more powerful CPUs.
We should now also increase the `time` parameter accordingly, so that
the security of our hashes grows with the increased performance available
on the market.

In this case, we do not need to supply a separate `argon2.Verifier`,
as the returned `Hasher` from `NewArgon2id()` should already implement
the `Verifier` interface for its algorithm. We do keep the `bcrypt.Verifier`
around, because we might still have users that didn't use their password since the
last update.

```go
passwords = passwap.NewSwapper(
    argon2.NewArgon2id(argon2.Params{
        Time:    2,
        Memory:  64 * 1024,
        Threads: 4,
        KeyLen:  32,
        SaltLen: 16,
    }),
    bcrypt.Verifier,
)
if updated, err := passwords.Verify(encoded, "good_password"); err != nil {
    panic(err)
} else if updated != "" {
    encoded = updated
}
```

At this point `encoded` would be updated again and look like
`$argon2id$v=19$m=65536,t=2,p=4$44X+dwU+aSS85Kl1qH3/Jg$n/tQoAtx/I/Rt9BXHH9tScshWucltPPmB0HBLVtXCq0`
You'll see that the `t=2` parameter is updated as well as the resulting
salt and hash. A new salt is always obtained during hashing.

The full example is also part of the [Go documentation](https://pkg.go.dev/github.com/zitadel/passwap#example-package).

## Supported Go Versions

For security reasons, we only support and recommend the use of one of the latest two Go versions (:white_check_mark:).  
Versions that also build are marked with :warning:.

| Version | Supported          |
| ------- | ------------------ |
| <1.23   | :x:                |
| 1.23    | :white_check_mark: |
| 1.24    | :white_check_mark: |

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
