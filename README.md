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

* Secure salt generation (from `crypto/rand`) for all algorithms included.
* Automatic update of passwords.
* Only [depends](go.mod) on the Go standard library and `golang.org/x/{sys,crypto}`.
* The `Hasher` and `Verifier` interfaces allow the use of custom algorithms and
  encoding schemes.

### Algorithms

| Algorithm | Identifiers                                                        | Secure             |
|-----------|--------------------------------------------------------------------|--------------------|
| argon2    | argon2i, argon2id                                                  | :heavy_check_mark: |
| bcrypt    | 2, 2a, 2b, 2y                                                      | :heavy_check_mark: |
| md5-crypt | 1                                                                  | :x:                |
| scrypt    | scrypt, 7                                                          | :heavy_check_mark: |
| pbkpdf2   | pbkdf2, pbkdf2-sha224, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512 | :heavy_check_mark: |

### Encoding

There is no unified standard for encoding password hashes. Essentially one
would need to store the parameters used, salt and the resulting hash.
As the salt and hash are typically raw bytes, they also need to be converted
to characters, for example using base64.

All of the Passwap supplied algorithms use dollar sign (`$`) delimited
encoding. This results in a single string containing all of the above for
later password verification.

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
| <1.18   | :x:                |
| 1.18    | :warning:          |
| 1.19    | :warning:          |
| 1.20    | :white_check_mark: |
| 1.21    | :white_check_mark: |

## License

The full functionality of this library is and stays open source and free to use for everyone. Visit
our [website](https://zitadel.com) and get in touch.

See the exact licensing terms [here](LICENSE)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
language governing permissions and limitations under the License.
