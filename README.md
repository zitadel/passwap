# Passwap

[![Go Reference](https://pkg.go.dev/badge/github.com/muhlemmer/passwap.svg)](https://pkg.go.dev/github.com/muhlemmer/passwap)
[![Go](https://github.com/muhlemmer/passwap/actions/workflows/go.yml/badge.svg)](https://github.com/muhlemmer/passwap/actions/workflows/go.yml)
[![codecov](https://codecov.io/github/muhlemmer/passwap/branch/main/graph/badge.svg?token=OIGV4ZT3B5)](https://codecov.io/github/muhlemmer/passwap)

Package passwap provides a unified implementation between
different password hashing algorithms.
It allows for easy swapping between algorithms,
using the same API for all of them.

Passwords hashed with passwap, using a certain algorithm
and parameters can be stored in a database.
If at a later moment paramers or even the algorithm is changed,
passwap is still able to verify the "outdated" hashes and
automatically return an updated hash when applicable.
Only when an updated hash is returned, the record in the database
needs to be updated.

Resulting password hashes are encoded using dollar sign ($)
notation. It's origin lies in Glibc, but there is no clear
standard on the matter For passwap it is choosen to follow
suit with python's passlib identifiers to be (hopefully)
as portable as possible. Suplemental information can be found:

Glibc: <https://man.archlinux.org/man/crypt.5>;

Passlib "Modular Crypt Format": <https://passlib.readthedocs.io/en/stable/modular_crypt_format.html>;

Password Hashing Competition string format: <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md>;
