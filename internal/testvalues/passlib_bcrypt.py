#!/usr/bin/env python3

from passlib.hash import bcrypt


password = "password"
rounds = 12
idents = ["2a", "2b", "2y"]

for ident in idents:
    print("EncodedBcrypt", ident, "= `", bcrypt.hash(password, rounds=rounds, ident=ident), "`", sep="")
