#!/usr/bin/env python3

from passlib.hash import scrypt

salt = bytes("randomsaltishard", 'utf-8')
password = "password"

print("EncodedScrypt = `", scrypt.hash(password, salt=salt), "`", sep="")

