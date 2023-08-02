#!/usr/bin/env python3

from passlib.hash import pbkdf2_sha1, pbkdf2_sha256, pbkdf2_sha512


password = "password"
salt = bytes("randomsaltishard", 'utf-8')
rounds = 12

print("Pbkdf2Sha1Encoded", " = `", pbkdf2_sha1.hash(password, salt=salt, rounds=rounds), "`", sep="")
print("Pbkdf2Sha256Encoded", " = `", pbkdf2_sha256.hash(password, salt=salt, rounds=rounds), "`", sep="")
print("Pbkdf2Sha512Encoded", " = `", pbkdf2_sha512.hash(password, salt=salt, rounds=rounds), "`", sep="")
