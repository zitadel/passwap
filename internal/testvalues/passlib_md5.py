#!/usr/bin/env python3

from passlib.hash import md5_crypt

password = "password"
salt = "kJ4QkJaQ"

print("MD5Encoded = `", md5_crypt.hash(password, salt=salt), "`", sep="")
