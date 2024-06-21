#!/usr/bin/env python3

import hashlib

password = b"password"

print("MD5PlainHex = `", hashlib.md5(password).hexdigest(), "`", sep="")
