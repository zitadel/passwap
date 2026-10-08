#!/usr/bin/env python3

# The standard library has no AES, so the AES-256-CTR step uses the openssl CLI.

import base64
import hashlib
import subprocess

password = b"user1password"
salt = base64.b64decode("42xEC+ixf3L2lw==")
salt_separator = base64.b64decode("Bw==")
signer_key = base64.b64decode(
    "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
)


def firebase_scrypt(ln, r, salt_separator):
    key = hashlib.scrypt(password, salt=salt + salt_separator, n=1 << ln, r=r, p=1, dklen=32)
    return subprocess.run(
        ["openssl", "enc", "-aes-256-ctr", "-K", key.hex(), "-iv", "00" * 16],
        input=signer_key,
        capture_output=True,
        check=True,
    ).stdout


def b64(b):
    return base64.b64encode(b).decode()


def encode(ln, r, salt_separator):
    password_hash = firebase_scrypt(ln, r, salt_separator)
    return f"$firebasescrypt$ln={ln},r={r}${b64(salt)}${b64(password_hash)}${b64(salt_separator)}${b64(signer_key)}"


print("FirebaseScryptEncoded = `", encode(14, 8, salt_separator), "`", sep="")
print("FirebaseScryptEncodedNoSaltSeparator = `", encode(14, 8, b""), "`", sep="")
print("FirebaseScryptEncodedLowCost = `", encode(10, 4, salt_separator), "`", sep="")
