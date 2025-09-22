#!/usr/bin/env python3

import hashlib
import base64

def get_iteration_count(char):
    """Get iteration count from the hash character (same as Go implementation)"""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    index = alphabet.find(char)
    if index == -1:
        return -1
    return 1 << index

def encode_crypt3(raw_bytes):
    """Python implementation of crypt3 encoding matching Go implementation"""
    alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    dest = []
    
    v = 0
    bits = 0
    
    for b in raw_bytes:
        v |= (b << bits)
        bits += 8
        
        while bits > 6:
            dest.append(alphabet[v & 63])
            v >>= 6
            bits -= 6
    
    if bits > 0:
        dest.append(alphabet[v & 63])
    
    return ''.join(dest)

def hash_password_drupal7(password, salt, iterations):
    """Python implementation of Drupal 7 password hashing"""
    # Initial hash: SHA-512(salt + password)
    hasher = hashlib.sha512()
    hasher.update((salt + password).encode('utf-8'))
    digest = hasher.digest()
    
    # Iterate: SHA-512(previous_hash + password)
    for i in range(iterations):
        hasher = hashlib.sha512()
        hasher.update(digest)
        hasher.update(password.encode('utf-8'))
        digest = hasher.digest()
    
    # Use crypt3 encoding
    return encode_crypt3(digest)

def generate_drupal7_hash(password, salt, iteration_char):
    """Generate a complete Drupal 7 hash"""
    iterations = get_iteration_count(iteration_char)
    if iterations == -1:
        raise ValueError(f"Invalid iteration character: {iteration_char}")
    
    # Ensure salt is exactly 8 characters
    if len(salt) > 8:
        salt = salt[:8]
    elif len(salt) < 8:
        salt = salt.ljust(8, '0')
    
    hash_portion = hash_password_drupal7(password, salt, iterations)
    
    # Truncate to 43 characters to match Drupal format
    if len(hash_portion) > 43:
        hash_portion = hash_portion[:43]
    
    return f"$S${iteration_char}{salt}{hash_portion}"

# Test values using standard test parameters
password = "password"
salt = "randomsa"  # First 8 chars of "randomsaltishard"
iteration_char = "E"  # 2^16 = 65536 iterations (common Drupal 7 default)

# Generate the hash
drupal7_hash = generate_drupal7_hash(password, salt, iteration_char)
print(f"Drupal7Encoded = `{drupal7_hash}`")
print(f"Drupal7Salt = \"{salt}\"")
print(f"Drupal7IterationChar = '{iteration_char}'")
print(f"Drupal7Iterations = {get_iteration_count(iteration_char)}")
