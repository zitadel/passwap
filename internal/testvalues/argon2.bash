#!/bin/bash

set -e

# Hex output
for mode in "i" "id"; do
    hash=$(echo -n "password" | argon2 randomsaltishard -${mode} -t 3 -m 12 -p 1 -l 32 -r)
    echo "Argon2${mode}Hex = \`${hash}\`"
done

# encoded hash output
for mode in "i" "d" "id"; do
    hash=$(echo -n "password" | argon2 randomsaltishard -${mode} -t 3 -m 12 -p 1 -l 32 -e)
    echo "Argon2${mode}Encoded = \`${hash}\`"
done
