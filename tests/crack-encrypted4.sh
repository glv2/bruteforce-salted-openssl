#!/bin/sh
# openssl enc -e -aes-256-cbc -md sha256 -iter 100 -in message.txt -out encrypted4.dat -k Bob

set -e
BRUTEFORCE_SALTED_OPENSSL=../bruteforce-salted-openssl

echo "Bruteforce AES-256-CBC with PBKDF2 and SHA256"
PASSWORD=$(${BRUTEFORCE_SALTED_OPENSSL} -1 -t 4 -f "dict.txt" \
                                        -K -i 100 -d "sha256" encrypted4.dat \
               | grep "Password candidate" \
               | cut -b 21-)

if [ "${PASSWORD}" = "Bob" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
