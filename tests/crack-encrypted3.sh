#!/bin/sh
# openssl enc -e -des3 -md sha256 -in message.txt -out encrypted3.dat -k Sara

set -e
BRUTEFORCE_SALTED_OPENSSL=../bruteforce-salted-openssl

echo "Bruteforce DES3 with SHA256"
PASSWORD=$(${BRUTEFORCE_SALTED_OPENSSL} -1 -t 4 -l 4 -m 4 -b "Sa" \
                                        -c "des3" -d "sha256" encrypted3.dat \
               | grep "Password candidate" \
               | cut -b 21-)

if [ "${PASSWORD}" = "Sara" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
