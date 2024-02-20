#!/bin/sh
# openssl enc -e -aes-256-cbc -md md5 -in message.txt -out encrypted1.dat -k Alexia

set -e
BRUTEFORCE_SALTED_OPENSSL=../bruteforce-salted-openssl

echo "Bruteforce AES-256-CBC with MD5"
PASSWORD=$(${BRUTEFORCE_SALTED_OPENSSL} -1 -t 4 -l 5 -m 6 -b "Al" -e "ia" \
                                        -d "md5" encrypted1.dat \
               | grep "Password candidate" \
               | cut -b 21-)

if [ "${PASSWORD}" = "Alexia" ];
then
    echo "SUCCESS (Password: ${PASSWORD})"
    exit 0
else
    echo "FAILURE"
    exit 1
fi
