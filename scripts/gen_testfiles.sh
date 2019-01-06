#!/bin/sh

password=secret123
ciphers="salsa20
         chacha20
         aes256
         aes256_chacha20
         aes256_salsa20
         chacha20_aes256
         salsa20_aes256"
infiles="testfiles/1bv1
         testfiles/1kv1
         testfiles/10kv1"

for infile in $infiles
do
    for cipher in $ciphers
    do
        echo "Encrypting $infile with cipher $cipher"
        encryptedfile=$infile.$cipher.vse

        if [ -e $encryptedfile ]; then
            echo "$encryptedfile already exist, do not re-generate it"
            continue
        fi

        sha1_expected=$(shasum $infile | cut -d' ' -f1)

        ./vsencrypt -e -c $cipher -i $infile -o $encryptedfile -f -p $password
        ret=$?
        if [ $ret -ne 0 ]; then
            echo "Error: encrypt $infile with cipher $cipher failed: $ret"
            exit 1
        fi

        decryptedfile=$infile.decrypted
        ./vsencrypt -d -i $encryptedfile -o $decryptedfile  -f -p $password
        ret=$?
        if [ $ret -ne 0 ]; then
            echo "Error: decrypt $encryptedfile failed: $ret"
            exit 2
        fi

        sha1=$(shasum $decryptedfile | cut -d' ' -f1)
        if [ "$sha1" != "$sha1_expected" ]; then
            echo "Error: decrypted file $decryptedfile not match original file $infile"
            exit 3
        fi

        rm -f $decryptedfile
    done
done