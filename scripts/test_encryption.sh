#!/bin/sh

password=secret123
ciphers="salsa20
         chacha20
         aes256
         aes256_chacha20
         aes256_salsa20
         chacha20_aes256
         salsa20_aes256"
infiles="tmp/1b
         tmp/1k
         tmp/10k
         tmp/20k
         tmp/1m"

rm -fr tmp
mkdir tmp

dd if=/dev/urandom of=tmp/1b bs=1 count=1
dd if=/dev/urandom of=tmp/1k bs=1000 count=1    # 1000, not 1024
dd if=/dev/urandom of=tmp/10k bs=1024 count=10
dd if=/dev/urandom of=tmp/20k bs=1024 count=20
dd if=/dev/urandom of=tmp/1m bs=1024 count=1000

for infile in $infiles
do
    for cipher in $ciphers
    do
        echo "Encrypting $infile with cipher $cipher"
        encryptedfile=$infile.$cipher.vse

        sha1_expected=$(shasum $infile | cut -d' ' -f1)

        ./vsencrypt -e -c $cipher -i $infile -o $encryptedfile -f -p $password
        ret=$?
        if [ $ret -ne 0 ]; then
            echo "Error: encrypt $infile with cipher $cipher failed: $ret"
            exit 1
        fi

        echo "Decrypting $encryptedfile"
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