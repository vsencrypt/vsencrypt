#!/bin/sh

password=secret123
infiles="testfiles/*.vse"

for infile in $infiles
do
    printf "Decrypting %-40s" $infile

    decryptedfile=$infile.decrypted
    ./vsencrypt -d -i $infile -o $decryptedfile  -f -p $password
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "  failed: $ret"
        exit 1
    else
        plaintextfile=$(echo $infile | cut -d'.' -f1)
        sha1=$(shasum $decryptedfile | cut -d' ' -f1)
        sha2=$(shasum $plaintextfile | cut -d' ' -f1)
        if [ "$sha1" != "$sha2" ]; then
            echo "  failed: Not match plain text file."
        else
            echo "  success"
        fi
    fi

    rm -f $decryptedfile
done
