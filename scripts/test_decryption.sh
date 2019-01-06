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
        echo "  success"
    fi

    rm -f $decryptedfile
done
