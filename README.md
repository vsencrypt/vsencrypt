VSENCRYPTION
============

Very string encryption to keep your file securely.

## Build

    make

## Usage

    vsencrypt [-h] [-v] [-q] -e|-d [-a cipher] -i infile [-o outfile] [-p password]

    DESCRIPTION
    Use very strong cipher to encrypt/decrypt file.

    The following options are available:

    -h Help.

    -v Show version.

    -q Quiet. No error output.

    -e Encryption.

    -d Decryption.

    -a Encryption cipher, used in encryption mode(-e) only.

    -i <infile> Input file for encrypt/decrypt.

    -o <infile> output file for encrypt/decrypt.

    -p Password.

    EXAMPLES
    Encryption:
    vsencrypt -e -i foo.jpg -o foo.jpg.vse -p secret123
    vsencrypt -e -i foo.jpg      # will output as foo.jpg.vse and ask password

    Decryption:
    vsencrypt -d -i foo.jpg.vse -d foo.jpg -p secret123
    vsencrypt -d -i foo.jpg.vse  # will output as foo.jpg and ask password

## Static Check

clang setup for static analysis

    export C_INCLUDE_PATH=`pwd`/src:`pwd`/src/argon2/include:`pwd`/src/argon2/src/blake2

## License

MIT. see [LICENSE.txt](LICENSE.txt)

## References

* [salsa20](https://cr.yp.to/salsa20.html)
* [chacha20](https://cr.yp.to/chacha.html)
