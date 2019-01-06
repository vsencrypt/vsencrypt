# vsencrypt

[![Build Status](https://travis-ci.org/vsencrypt/vsencrypt.svg?branch=master)](https://travis-ci.org/vsencrypt/vsencrypt)

Very strong encryption to keep your file securely.

Supported ciphers:

- **chacha20**          256bits.
- **salsa20**           256bits.
- **aes256**            AES 256bits in CTR mode.
- **chacha20_aes256**
- **aes256_chacha20**
- **salsa20_aes256**
- **aes256_salsa20**

## Support Platforms

- Mac OS
- Linux

## Build

    make
    make test

## Usage

    vsencrypt [-h] [-v] [-q] [-f] -e|-d [-a cipher] -i infile [-o outfile] [-p password]

    DESCRIPTION
    Use very strong cipher to encrypt/decrypt file.

    The following options are available:

    -h Help.

    -v Show version.

    -q Quiet. No error output.

    -f Force override output file if already exist.

    -e Encryption.

    -d Decryption.

    -a Encryption cipher, used in encryption mode(-e) only.

        Available ciphers:

        chacha20         256bit, faster than AES 256.
        salsa20          256bit, faster than AES 256.
        aes256           AES 256bit in CTR mode.
        aes256_chacha20  aes256 then chacha20.
        aes256_salsa20   aes256 then salsa20.
        chacha20_aes256  chacha20 then aes256.
        salsa20_aes256   salsa20 then aes256.

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

## Design

### File Format

    +++++++++++++++++++++++++++++++++++++++++++++++++++++
    | version | header | encrypted data...              |
    +++++++++++++++++++++++++++++++++++++++++++++++++++++

### Version

 1 byte. File format version. Current version is 1.

### Header

  Determined by version.

#### Version 1 Header

    ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    | cipher(1) |  salt(16)  |   iv(16)   |    mac(16)   |
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++

- 1 byte `cipher` algorithm.
- 16 bytes `salt` for password.
- 16 bytes `iv` for encryption/decryption.
- 16 bytes `mac` (message authentication code) of poly1305 used to verify the data integrity and the authenticity.

Version 1 header total size is 1(version) + 1(cipher) + salt(16) + 16(iv) + mac(16) = 50 bytes.

### Crypto

Key derivation function is [Argon2](https://en.wikipedia.org/wiki/Argon2) which was selected as the winner of the Password Hashing Competition in July 2015.

[Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used as message authentication code (MAC). Poly1305 has been standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539).

## Static Check

clang setup for static analysis

    export C_INCLUDE_PATH=`pwd`/src:`pwd`/src/argon2/include:`pwd`/src/argon2/src/blake2

## License

MIT. see [LICENSE.txt](LICENSE.txt)

## References

* [salsa20](https://cr.yp.to/salsa20.html)
* [chacha20](https://cr.yp.to/chacha.html)
* [argon2](https://github.com/P-H-C/phc-winner-argon2)
