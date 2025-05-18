# vsencrypt

[![Build Status](https://github.com/vsencrypt/vsencrypt/actions/workflows/CI.yml/badge.svg)](https://github.com/vsencrypt/vsencrypt/actions/workflows/CI.yml)

A very strong encryption command line app to keep your file securely.

Supported ciphers:

- **chacha20**          256bits.
- **salsa20**           256bits.
- **aes256**            AES 256bits in CTR mode.
- **chacha20_aes256**
- **aes256_chacha20**   default cipher.
- **salsa20_aes256**
- **aes256_salsa20**

## Support Platforms

- Mac OS
- Linux
- Windows

## Build

```sh
make
make test
```

## Usage

    vsencrypt [-h] [-v] [-q] [-f] [-D] -e|-d [-a cipher] -i infile [-o outfile] [-p password]

    DESCRIPTION
    Use very strong cipher to encrypt/decrypt file.

    The following options are available:

    -h Help.

    -v Show version.

    -q Quiet. No error output.

    -f Force override output file if already exist.

    -D Delete input file if encrypt/decrypt success.

    -e Encryption.

    -d Decryption.

    -c Encryption cipher, used in encryption mode(-e) only.

        Available ciphers:

        chacha20         256bit, faster than AES 256.
        salsa20          256bit, faster than AES 256.
        aes256           AES 256bit in CTR mode.
        aes256_chacha20  aes256 then chacha20 (default cipher).
        aes256_salsa20   aes256 then salsa20.
        chacha20_aes256  chacha20 then aes256.
        salsa20_aes256   salsa20 then aes256.

    -i <infile> Input file for encrypt/decrypt.

    -o <infile> Output file for encrypt/decrypt.

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

 1 byte. File format version. Current version is 0x1.

### Header

File header is determined by version.

#### Version 1 Header

    ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    | cipher(1) |  salt(16)  |   iv(16)   |    mac(16)   |
    ++++++++++++++++++++++++++++++++++++++++++++++++++++++

- 1 byte `cipher` algorithm.
- 16 bytes `salt` for password.
- 16 bytes `iv` for encryption/decryption.
- 16 bytes `mac` (Message Authentication Code) of poly1305 used to verify the data integrity and the authenticity.

Version 1 header total size is 1(version) + 1(cipher) + 16(salt) + 16(iv) + 16(mac) = 50 bytes.

### Crypto

Key derivation function is [Argon2](https://en.wikipedia.org/wiki/Argon2) which was selected as the winner of the Password Hashing Competition in July 2015.

[Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used as message authentication code (MAC).
Poly1305 has been standardized in [RFC 7539](https://tools.ietf.org/html/rfc7539).

## Static Check

clang setup for static analysis

```sh
export C_INCLUDE_PATH=`pwd`/src:`pwd`/src/argon2/include:`pwd`/src/argon2/src/blake2
```

## License

MIT. see [LICENSE.txt](LICENSE.txt)

## References

* [serpent](https://www.cl.cam.ac.uk/~rja14/serpent.html)
* [salsa20](https://cr.yp.to/salsa20.html)
* [chacha20](https://cr.yp.to/chacha.html)
* [argon2](https://github.com/P-H-C/phc-winner-argon2)
