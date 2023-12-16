#ifndef VSE_31FAB0FC_FD40_4BEF_B834_5E8D93C30C5F_H
#define VSE_31FAB0FC_FD40_4BEF_B834_5E8D93C30C5F_H

#include <stdint.h>
#include "error.h"

#define FILE_HASH_LEN 32
#define SALT_LEN 16 // bytes
#define IV_LEN 16   // bytes
#define KEY_LEN 32  // bytes
#define MAC_LEN 16

#define CIPHER_UNKNOWN 0
#define CIPHER_SALSA20 0x1
#define CIPHER_CHACHA20 0x2 // The ChaCha20 cipher is designed to provide 256-bit security.
#define CIPHER_AES_256_CTR 0x3
#define CIPHER_AES_256_CTR_CHACHA20 0x32
#define CIPHER_CHACHA20_AES_256_CTR 0x23
#define CIPHER_AES_256_CTR_SALSA20 0x31
#define CIPHER_SALSA20_AES_256_CTR 0x13

#define MODE_UNKNOWN 0
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

typedef struct vse_header_v1
{
    uint8_t cipher;
    uint8_t salt[SALT_LEN]; // salt for password
    uint8_t iv[IV_LEN];     // iv for encryption
    uint8_t mac[MAC_LEN];   //
} vse_header_v1_t;

#define FILE_HEADER_LEN (sizeof(vse_header_v1_t) / sizeof(char))

void vse_print_error(const char *fmt, ...);

typedef struct vse_cipher
{
    const char *name;
    void *ctx;
    int (*encrypt)(uint8_t *in, uint32_t in_nbytes, uint8_t *out, uint32_t out_nbytes);
    int (*decrypt)(uint8_t *in, uint32_t in_nbytes, uint8_t *out, uint32_t out_nbytes);
} vse_cipher_t;

#endif
