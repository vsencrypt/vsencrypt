#ifndef SALSA20_3118A7C5_9DBB_425A_A350_302EB42E8649_H
#define SALSA20_3118A7C5_9DBB_425A_A350_302EB42E8649_H

#include <stdint.h>

typedef struct salsa20_ctx
{
    uint32_t input[16];
} salsa20_ctx_t;

/*
 * Key setup. It is the user's responsibility to select the values of
 * keysize and ivsize from the set of supported values specified
 * above.
 *
 * @param keysize key size in bits. 128 or 256. 256 is recommended.
 * @param ivsize  iv size in bits, max 64.
 */
void salsa20_keysetup(
    salsa20_ctx_t *ctx,
    const uint8_t *key,
    uint32_t keysize, /* Key size in bits. */
    uint32_t ivsize); /* IV size in bits. */

/*
 * IV setup. After having called salsa20_keysetup(), the user is
 * allowed to call salsa20_ivsetup() different times in order to
 * encrypt/decrypt different messages with the same key but different
 * IV's.
 */
void salsa20_ivsetup(
    salsa20_ctx_t *ctx,
    const uint8_t *iv);

/*
 * Encryption/decryption of arbitrary length messages.
 *
 * The following sequence of calls is acceptable:
 *
 * salsa20_keysetup();
 *
 * salsa20_ivsetup();
 *
 * salsa20_xcrypt_bytes();
 *
 */
void salsa20_xcrypt_bytes(
    salsa20_ctx_t *ctx,
    const uint8_t *in,
    uint8_t *out,
    uint32_t msglen); /* Message length in bytes. */

#endif
