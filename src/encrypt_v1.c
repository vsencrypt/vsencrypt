#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "encrypt_v1.h"
#include "crypto_random.h"
#include "argon2/include/argon2.h"
#include "argon2/src/blake2/blake2.h"
#include "salsa20/salsa20.h"
#include "aes/aes.h"
#include "hexdump.h"
#include "chacha/chacha.h"
#include "chacha/poly1305.h"

int vse_gen_key_v1(const uint8_t *salt, size_t salt_nbytes,
                   const char *password, size_t password_nbytes,
                   size_t key_nbytes, uint8_t *key)
{
    uint32_t time_cost = 2;           // 2-pass computation
    uint32_t memory_cost = (1 << 16); // 64 MB memory vse_usage
    uint32_t parallelism = 4;         // number of threads and lanes

    return argon2i_hash_raw(time_cost, memory_cost, parallelism,
                            password, password_nbytes,
                            salt, salt_nbytes,
                            key, key_nbytes);
}

/**
 * Generate IV based on salt and input.
 *
 * Faster than vse_gen_key_v1().
 */
int vse_gen_iv_v1(const uint8_t *salt, size_t salt_nbytes,
                  const uint8_t *password, size_t password_nbytes,
                  size_t iv_nbytes, uint8_t *iv)
{
    uint32_t time_cost = 1;          // 1-pass computation
    uint32_t memory_cost = (1 << 8); // 32 MB memory vse_usage
    uint32_t parallelism = 1;        // number of threads and lanes

    return argon2i_hash_raw(time_cost, memory_cost, parallelism,
                            password, password_nbytes,
                            salt, salt_nbytes,
                            iv, iv_nbytes);
}

void vse_calculate_mac_v1(const vse_header_v1_t *header,
                          const uint8_t *file_hash,
                          const uint8_t *key, // 32 bytes
                          uint8_t *mac)       // 16 bytes. out
{
    uint8_t message[SALT_LEN + IV_LEN + FILE_HASH_LEN] = {0};
    memcpy(message, header->salt, SALT_LEN);
    memcpy(message + SALT_LEN, header->iv, IV_LEN);
    memcpy(message + SALT_LEN + IV_LEN, file_hash, FILE_HASH_LEN);

    poly1305_auth(mac,
                  message, sizeof(message) / sizeof(uint8_t),
                  key);
}

static void vse_setup_cipher_v1(salsa20_ctx_t *salsa20,
                                chacha_ctx_t *chacha,
                                aes_ctx_t *aes,
                                const uint8_t *iv, size_t iv_nbytes,
                                const uint8_t *key, size_t key_nbytes)
{
    uint8_t iv_aes[IV_LEN] = {0};
    uint8_t iv_chacha[IV_LEN] = {0};
    uint8_t iv_salsa20[IV_LEN] = {0};
    vse_gen_iv_v1(iv, iv_nbytes, (uint8_t *)"aes", 3, IV_LEN, iv_aes);
    vse_gen_iv_v1(iv, iv_nbytes, (uint8_t *)"chacha", 6, IV_LEN, iv_chacha);
    vse_gen_iv_v1(iv, iv_nbytes, (uint8_t *)"salsa20", 7, IV_LEN, iv_chacha);

    AES_init_ctx_iv(aes, key, iv_aes);

    chacha_ivsetup(chacha, iv_chacha, NULL);
    chacha_keysetup(chacha, key, 256);

    salsa20_keysetup(salsa20, key, 256, IV_LEN * 8);
    salsa20_ivsetup(salsa20, iv_salsa20);
}

int vse_block_xcrypt_v1(int cipher,
                        salsa20_ctx_t *salsa20,
                        chacha_ctx_t *chacha,
                        aes_ctx_t *aes,
                        uint8_t *buf, size_t buf_nbytes)
{
    int ret = 0;
    switch (cipher)
    {
    case CIPHER_SALSA20:
        salsa20_xcrypt_bytes(salsa20, buf, buf, buf_nbytes);
        break;
    case CIPHER_CHACHA20:
        chacha_xcrypt_bytes(chacha, buf, buf, buf_nbytes);
        break;
    case CIPHER_AES_256_CTR:
        AES_CTR_xcrypt_buffer(aes, buf, buf_nbytes);
        break;
    case CIPHER_AES_256_CTR_CHACHA20:
        AES_CTR_xcrypt_buffer(aes, buf, buf_nbytes);
        chacha_xcrypt_bytes(chacha, buf, buf, buf_nbytes);
        break;
    case CIPHER_CHACHA20_AES_256_CTR:
        chacha_xcrypt_bytes(chacha, buf, buf, buf_nbytes);
        AES_CTR_xcrypt_buffer(aes, buf, buf_nbytes);
        break;
    case CIPHER_AES_256_CTR_SALSA20:
        AES_CTR_xcrypt_buffer(aes, buf, buf_nbytes);
        salsa20_xcrypt_bytes(salsa20, buf, buf, buf_nbytes);
        break;
    case CIPHER_SALSA20_AES_256_CTR:
        salsa20_xcrypt_bytes(salsa20, buf, buf, buf_nbytes);
        AES_CTR_xcrypt_buffer(aes, buf, buf_nbytes);
        break;
    default:
        vse_print_error("Error: Invalid cipher %d", cipher);
        ret = ERR_ENCRYPT_V1_STREAM_CRYPT_INVALID_CIPHER;
        break;
    }

    return ret;
}

int vse_stream_crypt_v1(int mode, int cipher,
                        const uint8_t *iv, size_t iv_nbytes,
                        const uint8_t *key, size_t key_nbytes,
                        FILE *fp_in, FILE *fp_out,
                        uint8_t *file_hash, size_t file_hash_nbytes)
{
    int ret = 0;
    aes_ctx_t aes;
    chacha_ctx_t chacha;
    salsa20_ctx_t salsa20;

    vse_setup_cipher_v1(&salsa20,
                        &chacha,
                        &aes,
                        iv, iv_nbytes,
                        key, key_nbytes);

    blake2b_state blake2b;
    blake2b_init_key(&blake2b, file_hash_nbytes, iv, iv_nbytes);

    uint8_t buf[4096];
    size_t len;
    while ((len = fread(buf, 1, 4096, fp_in)) > 0)
    {
        ret = vse_block_xcrypt_v1(cipher, &salsa20, &chacha, &aes, buf, len);
        if (ret != 0)
        {
            return ret;
        }

        if (mode == MODE_ENCRYPT)
        {
            // calculate hash after encrypt
            blake2b_update(&blake2b, buf, len);
        }

        if (fwrite(buf, 1, len, fp_out) != len)
        {
            vse_print_error("Error: Failed to write to output file: %s\n", strerror(errno));
            return ERR_ENCRYPT_V1_STREAM_CRYPT_FAILED_TO_WRITE_OUTFILE;
        }
    }

    if (!feof(fp_in))
    {
        vse_print_error("Error: Failed to read infile: %s", strerror(errno));
        return ERR_ENCRYPT_V1_STREAM_CRYPT_FAILED_TO_READ_INFILE;
    }

    blake2b_final(&blake2b, file_hash, file_hash_nbytes);

    return ret;
}

/**
 * Encrypt file.
 *
 * The MAC calculation is based on salt, iv and encrypted data
 * to provide authentication and integration.
 */
int vse_encrypt_file_v1(int cipher,
                        const char *password, size_t password_nbytes,
                        const char *infile, const char *outfile)
{
    int ret = 0;
    uint8_t key[KEY_LEN] = {0};
    uint8_t file_hash[FILE_HASH_LEN];
    vse_header_v1_t header;
    memset(&header, 0, sizeof(vse_header_v1_t));

    header.cipher = cipher;
    crypto_random(header.salt, SALT_LEN);
    crypto_random(header.iv, IV_LEN);

    vse_gen_key_v1(header.salt, SALT_LEN,
                   password, password_nbytes, KEY_LEN, key);

    FILE *fp_in = NULL;
    FILE *fp_out = NULL;
    do
    {
        fp_in = fopen(infile, "r");
        if (fp_in == NULL)
        {
            vse_print_error("Error: Failed to open input file %s: %s\n", infile, strerror(errno));
            ret = ERR_ENCRYPT_FILE_V1_FAIL_TO_OPEN_INPUT_FILE;
            break;
        }

        fp_out = fopen(outfile, "w");
        if (fp_out == NULL)
        {
            vse_print_error("Error: Failed to open output file %s: %s\n", outfile, strerror(errno));
            ret = ERR_ENCRYPT_FILE_V1_FAIL_TO_OPEN_OUTPUT_FILE;
            break;
        }

        uint8_t version = 1;
        if (fwrite(&version, 1, 1, fp_out) != 1)
        {
            vse_print_error("Error: Failed to write version: %s\n", strerror(errno));
            ret = ERR_ENCRYPT_FILE_V1_FAIL_TO_WRITE_VERSION;
            break;
        }

        if (fseek(fp_out, sizeof(vse_header_v1_t), SEEK_CUR) != 0)
        {
            vse_print_error("Error: Failed to seek to end of header: %s\n", strerror(errno));
            ret = ERR_ENCRYPT_FILE_V1_FAIL_TO_SEEK_END_OF_HEADER;
            break;
        }

        ret = vse_stream_crypt_v1(MODE_ENCRYPT,
                                  cipher,
                                  header.iv, IV_LEN,
                                  key, KEY_LEN,
                                  fp_in, fp_out,
                                  file_hash, FILE_HASH_LEN);

        if (ret != 0)
        {
            break;
        }

        vse_calculate_mac_v1(&header, file_hash, key, header.mac);

        // char hex_out[1000] = {0};
        // printf("enc: file_hash: %s\n", hexdump(file_hash, 16, hex_out));
        // printf("enc: mac: %s\n", hexdump(header.mac, 16, hex_out));

        if (fseek(fp_out, 1, SEEK_SET) != 0)
        {
            vse_print_error("Error: Failed to seek to v1 header of file %s: %s\n", outfile, strerror(errno));
            ret = ERR_ENCRYPT_FILE_OUTFILE_SEEK_TO_HEAD_FAILED;
            break;
        }

        if (fwrite(&header, sizeof(vse_header_v1_t), 1, fp_out) != 1)
        {
            vse_print_error("Error: Failed to write file header: %s", strerror(errno));
            ret = ERR_ENCRYPT_FILE_FAILED_TO_WRITE_HEADER;
            break;
        }
    } while (0);

    if (fp_in)
    {
        fclose(fp_in);
    }

    if (fp_out)
    {
        fclose(fp_out);
    }

    return ret;
}
