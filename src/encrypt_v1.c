#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "encrypt_v1.h"
#include "crypto_random.h"
#include "argon2.h"
#include "blake2.h"
#include "salsa20/salsa20.h"
#include "aes/aes.h"
#include "chacha/chacha.h"
#include "chacha/poly1305.h"

int vse_gen_key_v1(const u_int8_t *salt, size_t salt_nbytes,
                   const char *password, size_t password_nbytes,
                   size_t key_nbytes, u_int8_t *key)
{
    uint32_t time_cost = 8;           // 8-pass computation
    uint32_t memory_cost = (1 << 16); // 64 MB memory vse_usage
    uint32_t parallelism = 4;         // number of threads and lanes

    return argon2i_hash_raw(time_cost, memory_cost, parallelism,
                            password, password_nbytes,
                            salt, salt_nbytes,
                            key, key_nbytes);
}

int vse_stream_crypt_v1(int mode, int cipher,
                     const u_int8_t *iv, size_t iv_nbytes,
                     const u_int8_t *key, size_t key_nbytes,
                     FILE *fp_in, FILE *fp_out,
                     u_int8_t *file_hash, size_t file_hash_nbytes)
{
    int ret = 0;
    struct AES_ctx ctx;
    struct chacha_ctx chacha_ctx;
    salsa20_ctx_t salsa20;

    u_int8_t iv_aes[IV_LEN] = {0};
    u_int8_t iv_chacha[IV_LEN] = {0};
    u_int8_t iv_salsa20[IV_LEN] = {0};
    vse_gen_key_v1(iv, iv_nbytes, "aes", 3, IV_LEN, iv_aes);
    vse_gen_key_v1(iv, iv_nbytes, "chacha", 6, IV_LEN, iv_chacha);
    vse_gen_key_v1(iv, iv_nbytes, "salsa20", 7, IV_LEN, iv_chacha);

    AES_init_ctx_iv(&ctx, key, iv_aes);

    chacha_ivsetup(&chacha_ctx, iv_chacha, NULL);
    chacha_keysetup(&chacha_ctx, key, 256);

    salsa20_keysetup(&salsa20, key, 256, IV_LEN * 8);
    salsa20_ivsetup(&salsa20, iv_salsa20);

    blake2b_state blake2b;
    blake2b_init_key(&blake2b, file_hash_nbytes, iv, iv_nbytes);

    u_int8_t buf[4096];
    size_t len;
    while ((len = fread(buf, 1, 4096, fp_in)) > 0)
    {
        if (mode == MODE_ENCRYPT)
        {
            // calculate hash before encrypt
            blake2b_update(&blake2b, buf, len);
        }

        switch (cipher)
        {
        case CIPHER_SALSA20:
            salsa20_xcrypt_bytes(&salsa20, buf, buf, len);
            break;
        case CIPHER_CHACHA20:
            chacha_xcrypt_bytes(&chacha_ctx, buf, buf, len);
            break;
        case CIPHER_AES_256_CTR:
            AES_CTR_xcrypt_buffer(&ctx, buf, len);
            break;
        case CIPHER_AES_256_CTR_CHACHA20:
            AES_CTR_xcrypt_buffer(&ctx, buf, len);
            chacha_xcrypt_bytes(&chacha_ctx, buf, buf, len);
            break;
        case CIPHER_CHACHA20_AES_256_CTR:
            chacha_xcrypt_bytes(&chacha_ctx, buf, buf, len);
            AES_CTR_xcrypt_buffer(&ctx, buf, len);
            break;
        default:
            ret = ERR_STREAM_CRYPT_INVALID_CIPHER;
            break;
        }

        if (mode == MODE_DECRYPT)
        {
            // calculate hash after decrypt
            blake2b_update(&blake2b, buf, len);
        }

        if (fwrite(buf, len, 1, fp_out) != len)
        {
            return ERR_STREAM_CRYPT_WRITE;
        }
    }

    blake2b_final(&blake2b, file_hash, file_hash_nbytes);

    return ret;
}

int vse_encrypt_file_v1(int cipher,
                     const char *password, size_t password_nbytes,
                     const char *infile, const char *outfile)
{
    int ret = 0;
    u_int8_t key[KEY_LEN] = {0};
    u_int8_t file_hash[FILE_HASH_LEN];
    vsc_header_v1_t header;
    memset(&header, 0, sizeof(vsc_header_v1_t));

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
            break;
        }

        fp_out = fopen(outfile, "w");
        if (fp_out == NULL)
        {
            vse_print_error("Error: Failed to open output file %s: %s\n", outfile, strerror(errno));
            break;
        }

        u_int8_t version = 1;
        fwrite(&version, 1, 1, fp_out);
        fseek(fp_out, sizeof(vsc_header_v1_t), SEEK_CUR);
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

        u_int8_t message[SALT_LEN + IV_LEN + FILE_HASH_LEN] = {0};
        memcpy(message, header.salt, SALT_LEN);
        memcpy(message + SALT_LEN, header.iv, IV_LEN);
        memcpy(message + SALT_LEN + IV_LEN, file_hash, FILE_HASH_LEN);

        poly1305_auth(header.mac,
                      message, sizeof(message) / sizeof(u_int8_t),
                      key);

        ret = fseek(fp_out, 1, SEEK_SET);
        if (ret != 0)
        {
            vse_print_error("Error: Failed to seek to file %s: %s", outfile, strerror(errno));
            ret = ERR_ENCRYPT_FILE_OUTFILE_SEEK_TO_HEAD_FAILED;
            break;
        }

        ret = fwrite(&header, sizeof(vsc_header_v1_t), 1, fp_out);
        if (ret != 1)
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
