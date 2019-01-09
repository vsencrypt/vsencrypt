#ifndef ENCRYPT_V1_7A1117C3_0261_4E14_BF34_3A56489A0D9A_H
#define ENCRYPT_V1_7A1117C3_0261_4E14_BF34_3A56489A0D9A_H

#include "vse.h"

int vse_gen_key_v1(const uint8_t *salt, size_t salt_nbytes,
                   const char *password, size_t password_nbytes,
                   size_t key_nbytes, uint8_t *key);

int vse_stream_crypt_v1(int mode, int cipher,
                        const uint8_t *iv, size_t iv_nbytes,
                        const uint8_t *key, size_t key_nbytes,
                        FILE *fp_in, FILE *fp_out,
                        uint8_t *file_hash, size_t file_hash_nbytes);

void vse_calculate_mac_v1(const vse_header_v1_t *header,
                          const uint8_t *file_hash, // size: FILE_HASH_LEN
                          const uint8_t *key,       // size: KEY_LEN
                          uint8_t *mac);            // output

int vse_encrypt_file_v1(int cipher,
                        const char *password, size_t password_nbytes,
                        const char *infile, const char *outfile);

#endif
