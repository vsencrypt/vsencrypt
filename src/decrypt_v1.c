#include <string.h>
#include <errno.h>
#include "vse.h"
#include "decrypt_v1.h"
#include "encrypt_v1.h"
#include "argon2/src/blake2/blake2.h"
#include "hexdump.h"
#include "chacha/poly1305.h"
#define BUF_SIZE 4096

static int vse_verify_mac(const vse_header_v1_t *header,
                          const uint8_t *key,
                          FILE *fp)
{
    int ret = 0;
    uint8_t mac[MAC_LEN] = {0};
    long pos = ftell(fp);

    uint8_t file_hash[FILE_HASH_LEN] = {0};
    blake2b_state blake2b;
    blake2b_init_key(&blake2b, FILE_HASH_LEN, header->iv, IV_LEN);

    uint8_t buf[BUF_SIZE];
    size_t len;
    while ((len = fread(buf, 1, BUF_SIZE, fp)) > 0)
    {
        blake2b_update(&blake2b, buf, len);
    }

    if (!feof(fp))
    {
        vse_print_error("Error: Failed to read infile: %s", strerror(errno));
        return ERR_DECRYPT_V1_FAILED_TO_READ_INFILE;
    }

    blake2b_final(&blake2b, file_hash, FILE_HASH_LEN);

    vse_calculate_mac_v1(header, file_hash, key, mac);

    // char hex_out[1000] = {0};
    // printf("dec: file_hash: %s\n", hexdump(file_hash, 16, hex_out));
    // printf("dec: header.mac: %s\n", hexdump(header->mac, 16, hex_out));
    // printf("dec: mac: %s\n", hexdump(mac, 16, hex_out));

    if (memcmp(mac, header->mac, MAC_LEN) != 0)
    {
        vse_print_error("Error: Invalid password\n");
        return ERR_DECRYPT_V1_INVALID_PASSWORD;
    }

    fseek(fp, pos, SEEK_SET);
    return ret;
}

int vse_decrypt_file_v1(const char *password, size_t password_nbytes,
                        FILE *fp_in, FILE *fp_out)
{
    int ret = 0;
    uint8_t key[KEY_LEN] = {0};
    uint8_t file_hash[FILE_HASH_LEN];

    vse_header_v1_t header = {0};
    if ((fread(&header, sizeof(vse_header_v1_t), 1, fp_in)) != 1)
    {
        vse_print_error("Error: Failed to read file header.\n");
        return ERR_DECRYPT_V1_FAIL_TO_READ_FILE_HEADER;
    }

    vse_gen_key_v1(header.salt, SALT_LEN,
                   password, password_nbytes,
                   KEY_LEN, key);

    ret = vse_verify_mac(&header, key, fp_in);
    if (ret != 0)
    {
        return ret;
    }

    ret = vse_stream_crypt_v1(MODE_DECRYPT,
                              header.cipher,
                              header.iv, IV_LEN,
                              key, KEY_LEN,
                              fp_in, fp_out,
                              file_hash, FILE_HASH_LEN);

    return ret;
}
