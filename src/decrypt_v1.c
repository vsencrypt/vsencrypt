#include <string.h>
#include "decrypt_v1.h"
#include "encrypt_v1.h"
#include "vse.h"
#include "hexdump.h"
#include "chacha/poly1305.h"

int vse_decrypt_file_v1(const char *password, size_t password_nbytes,
                        FILE *fp_in, FILE *fp_out)
{
    int ret = 0;
    u_int8_t key[KEY_LEN] = {0};
    u_int8_t file_hash[FILE_HASH_LEN];

    vsc_header_v1_t header = {0};
    if ((fread(&header, sizeof(vsc_header_v1_t), 1, fp_in)) != 1)
    {
        vse_print_error("Error: Failed to read file header.\n");
        return ERR_DECRYPT_V1_FAIL_TO_READ_FILE_HEADER;
    }

    vse_gen_key_v1(header.salt, SALT_LEN,
                   password, password_nbytes, KEY_LEN, key);

    ret = vse_stream_crypt_v1(MODE_DECRYPT,
                           header.cipher,
                           header.iv, IV_LEN,
                           key, KEY_LEN,
                           fp_in, fp_out,
                           file_hash, FILE_HASH_LEN);

    if (ret != 0)
    {
        return ret;
    }

    u_int8_t message[SALT_LEN + IV_LEN + FILE_HASH_LEN] = {0};
    memcpy(message, header.salt, SALT_LEN);
    memcpy(message + SALT_LEN, header.iv, IV_LEN);
    memcpy(message + SALT_LEN + IV_LEN, file_hash, FILE_HASH_LEN);

    u_int8_t mac[MAC_LEN] = {0};
    poly1305_auth(mac,
                  message, sizeof(message) / sizeof(u_int8_t),
                  key);

    // char hex_out[1000] = {0};
    // printf("file_hash: %s\n", hexdump(file_hash, 16, hex_out));
    // printf("header.mac: %s\n", hexdump(header.mac, 16, hex_out));
    // printf("mac: %s\n", hexdump(mac, 16, hex_out));

    if (memcmp(mac, header.mac, MAC_LEN) != 0)
    {
        vse_print_error("Error: Invalid password\n");
        return 1;
    }

    return ret;
}
