#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include "hexdump.h"
#include "aes/aes.h"
#include "argon2/include/argon2.h"
#include "argon2/src/blake2/blake2.h"
#include "getopt.h"
#include "getpass.h"
#include "error.h"
#include "chacha/chacha.h"
#include "salsa20/salsa20.h"

#include "crypto_random.h"
#include "encrypt_v1.h"
#include "decrypt_v1.h"

#define VERSION "1.0.0"

static int g_quite = 0;


void vse_print_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (!g_quite)
        vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static int vse_decrypt_file(const char *password, size_t password_nbytes,
                     const char *infile, const char *outfile)
{
    struct stat buf = {0};
    int ret = stat(infile, &buf);
    if (ret != 0)
    {
        vse_print_error("Error: Failed to open file %s: %s\n", infile, strerror(errno));
        return 1;
    }

    if (buf.st_size < FILE_HEADER_LEN)
    {
        vse_print_error("Error: File too small to decrypted: %s\n", infile);
        return 1;
    }

    FILE *fp_in = fopen(infile, "r");
    if (fp_in == NULL)
    {
        vse_print_error("Error: Failed to open file %s for read\n", infile);
        return 2;
    }

    u_int8_t version = 0;
    if (fread(&version, 1, 1, fp_in) != 1)
    {
        vse_print_error("Error: Failed to read 1st byte of file %s\n", infile);
        fclose(fp_in);
        return 3;
    }

    FILE *fp_out = fopen(outfile, "w");
    if (fp_out == NULL)
    {
        vse_print_error("Error: Failed to open file %s for write\n", outfile);
        fclose(fp_in);
        return 5;
    }

    if (version == 1)
    {
        ret = vse_decrypt_file_v1(password, password_nbytes, fp_in, fp_out);
    }
    else
    {
        vse_print_error("Error: Invalid version %d\n", version);
        ret = 5;
    }

    fclose(fp_in);
    fclose(fp_out);

    if (ret != 0)
    {
        // delete outfile
        unlink(outfile);
    }

    return ret;
}

static void vse_usage(const char *argv0)
{
    printf("NAME\n");
    printf("  %s -- Very secure file encryption.\n\n", argv0);
    printf("SYNOPSIS\n");
    printf("  %s [-h] [-v] [-q] -e|-d [-a cipher] -i infile [-o outfile] [-p password]\n\n", argv0);
    printf("DESCRIPTION\n");
    printf("  Use very strong cipher to encrypt/decrypt file.\n\n");
    printf("  The following options are available:\n\n");
    printf("  -h Help.\n\n");
    printf("  -v Show version.\n\n");
    printf("  -q Quiet. No error output.\n\n");
    printf("  -e Encryption.\n\n");
    printf("  -d Decryption.\n\n");
    printf("  -a Encryption cipher, used in encryption mode(-e) only.\n\n");
    printf("  -i <infile> Input file for encrypt/decrypt.\n\n");
    printf("  -o <infile> output file for encrypt/decrypt.\n\n");
    printf("  -p Password.\n\n");
    printf("EXAMPLES\n");
    printf("  Encryption:\n");
    printf("  vsencrypt -e -i foo.jpg -o foo.jpg.vse -p secret123\n");
    printf("  vsencrypt -e -i foo.jpg      # will output as foo.jpg.vse and ask password\n\n");
    printf("  Decryption:\n");
    printf("  vsencrypt -d -i foo.jpg.vse -d foo.jpg -p secret123\n");
    printf("  vsencrypt -d -i foo.jpg.vse  # will output as foo.jpg and ask password\n\n");
    printf("Version: %s\n", VERSION);
}

static int vse_parse_cipher(const char *cipher_name)
{
    int cipher = CIPHER_UNKNOWN;
    if (strcmp(cipher_name, "chacha20") == 0)
    {
        cipher = CIPHER_CHACHA20;
    }
    else if (strcmp(cipher_name, "aes_256_ctr") == 0)
    {
        cipher = CIPHER_AES_256_CTR;
    }
    else if (strcmp(cipher_name, "aes_256_ctr_chacha20") == 0)
    {
        cipher = CIPHER_AES_256_CTR_CHACHA20;
    }
    else if (strcmp(cipher_name, "chacha20_aes_256_ctr") == 0)
    {
        cipher = CIPHER_CHACHA20_AES_256_CTR;
    }
    else if (strcmp(cipher_name, "aes_256_ctr_salsa20") == 0)
    {
        cipher = CIPHER_AES_256_CTR_SALSA20;
    }
    else if (strcmp(cipher_name, "salsa20_aes_256_ctr") == 0)
    {
        cipher = CIPHER_SALSA20_AES_256_CTR;
    }
    else
    {
        // do nothing here.
    }

    return cipher;
}

static const char *gen_tmp_filename(const char *path)
{
    u_int8_t random_buf[4] = {0};
    char buf[10] = {0};
    crypto_random(random_buf, 4);

    char *ret = calloc(strlen(path) + 10, 1);
    strcpy(ret, path);
    strcat(ret, ".");
    strcat(ret, hexdump(random_buf, 4, buf));

    return ret;
}

int main(int argc, char *argv[])
{
    int mode = MODE_UNKNOWN;                  // encrypt or decrypt
    int cipher = CIPHER_AES_256_CTR_CHACHA20; // default cipher
    int opt;
    char *password = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    size_t password_nbytes = 0;

    while ((opt = getopt(argc, argv, "hvqedc:p:i:o:")) != -1)
    {
        switch (opt)
        {
        case 'h':
            vse_usage(argv[0]);
            return 0;
        case 'v':
            printf("version: %s\n", VERSION);
            return 0;
        case 'q':
            // quite mode, no error print.
            // Use exit code to determine encrypt/decrypt success/failure
            g_quite = 1;
            break;
        case 'e':
            mode = MODE_ENCRYPT;
            break;
        case 'd':
            mode = MODE_DECRYPT;
            break;
        case 'c':
            cipher = vse_parse_cipher(optarg);
            break;
        case 'i':
            infile = strdup(optarg);
            break;
        case 'o':
            outfile = strdup(optarg);
            break;
        case 'p':
            password = strdup(optarg);
            password_nbytes = strlen(password);
            break;
        default: /* '?' */
            vse_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (mode == MODE_UNKNOWN)
    {
        vse_usage(argv[0]);
        return 1;
    }

    if (mode == MODE_ENCRYPT && cipher == CIPHER_UNKNOWN)
    {
        vse_usage(argv[0]);
        return 1;
    }

    if (infile == NULL)
    {
        vse_usage(argv[0]);
        return 1;
    }

    if (outfile == NULL)
    {
        if (mode == MODE_ENCRYPT)
        {
            outfile = calloc(strlen(infile) + 5, 1);
            strcpy(outfile, infile);
            strcat(outfile, ".vse");
        }
        else
        {
            size_t infile_len = strlen(infile);
            if (infile_len > 5)
            {
                if (infile[infile_len - 1] == 'e' && infile[infile_len - 2] == 's' && infile[infile_len - 3] == 'v' && infile[infile_len - 4] == '.')
                {
                    outfile = strdup(infile);
                    outfile[infile_len - 4] = 0;
                }
            }
        }

        if (outfile == NULL)
        {
            vse_usage(argv[0]);
            return 1;
        }
    }

    if (password == NULL)
    {
        password = getpass("Password: ");
        password_nbytes = strlen(password);
    }

    const char *tmp_outfile = gen_tmp_filename(outfile);

    printf("mode=%d, cipher=%d, infile=%s, outfile=%s tmp_outfile=%s\n",
           mode, cipher, infile, outfile, tmp_outfile);

    int ret = 0;

    if (mode == MODE_ENCRYPT)
    {
        ret = vse_encrypt_file_v1(cipher, password, password_nbytes, infile, tmp_outfile);
    }
    else
    {
        ret = vse_decrypt_file(password, password_nbytes, infile, tmp_outfile);
    }

    if (ret == 0)
    {
        ret = rename(tmp_outfile, outfile);
        if (ret != 0)
        {
            vse_print_error("Error: Failed to rename output file: %s\n", strerror(errno));
        }
    }

    // if (optind >= argc)
    // {
    //     fprintf(stderr, "Expected argument after options\n");
    // }

    return ret;
}
