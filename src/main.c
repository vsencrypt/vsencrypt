#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#include "hexdump.h"
#include "getopt.h"
#include "getpass.h"
#include "error.h"
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
    int ret = 0;
    FILE *fp_in = NULL;
    FILE *fp_out = NULL;

    do
    {
        struct stat buf;
        if (stat(infile, &buf) != 0)
        {
            vse_print_error("Error: Failed to stat file %s: %s\n", infile, strerror(errno));
            ret = ERR_DECRYPT_FILE_FAILED_TO_STAT_INPUT_FILE;
            break;
        }

        if (buf.st_size < FILE_HEADER_LEN)
        {
            vse_print_error("Error: File too small to decrypted: %s\n", infile);
            ret = ERR_DECRYPT_FILE_INPUT_FILE_SIZE_TOO_SMALL;
            break;
        }

        fp_in = fopen(infile, "r");
        if (fp_in == NULL)
        {
            vse_print_error("Error: Failed to open file %s for read\n", infile);
            ret = ERR_DECRYPT_FILE_FAILED_TO_OPEN_INPUT_FILE;
            break;
        }

        u_int8_t version = 0;
        if (fread(&version, 1, 1, fp_in) != 1)
        {
            vse_print_error("Error: Failed to read 1st byte of file %s\n", infile);
            ret = ERR_DECRYPT_FILE_FAILED_TO_OPEN_INPUT_FILE;
            break;
        }

        if (version != 1)
        {
            vse_print_error("Error: Invalid version %d\n", version);
            ret = ERR_DECRYPT_FILE_INVALID_VERSION;
            break;
        }

        fp_out = fopen(outfile, "w");
        if (fp_out == NULL)
        {
            vse_print_error("Error: Failed to open file %s for write\n", outfile);
            ret = ERR_DECRYPT_FILE_FAILED_TO_OPEN_OUTPUT_FILE;
            break;
        }

        switch (version)
        {
        case 1:
            ret = vse_decrypt_file_v1(password, password_nbytes, fp_in, fp_out);
            break;
        default:
            assert(!"BUG: un-handled version");
        }

    } while (0);

    if (fp_in != NULL)
    {
        fclose(fp_in);
    }

    if (fp_out != NULL)
    {
        fclose(fp_out);
    }

    return ret;
}

static void vse_usage(const char *argv0)
{
    printf("NAME\n");
    printf("  %s -- Very secure file encryption.\n\n", argv0);
    printf("SYNOPSIS\n");
    printf("  %s [-h] [-v] [-q] [-f] -e|-d [-a cipher] -i infile [-o outfile] [-p password]\n\n", argv0);
    printf("DESCRIPTION\n");
    printf("  Use very strong cipher to encrypt/decrypt file.\n\n");
    printf("  The following options are available:\n\n");
    printf("  -h Help.\n\n");
    printf("  -v Show version.\n\n");
    printf("  -q Quiet. No error output.\n\n");
    printf("  -f Force override output file if already exist.\n\n");
    printf("  -e Encryption.\n\n");
    printf("  -d Decryption.\n\n");
    printf("  -a Encryption cipher, used in encryption mode(-e) only.\n\n");
    printf("     Available ciphers:\n\n");
    printf("     chacha20         256bit, faster than AES 256.\n");
    printf("     salsa20          256bit, faster than AES 256.\n");
    printf("     aes256           AES 256bit in CTR mode.\n");
    printf("     aes256_chacha20  aes256 then chacha20 (default cipher).\n");
    printf("     aes256_salsa20   aes256 then salsa20.\n");
    printf("     chacha20_aes256  chacha20 then aes256.\n");
    printf("     salsa20_aes256   salsa20 then aes256.\n\n");
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
    if (strcmp(cipher_name, "chacha20") == 0 || strcmp(cipher_name, "chacha") == 0)
    {
        cipher = CIPHER_CHACHA20;
    }
    else if (strcmp(cipher_name, "salsa20") == 0)
    {
        cipher = CIPHER_SALSA20;
    }
    else if (strcmp(cipher_name, "aes") == 0 || strcmp(cipher_name, "aes256") == 0)
    {
        cipher = CIPHER_AES_256_CTR;
    }
    else if (strcmp(cipher_name, "aes256_chacha20") == 0)
    {
        cipher = CIPHER_AES_256_CTR_CHACHA20;
    }
    else if (strcmp(cipher_name, "chacha20_aes256") == 0)
    {
        cipher = CIPHER_CHACHA20_AES_256_CTR;
    }
    else if (strcmp(cipher_name, "aes256_salsa20") == 0)
    {
        cipher = CIPHER_AES_256_CTR_SALSA20;
    }
    else if (strcmp(cipher_name, "salsa20_aes256") == 0)
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
    int ret = 0;
    int mode = MODE_UNKNOWN;                  // encrypt or decrypt
    int cipher = CIPHER_AES_256_CTR_CHACHA20; // default cipher
    int opt;
    int force_override_outfile = 0;
    char *password = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    size_t password_nbytes = 0;

    opterr = 0; // do not allow getopt() print any error.

    while ((opt = getopt(argc, argv, "hvqfedc:p:i:o:")) != -1)
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
        case 'f':
            force_override_outfile = 1;
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
            vse_print_error("Error: Illegal option \"-%c\".\n", optopt);
            vse_print_error("       Use \"%s -h\" to see all available options.\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (mode == MODE_UNKNOWN)
    {
        vse_print_error("Error: Missing -e or -d.\n");
        return 1;
    }

    if (mode == MODE_ENCRYPT && cipher == CIPHER_UNKNOWN)
    {
        vse_print_error("Error: Invalid cipher.\n");
        return 1;
    }

    if (infile == NULL)
    {
        vse_print_error("Error: Missing -i\n");
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
            vse_print_error("Error: missing -o\n");
            return 1;
        }
    }

    struct stat stat_buf;
    if (force_override_outfile == 0 && stat(outfile, &stat_buf) == 0)
    {
        vse_print_error("Error: output file %s already exist. Use -f to force override it.\n", outfile);
        return ERR_MAIN_OUTPUT_FILE_ALREADY_EXIST;
    }

    if (password == NULL)
    {
        password = getpass("Password: ");
        password_nbytes = strlen(password);
    }

    const char *tmp_outfile = gen_tmp_filename(outfile);

    // printf("mode=%d, cipher=0x%x, infile=%s, outfile=%s tmp_outfile=%s\n",
    //       mode, cipher, infile, outfile, tmp_outfile);

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

            // delete temporial outfile
            unlink(tmp_outfile);
        }
    }
    else
    {
        // delete temporial outfile
        unlink(tmp_outfile);
    }

    // if (optind >= argc)
    // {
    //     fprintf(stderr, "Expected argument after options\n");
    // }

    return ret;
}
