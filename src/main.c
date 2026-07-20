#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>
#if _MSC_VER
#include <Windows.h>
#else
#include <dirent.h>
#endif
#include "hexdump.h"
#include "getopt.h"
#include "getpass.h"
#include "error.h"
#include "crypto_random.h"
#include "encrypt_v1.h"
#include "decrypt_v1.h"

#define VERSION "1.0.1"

static int g_quiet = 0;

void vse_print_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (!g_quiet)
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

        fp_in = fopen(infile, "rb");
        if (fp_in == NULL)
        {
            vse_print_error("Error: Failed to open file %s for read\n", infile);
            ret = ERR_DECRYPT_FILE_FAILED_TO_OPEN_INPUT_FILE;
            break;
        }

        uint8_t version = 0;
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

        fp_out = fopen(outfile, "wb");
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
    printf("  %s [-h] [-v] [-q] [-f] [-D] -e|-d [-a cipher] -i infile|infolder [-o outfile|outfolder] [-p password]\n\n", argv0);
    printf("DESCRIPTION\n");
    printf("  Use very strong cipher to encrypt/decrypt file.\n\n");
    printf("  The following options are available:\n\n");
    printf("  -h Help.\n\n");
    printf("  -v Show version.\n\n");
    printf("  -q Quiet mode. No error output.\n\n");
    printf("  -f Force override output file if already exist.\n\n");
    printf("  -D Delete input file if encrypt/decrypt success.\n\n");
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
    printf("  -i <infile|infolder>  Input file or folder for encrypt/decrypt.\n");
    printf("                        When a folder is given, all non-empty regular files are\n");
    printf("                        processed recursively.\n\n");
    printf("  -o <outfile|outfolder>  Output file (single-file mode) or output folder\n");
    printf("                          (folder mode). In folder mode the directory tree is\n");
    printf("                          mirrored; the folder is created if it does not exist.\n");
    printf("                          Omit to process files in-place.\n\n");
    printf("  -p Password.\n\n");
    printf("EXAMPLES\n");
    printf("  Encryption:\n");
    printf("  %s -e -i foo.jpg -o foo.jpg.vse -p secret123\n", argv0);
    printf("  %s -e -i foo.jpg      # will output as foo.jpg.vse and ask password\n", argv0);
    printf("  %s -e -i src/ -o enc/ -p secret123  # encrypt tree src/ into enc/\n", argv0);
    printf("  %s -e -i src/ -p secret123          # encrypt in-place inside src/\n\n", argv0);
    printf("  Decryption:\n");
    printf("  %s -d -i foo.jpg.vse -o foo.jpg -p secret123\n", argv0);
    printf("  %s -d -i foo.jpg.vse  # will output as foo.jpg and ask password\n", argv0);
    printf("  %s -d -i enc/ -o dec/ -p secret123  # decrypt tree enc/ into dec/\n", argv0);
    printf("  %s -d -i enc/ -p secret123          # decrypt in-place inside enc/\n\n", argv0);
    printf("Version: %s\n\n", VERSION);
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
    uint8_t random_buf[4] = {0};
    char buf[10] = {0};
    crypto_random(random_buf, 4);

    char *ret = calloc(strlen(path) + 10, 1);
    strcpy(ret, path);
    strcat(ret, ".");
    strcat(ret, hexdump(random_buf, 4, buf));

    return ret;
}

/* Returns a pointer to the filename component of path (after the last / or \). */
static const char *path_basename(const char *path)
{
    const char *p = strrchr(path, '/');
    const char *q = strrchr(path, '\\');
    if (p == NULL && q == NULL)
        return path;
    if (p == NULL)
        return q + 1;
    if (q == NULL)
        return p + 1;
    return (p > q ? p : q) + 1;
}

/*
 * Given a bare filename (no directory), returns a malloc'd output filename, or
 * NULL if the name cannot be derived (decrypt mode and name lacks .vse suffix).
 */
static char *derive_outname(int mode, const char *name)
{
    if (mode == MODE_ENCRYPT)
    {
        char *out = calloc(strlen(name) + 5, 1);
        strcpy(out, name);
        strcat(out, ".vse");
        return out;
    }
    size_t len = strlen(name);
    if (len > 5 &&
        name[len - 1] == 'e' && name[len - 2] == 's' &&
        name[len - 3] == 'v' && name[len - 4] == '.')
    {
        char *out = strdup(name);
        out[len - 4] = 0;
        return out;
    }
    return NULL;
}

/* Returns a malloc'd output path for infile (output in the same directory), or NULL. */
static char *derive_outfile(int mode, const char *infile)
{
    const char *name = path_basename(infile);
    char *outname = derive_outname(mode, name);
    if (outname == NULL)
        return NULL;
    if (name == infile)
        return outname;
    size_t dir_len = (size_t)(name - infile);
    char *out = malloc(dir_len + strlen(outname) + 1);
    memcpy(out, infile, dir_len);
    strcpy(out + dir_len, outname);
    free(outname);
    return out;
}

/* Create a single directory level. Returns 0 on success or if already exists. */
static int make_dir(const char *path)
{
#if _MSC_VER
    if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
        return 0;
    return -1;
#else
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    return -1;
#endif
}

/* Encrypt or decrypt infile to outfile via a temp file, then rename into place. */
static int run_on_file(int mode, int cipher,
                       const char *password, size_t password_nbytes,
                       const char *infile, const char *outfile,
                       int delete_infile)
{
    const char *tmp_outfile = gen_tmp_filename(outfile);
    int ret;

    if (mode == MODE_ENCRYPT)
        ret = vse_encrypt_file_v1(cipher, password, password_nbytes, infile, tmp_outfile);
    else
        ret = vse_decrypt_file(password, password_nbytes, infile, tmp_outfile);

    if (ret == 0)
    {
        struct stat stat_buf;
        if (stat(outfile, &stat_buf) == 0)
            unlink(outfile);

        ret = rename(tmp_outfile, outfile);
        if (ret != 0)
        {
            vse_print_error("Error: Failed to rename output file: %s\n", strerror(errno));
            unlink(tmp_outfile);
        }
    }
    else
    {
        unlink(tmp_outfile);
    }

    free((void *)tmp_outfile);

    if (ret == 0 && delete_infile)
        unlink(infile);

    return ret;
}

/*
 * Recursively process all non-empty regular files under infolder.
 * outfolder: mirror directory for output, or NULL to write output in-place (next to input).
 * Returns the first non-zero error encountered, or 0.
 */
static int process_folder(int mode, int cipher,
                           const char *password, size_t password_nbytes,
                           const char *infolder, const char *outfolder,
                           int force_override, int delete_infile)
{
    int any_error = 0;

#if _MSC_VER
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", infolder);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        vse_print_error("Error: Failed to open folder %s\n", infolder);
        return 1;
    }

    do
    {
        if (fd.cFileName[0] == '.')
            continue;

        size_t path_len = strlen(infolder) + 1 + strlen(fd.cFileName) + 1;
        char *filepath = malloc(path_len);
        snprintf(filepath, path_len, "%s\\%s", infolder, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            char *suboutfolder = NULL;
            if (outfolder != NULL)
            {
                size_t out_len = strlen(outfolder) + 1 + strlen(fd.cFileName) + 1;
                suboutfolder = malloc(out_len);
                snprintf(suboutfolder, out_len, "%s\\%s", outfolder, fd.cFileName);
                if (make_dir(suboutfolder) != 0)
                {
                    vse_print_error("Error: Failed to create directory %s\n", suboutfolder);
                    free(suboutfolder);
                    free(filepath);
                    if (any_error == 0) any_error = 1;
                    continue;
                }
            }
            int ret = process_folder(mode, cipher, password, password_nbytes,
                                     filepath, suboutfolder, force_override, delete_infile);
            if (ret != 0 && any_error == 0) any_error = ret;
            free(suboutfolder);
            free(filepath);
            continue;
        }

        if (fd.nFileSizeLow == 0 && fd.nFileSizeHigh == 0)
        {
            free(filepath);
            continue;
        }

        char *outfile;
        if (outfolder != NULL)
        {
            char *outname = derive_outname(mode, fd.cFileName);
            if (outname == NULL)
            {
                vse_print_error("Warning: Skipping %s: cannot derive output filename\n", filepath);
                free(filepath);
                continue;
            }
            size_t out_len = strlen(outfolder) + 1 + strlen(outname) + 1;
            outfile = malloc(out_len);
            snprintf(outfile, out_len, "%s\\%s", outfolder, outname);
            free(outname);
        }
        else
        {
            outfile = derive_outfile(mode, filepath);
            if (outfile == NULL)
            {
                vse_print_error("Warning: Skipping %s: cannot derive output filename\n", filepath);
                free(filepath);
                continue;
            }
        }

        struct stat st;
        if (!force_override && stat(outfile, &st) == 0)
        {
            vse_print_error("Warning: Skipping %s: output %s already exists. Use -f to override.\n",
                            filepath, outfile);
            free(outfile);
            free(filepath);
            continue;
        }

        int ret = run_on_file(mode, cipher, password, password_nbytes,
                              filepath, outfile, delete_infile);
        if (ret != 0)
        {
            vse_print_error("Error: Failed to process %s: %d\n", filepath, ret);
            if (any_error == 0) any_error = ret;
        }

        free(outfile);
        free(filepath);
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
#else
    DIR *dir = opendir(infolder);
    if (dir == NULL)
    {
        vse_print_error("Error: Failed to open folder %s: %s\n", infolder, strerror(errno));
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;

        size_t path_len = strlen(infolder) + 1 + strlen(entry->d_name) + 1;
        char *filepath = malloc(path_len);
        snprintf(filepath, path_len, "%s/%s", infolder, entry->d_name);

        struct stat st;
        if (stat(filepath, &st) != 0)
        {
            free(filepath);
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            char *suboutfolder = NULL;
            if (outfolder != NULL)
            {
                size_t out_len = strlen(outfolder) + 1 + strlen(entry->d_name) + 1;
                suboutfolder = malloc(out_len);
                snprintf(suboutfolder, out_len, "%s/%s", outfolder, entry->d_name);
                if (make_dir(suboutfolder) != 0)
                {
                    vse_print_error("Error: Failed to create directory %s: %s\n",
                                    suboutfolder, strerror(errno));
                    free(suboutfolder);
                    free(filepath);
                    if (any_error == 0) any_error = 1;
                    continue;
                }
            }
            int ret = process_folder(mode, cipher, password, password_nbytes,
                                     filepath, suboutfolder, force_override, delete_infile);
            if (ret != 0 && any_error == 0) any_error = ret;
            free(suboutfolder);
            free(filepath);
            continue;
        }

        if (!S_ISREG(st.st_mode) || st.st_size == 0)
        {
            free(filepath);
            continue;
        }

        char *outfile;
        if (outfolder != NULL)
        {
            char *outname = derive_outname(mode, entry->d_name);
            if (outname == NULL)
            {
                vse_print_error("Warning: Skipping %s: cannot derive output filename\n", filepath);
                free(filepath);
                continue;
            }
            size_t out_len = strlen(outfolder) + 1 + strlen(outname) + 1;
            outfile = malloc(out_len);
            snprintf(outfile, out_len, "%s/%s", outfolder, outname);
            free(outname);
        }
        else
        {
            outfile = derive_outfile(mode, filepath);
            if (outfile == NULL)
            {
                vse_print_error("Warning: Skipping %s: cannot derive output filename\n", filepath);
                free(filepath);
                continue;
            }
        }

        if (!force_override && stat(outfile, &st) == 0)
        {
            vse_print_error("Warning: Skipping %s: output %s already exists. Use -f to override.\n",
                            filepath, outfile);
            free(outfile);
            free(filepath);
            continue;
        }

        int ret = run_on_file(mode, cipher, password, password_nbytes,
                              filepath, outfile, delete_infile);
        if (ret != 0)
        {
            vse_print_error("Error: Failed to process %s: %d\n", filepath, ret);
            if (any_error == 0) any_error = ret;
        }

        free(outfile);
        free(filepath);
    }

    closedir(dir);
#endif

    return any_error;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    int mode = MODE_UNKNOWN;                  // encrypt or decrypt
    int cipher = CIPHER_AES_256_CTR_CHACHA20; // default cipher
    int opt;
    int force_override_outfile = 0;
    int delete_infile = 0;
    const char *password = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    size_t password_nbytes = 0;

    opterr = 0; // do not allow getopt() print any error.

    while ((opt = getopt(argc, argv, "hvqfDedc:p:i:o:")) != -1)
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
            // quiet mode, no error print.
            // Use exit code to determine encrypt/decrypt success/failure
            g_quiet = 1;
            break;
        case 'f':
            force_override_outfile = 1;
            break;
        case 'D':
            delete_infile = 1;
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
        vse_usage(argv[0]);
        return 1;
    }

    if (mode == MODE_ENCRYPT && cipher == CIPHER_UNKNOWN)
    {
        vse_print_error("Error: Invalid cipher.\n");
        vse_usage(argv[0]);
        return 1;
    }

    if (infile == NULL)
    {
        vse_print_error("Error: Missing -i\n");
        vse_usage(argv[0]);
        return 1;
    }

    // Folder mode: process recursively.
    struct stat infile_stat;
    if (stat(infile, &infile_stat) == 0 && S_ISDIR(infile_stat.st_mode))
    {
        const char *outfolder = outfile;

        if (outfolder != NULL)
        {
            struct stat out_stat;
            if (stat(outfolder, &out_stat) == 0)
            {
                if (!S_ISDIR(out_stat.st_mode))
                {
                    vse_print_error("Error: -o %s already exists and is not a folder\n", outfolder);
                    return 1;
                }
                // exists and is a directory: OK
            }
            else
            {
                if (make_dir(outfolder) != 0)
                {
                    vse_print_error("Error: Failed to create output folder %s: %s\n",
                                    outfolder, strerror(errno));
                    return 1;
                }
            }
        }

        if (password == NULL)
        {
            password = getpass("Password: ");
            password_nbytes = strlen(password);
        }

        return process_folder(mode, cipher, password, password_nbytes,
                              infile, outfolder, force_override_outfile, delete_infile);
    }

    // Single-file mode.
    if (outfile == NULL)
    {
        outfile = derive_outfile(mode, infile);
        if (outfile == NULL)
        {
            vse_print_error("Error: missing -o\n");
            vse_usage(argv[0]);
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

    ret = run_on_file(mode, cipher, password, password_nbytes,
                      infile, outfile, delete_infile);

    return ret;
}
