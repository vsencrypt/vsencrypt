#ifndef DECRYPT_V1_477D227B_E1BF_483D_A931_A17721B35150_H
#define DECRYPT_V1_477D227B_E1BF_483D_A931_A17721B35150_H

#include <stdlib.h>
#include <stdio.h>

int vse_decrypt_file_v1(const char *password, size_t password_nbytes,
                        FILE *fp_in, FILE *fp_out);

#endif