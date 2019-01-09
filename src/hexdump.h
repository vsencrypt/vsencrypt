#ifndef HEXDUMP_476675B9_BF18_4BFA_BD7C_193CEDE448CC_H
#define HEXDUMP_476675B9_BF18_4BFA_BD7C_193CEDE448CC_H

#include <stdint.h>

/**
 * Hex dump
 *
 * @param buf           buf to be dumped.
 * @param buf_nbytes    buf size in bytes.
 * @param hex_out       output in lower case.
 *                      buffer length should >= buf_nbytes*2 + 1
 */
const char *hexdump(const uint8_t *buf,
                    size_t buf_nbytes,
                    char *hex_out);
#endif
