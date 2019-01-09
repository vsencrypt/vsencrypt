#include <stdio.h>
#include "hexdump.h"

const char *hexdump(const uint8_t *buf,
                    size_t buf_nbytes,
                    char *hex_out)
{
    int i;

    for (i = 0; i < buf_nbytes; ++i)
    {
        sprintf((char *)(hex_out + i * 2), "%02x", buf[i]);
    }

    hex_out[buf_nbytes * 2] = 0;

    return hex_out;
}
