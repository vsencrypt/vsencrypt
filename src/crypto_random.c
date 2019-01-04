#include "crypto_random.h"

void crypto_random(void *buf, size_t nbytes)
{
// use a cryptographic pseudo-random number
// generator to generate high quality random
// bytes very quickly.
#if __APPLE__
    arc4random_buf(buf, nbytes);
#elif __linux
    FILE *fp = fopen("/dev/random", "r");
    if (fp == NULL)
    {
        return;
    }
    fread(buf, 1, nbytes, fp);
    fclose(fp);
#elif __WIN32
#error "TODO"
#elif __WIN64
#error "TODO"
#endif
}