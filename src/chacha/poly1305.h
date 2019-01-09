/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/*
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ifndef POLY1305_H
#define POLY1305_H

#include <stdint.h>
#include <sys/types.h>

#if _MSC_VER
#ifndef __attribute__
#define __attribute__(x)
#endif
#endif

#define POLY1305_KEYLEN 32
#define POLY1305_TAGLEN 16

void poly1305_auth(uint8_t mac[POLY1305_TAGLEN],
                   const uint8_t *message, size_t message_nbytes,
                   const uint8_t key[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#endif /* POLY1305_H */
