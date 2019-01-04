#ifndef CRYPTO_RANDOM_E61CEB7E_6B01_4C44_ACF6_FAF340C4876C_H
#define CRYPTO_RANDOM_E61CEB7E_6B01_4C44_ACF6_FAF340C4876C_H

#include <stdlib.h>

/**
 * Generate crypto random.
 *
 * used this function to generate iv, salt etc.
 */
void crypto_random(void *buf, size_t nbytes);

#endif
