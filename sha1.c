/*
 * sha1.c
 * Thin wrapper around OpenSSL's SHA-1 to produce an uppercase hex string
 */

#include "breach_checker.h"

void sha1_hex(const char *input, char out_hex[SHA1_HEX_LEN + 1]) {
    unsigned char raw[SHA_DIGEST_LENGTH];   /* 20 bytes */
    SHA1((const unsigned char *)input, strlen(input), raw);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
        snprintf(out_hex + i * 2, 3, "%02X", raw[i]);

    out_hex[SHA1_HEX_LEN] = '\0';
}
