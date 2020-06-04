#pragma once
/** Local implementation of the SHA1 hashing scheme
 *
 * SHA-1 in C 100% Public Domain
 *
 * @file src/lib/util/sha1.h
 *
 * @author Steve Reid (steve@edmweb.com)
 */
RCSIDH(sha1_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#ifdef WITH_OPENSSL_SHA1
#  include <openssl/sha.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifndef SHA1_DIGEST_LENGTH
#  define SHA1_DIGEST_LENGTH 20
#endif

#ifndef WITH_OPENSSL_SHA1
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} fr_sha1_ctx;

void fr_sha1_transform(uint32_t state[static 5], uint8_t const buffer[static 64]);
void fr_sha1_init(fr_sha1_ctx *context);
void fr_sha1_update(fr_sha1_ctx *context, uint8_t const *in, size_t len);
void fr_sha1_final(uint8_t digest[static SHA1_DIGEST_LENGTH], fr_sha1_ctx *context);

/*
 * this version implements a raw SHA1 transform, no length is appended,
 * nor any 128s out to the block size.
 */
void fr_sha1_final_no_len(uint8_t digest[static SHA1_DIGEST_LENGTH], fr_sha1_ctx* context);

#else  /* WITH_OPENSSL_SHA1 */
USES_APPLE_DEPRECATED_API
#  define fr_sha1_ctx	SHA_CTX
#  define fr_sha1_init	SHA1_Init
#  define fr_sha1_update	SHA1_Update
#  define fr_sha1_final	SHA1_Final
#  define fr_sha1_transform SHA1_Transform
#endif

/* hmacsha1.c */

void fr_hmac_sha1(uint8_t digest[static SHA1_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		  uint8_t const *key, size_t key_len);

#ifdef __cplusplus
}
#endif
