#ifndef _FR_SHA1_H
#define _FR_SHA1_H

#ifdef WITH_OPENSSL_SHA1
#include <openssl/sha.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SHA1_DIGEST_LENGTH
#  define SHA1_DIGEST_LENGTH 20
#endif

#ifndef WITH_OPENSSL_SHA1
typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} fr_sha1_ctx;

void fr_sha1_transform(uint32_t state[5], uint8_t const buffer[64]);
void fr_sha1_init(fr_sha1_ctx *context);
void fr_sha1_update(fr_sha1_ctx *context, uint8_t const *data, size_t len);
void fr_sha1_final(uint8_t digest[20], fr_sha1_ctx *context);

/*
 * this version implements a raw SHA1 transform, no length is appended,
 * nor any 128s out to the block size.
 */
void fr_sha1_final_no_len(uint8_t digest[20], fr_sha1_ctx* context);

#else  /* WITH_OPENSSL_SHA1 */
USES_APPLE_DEPRECATED_API
#define fr_sha1_ctx	SHA_CTX
#define fr_sha1_init	SHA1_Init
#define fr_sha1_update	SHA1_Update
#define fr_sha1_final	SHA1_Final
#define fr_sha1_transform SHA1_Transform
#endif

/*
 * FIPS 186-2 PRF based upon SHA1.
 */
void fips186_2prf(uint8_t mk[20], uint8_t finalkey[160]);

/* hmacsha1.c */

void fr_hmac_sha1(uint8_t digest[SHA1_DIGEST_LENGTH], uint8_t const *text, size_t text_len,
		  uint8_t const *key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif /* _FR_SHA1_H */
