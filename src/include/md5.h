/**
 * $Id$
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file md5.h
 * @brief Structures and prototypes for md5.
 */

#ifndef _FR_MD5_H
#define _FR_MD5_H

RCSIDH(md5_h, "$Id$")

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#  include <string.h>

#ifdef WITH_FIPS
#undef HAVE_OPENSSL_MD5_H
#endif

#ifdef HAVE_OPENSSL_MD5_H
#  include <openssl/md5.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MD5_DIGEST_LENGTH
#  define MD5_DIGEST_LENGTH 16
#endif

#ifndef HAVE_OPENSSL_MD5_H
/*
 * The MD5 code used here and in md5.c was originally retrieved from:
 *   http://www.openbsd.org/cgi-bin/cvsweb/~checkout~/src/sys/crypto/md5.h?rev=1.1
 *
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */
#  define MD5_BLOCK_LENGTH 64
typedef struct FR_MD5Context {
	uint32_t state[4];			//!< State.
	uint32_t count[2];			//!< Number of bits, mod 2^64.
	uint8_t buffer[MD5_BLOCK_LENGTH];	//!< Input buffer.
} FR_MD5_CTX;

void 	fr_md5_init(FR_MD5_CTX *ctx);
void	fr_md5_update(FR_MD5_CTX *ctx, uint8_t const *in, size_t inlen)
	CC_BOUNDED(__string__, 2, 3);
void	fr_md5_final(uint8_t out[MD5_DIGEST_LENGTH], FR_MD5_CTX *ctx)
	CC_BOUNDED(__minbytes__, 1, MD5_DIGEST_LENGTH);
void	fr_md5_transform(uint32_t state[4], uint8_t const block[MD5_BLOCK_LENGTH])
	CC_BOUNDED(__size__, 1, 4, 4)
	CC_BOUNDED(__minbytes__, 2, MD5_BLOCK_LENGTH);
#  define fr_md5_destroy(_x)
#  define fr_md5_copy(_dst, _src) _dst = _src
#else  /* HAVE_OPENSSL_MD5_H */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
USES_APPLE_DEPRECATED_API
#  define FR_MD5_CTX		MD5_CTX
#  define fr_md5_init		MD5_Init
#  define fr_md5_update		MD5_Update
#  define fr_md5_final		MD5_Final
#  define fr_md5_transform	MD5_Transform
#  define fr_md5_copy(_dst, _src) _dst = _src
#  define fr_md5_destroy(_x)
#else
#include <openssl/evp.h>

/*
 *	Wrappers for OpenSSL3, so we don't have to butcher the rest of
 *	the code too much.
 */
typedef EVP_MD_CTX* FR_MD5_CTX;

#  define fr_md5_init(_ctx) \
	do { \
		*_ctx = EVP_MD_CTX_new(); \
		EVP_MD_CTX_set_flags(*_ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW); \
		EVP_DigestInit_ex(*_ctx, EVP_md5(), NULL); \
	} while (0)
#  define fr_md5_update(_ctx, _str, _len) \
        EVP_DigestUpdate(*_ctx, _str, _len)
#  define fr_md5_final(_out, _ctx) \
	EVP_DigestFinal_ex(*_ctx, _out, NULL)
#  define fr_md5_destroy(_ctx)	EVP_MD_CTX_destroy(*_ctx)
#  define fr_md5_copy(_dst, _src) EVP_MD_CTX_copy_ex(_dst, _src)
#endif	/* OPENSSL3 */
#endif	/* HAVE_OPENSSL_MD5_H */

/* hmac.c */
void	fr_hmac_md5(uint8_t digest[MD5_DIGEST_LENGTH], uint8_t const *text, size_t text_len,
		    uint8_t const *key, size_t key_len)
	CC_BOUNDED(__minbytes__, 1, MD5_DIGEST_LENGTH);

/* md5.c */
void	fr_md5_calc(uint8_t *out, uint8_t const *in, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* _FR_MD5_H */
