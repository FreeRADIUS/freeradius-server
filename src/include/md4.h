/**
 * $Id$
 *
 * @note license is LGPL, but largely derived from a public domain source.
 *
 * @file md4.h
 * @brief Structures and prototypes for md4.
 */

#ifndef _FR_MD4_H
#define _FR_MD4_H

RCSIDH(md4_h, "$Id$")

#ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_STDINT_H
#  include <stdint.h>
#endif

#include <string.h>

#ifdef WITH_FIPS
#undef HAVE_OPENSSL_MD4_H
#endif

#ifdef HAVE_OPENSSL_MD4_H
#  include <openssl/md4.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MD4_DIGEST_LENGTH
#  define MD4_DIGEST_LENGTH 16
#endif

#ifndef HAVE_OPENSSL_MD4_H
/*
 * The MD5 code used here and in md4.c was originally retrieved from:
 *   http://www.openbsd.org/cgi-bin/cvsweb/src/include/md4.h?rev=1.12
 *
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 * Todd C. Miller modified the MD5 code to do MD4 based on RFC 1186.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */
#  define MD4_BLOCK_LENGTH 64
#  define MD4_DIGEST_STRING_LENGTH (MD4_DIGEST_LENGTH * 2 + 1)

typedef struct FR_MD4Context {
	uint32_t state[4];			//!< State.
	uint32_t count[2];			//!< Number of bits, mod 2^64.
	uint8_t buffer[MD4_BLOCK_LENGTH];	//!< Input buffer.
} FR_MD4_CTX;

void	fr_md4_init(FR_MD4_CTX *ctx);
void	fr_md4_update(FR_MD4_CTX *ctx, uint8_t const *in, size_t inlen)
	CC_BOUNDED(__string__, 2, 3);
void	fr_md4_final(uint8_t out[MD4_DIGEST_LENGTH], FR_MD4_CTX *ctx)
	CC_BOUNDED(__minbytes__, 1, MD4_DIGEST_LENGTH);
void	fr_md4_transform(uint32_t buf[4], uint8_t const inc[MD4_BLOCK_LENGTH])
	CC_BOUNDED(__size__, 1, 4, 4)
	CC_BOUNDED(__minbytes__, 2, MD4_BLOCK_LENGTH);
#  define fr_md4_destroy(_x)
#else  /* HAVE_OPENSSL_MD4_H */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
USES_APPLE_DEPRECATED_API
#  define FR_MD4_CTX		MD4_CTX
#  define fr_md4_init		MD4_Init
#  define fr_md4_update		MD4_Update
#  define fr_md4_final		MD4_Final
#  define fr_md4_transform	MD4_Transform
#  define fr_md4_destroy(_x)
#else
#include <openssl/evp.h>

/*
 *	Wrappers for OpenSSL3, so we don't have to butcher the rest of
 *	the code too much.
 */
typedef struct FR_MD4_CTX {
	EVP_MD_CTX	*ctx;
	EVP_MD const   	*md;
	unsigned int	len;
} FR_MD4_CTX;

static inline void fr_md4_init(FR_MD4_CTX *ctx)
{
	ctx->ctx = EVP_MD_CTX_new();
//	ctx->md = EVP_MD_fetch(NULL, "MD4", "provider=legacy");
	ctx->md = EVP_md4();
	ctx->len = MD4_DIGEST_LENGTH;

	EVP_MD_CTX_set_flags(ctx->ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	EVP_DigestInit_ex(ctx->ctx, ctx->md, NULL);
}

static inline void fr_md4_update(FR_MD4_CTX *ctx, uint8_t const *in, size_t inlen)
{
        EVP_DigestUpdate(ctx->ctx, in, inlen);
}

static inline void fr_md4_final(uint8_t out[MD4_DIGEST_LENGTH], FR_MD4_CTX *ctx)
{
	EVP_DigestFinal_ex(ctx->ctx, out, &(ctx->len));
}

static inline void fr_md4_destroy(FR_MD4_CTX *ctx)
{
	EVP_MD_CTX_destroy(ctx->ctx);
//	EVP_MD_free(ctx->md);
}

#endif	/* OPENSSL3 */
#endif	/* HAVE_OPENSSL_MD4_H */

/* md4.c */
void fr_md4_calc(uint8_t out[MD4_DIGEST_LENGTH], uint8_t const *in, size_t inlen);

#ifdef __cplusplus
}
#endif
#endif /* _FR_MD4_H */
