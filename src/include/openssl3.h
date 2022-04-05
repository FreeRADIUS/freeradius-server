/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef FR_OPENSSL3_H
#define FR_OPENSSL3_H
/**
 * $Id$
 *
 * @file openssl3.h
 * @brief Wrappers to shut up OpenSSL3
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

RCSIDH(openssl3_h, "$Id$")

/*
 *	The HMAC APIs are deprecated in OpenSSL3.  We don't want to
 *	fill the code with ifdef's, so we define some horrific
 *	wrappers here.
 *
 *	This file should be included AFTER all OpenSSL header files.
 */
#ifdef HAVE_OPENSSL_SSL_H
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

typedef struct {
	EVP_MAC		*mac;
	EVP_MAC_CTX	*ctx;
} HMAC3_CTX;
#define HMAC_CTX HMAC3_CTX

#define HMAC_CTX_new HMAC3_CTX_new
static inline HMAC3_CTX *HMAC3_CTX_new(void)
{
	HMAC3_CTX *h = calloc(1, sizeof(*h));

	return h;
}

#define HMAC_Init_ex(_ctx, _key, _keylen, _md, _engine) HMAC3_Init_ex(_ctx, _key, _keylen, _md, _engine)
static inline int HMAC3_Init_ex(HMAC3_CTX *ctx, const unsigned char *key, unsigned int keylen, const EVP_MD *md, UNUSED void *engine)
{
	OSSL_PARAM params[2], *p = params;
	char const *name;
	char *unconst;

	ctx->mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
	if (!ctx->mac) return 0;

	ctx->ctx = EVP_MAC_CTX_new(ctx->mac);
	if (!ctx->ctx) return 0;

	name = EVP_MD_get0_name(md);
	memcpy(&unconst, &name, sizeof(name)); /* const issues */

	p[0] = OSSL_PARAM_construct_utf8_string(OSSL_ALG_PARAM_DIGEST, unconst, 0);
	p[1] = OSSL_PARAM_construct_end();

	return EVP_MAC_init(ctx->ctx, key, keylen, params);
}

#define HMAC_Update HMAC3_Update
static inline int HMAC3_Update(HMAC3_CTX *ctx, const unsigned char *data, unsigned int datalen)
{
	return EVP_MAC_update(ctx->ctx, data, datalen);
}

#define HMAC_Final HMAC3_Final
static inline int HMAC3_Final(HMAC3_CTX *ctx, unsigned char *out, unsigned int *len)
{
	size_t mylen = *len;

	if (!EVP_MAC_final(ctx->ctx, out, &mylen, mylen)) return 0;

	*len = mylen;
	return 1;
}

#define HMAC_CTX_free HMAC3_CTX_free
static inline void HMAC3_CTX_free(HMAC3_CTX *ctx)
{
	if (!ctx) return;

	EVP_MAC_free(ctx->mac);
	EVP_MAC_CTX_free(ctx->ctx);
	free(ctx);
}

#define HMAC_CTX_set_flags(_ctx, _flags)

#endif	/* OPENSSL_VERSION_NUMBER */
#endif
#endif /* FR_OPENSSL3_H */
