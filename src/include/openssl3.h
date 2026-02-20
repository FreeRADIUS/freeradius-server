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
 *	For FIPS environments, we need to define an OSSL_LIB_CTX that will
 *	hold both default and legacy providers, which will allow us to access MD5
 *	and MD4 under these systems.
 * 
 *	This file should be included AFTER all OpenSSL header files.
 */
#ifdef HAVE_OPENSSL_SSL_H
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <freeradius-devel/threads.h>

typedef struct {
	OSSL_LIB_CTX *libctx;
	OSSL_PROVIDER *default_provider;
	OSSL_PROVIDER *legacy_provider;
	EVP_MD *md5;
	EVP_MD *md4;
} OSSL_FIPS_LIBCTX;

fr_thread_local_setup(OSSL_FIPS_LIBCTX *, fips_ossl_libctx)	/* macro */

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

static inline void _fips_ossl_libctx_free(void *arg) {
	OSSL_FIPS_LIBCTX *ctx = arg;
	if (ctx->legacy_provider) {
		OSSL_PROVIDER_unload(ctx->legacy_provider);
		ctx->legacy_provider = NULL;
	}
	if (ctx->default_provider) {
		OSSL_PROVIDER_unload(ctx->default_provider);
		ctx->default_provider = NULL;
	}
	if (ctx->libctx) {
		OSSL_LIB_CTX_free(ctx->libctx);
		ctx->libctx = NULL;
	}
	if (ctx->md5) {
		EVP_MD_free(ctx->md5);
		ctx->md5 = NULL;
	}
	if (ctx->md4) {
		EVP_MD_free(ctx->md4);
		ctx->md4 = NULL;
	}
	free(arg);
	fips_ossl_libctx = NULL;
}

static inline OSSL_FIPS_LIBCTX *_fips_ossl_libctx_create() {
	OSSL_FIPS_LIBCTX *ret = calloc(1, sizeof(*ret));
	ret->libctx = OSSL_LIB_CTX_new();
	ret->default_provider = OSSL_PROVIDER_load(ret->libctx, "default");
	if (!ret->default_provider) {
			fprintf(stderr, "Failed loading OpenSSL default provider.");
			return NULL;
	}
	ret->legacy_provider = OSSL_PROVIDER_load(ret->libctx, "legacy");
	if (!ret->legacy_provider) {
			fprintf(stderr, "Failed loading OpenSSL legacy provider.");
			return NULL;
	}
	ret->md5 = EVP_MD_fetch(ret->libctx, "MD5", NULL);
	if (!ret->md5) {
			fprintf(stderr, "Failed loading OpenSSL MD5 function.");
			return NULL;
	}
	ret->md4 = EVP_MD_fetch(ret->libctx, "MD4", NULL);
	if (!ret->md4) {
			fprintf(stderr, "Failed loading OpenSSL MD4 function.");
			return NULL;
	}
	return ret;
}

#define HMAC_Init_ex(_ctx, _key, _keylen, _md, _engine) HMAC3_Init_ex(_ctx, _key, _keylen, _md, _engine)
static inline int HMAC3_Init_ex(HMAC3_CTX *ctx, const unsigned char *key, unsigned int keylen, const EVP_MD *md, UNUSED void *engine)
{
	OSSL_PARAM params[2], *p = params;
	char const *name;
	char *unconst;

	OSSL_LIB_CTX *libctx = NULL;
	if (EVP_default_properties_is_fips_enabled(NULL)) {
		OSSL_FIPS_LIBCTX *fips_libctx = fr_thread_local_init(fips_ossl_libctx, _fips_ossl_libctx_free);
		if (!fips_libctx) {
			fips_libctx = _fips_ossl_libctx_create();
			fr_thread_local_set(fips_ossl_libctx, fips_libctx);
		}
		libctx = fips_libctx->libctx;
	}
	ctx->mac = EVP_MAC_fetch(libctx, "HMAC", NULL);
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
