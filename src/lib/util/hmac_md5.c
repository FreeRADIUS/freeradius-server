/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** MD5 HMAC not dependent on OpenSSL
 *
 * @file src/lib/util/hmac_md5.c
 *
 * @note New code that needs fast or incremental HMACs should use the OpenSSL EVP_* HMAC
 *	interface instead, as that can take advantage of acceleration instructions provided
 *	by various CPUs (and provides an incremental hashing interface).
 *
 * For the sake of illustration we provide the following sample code for the implementation
 * of HMAC-MD5 as well as some corresponding test vectors (the code is based on MD5 code as
 * described in [MD5]).
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/atexit.h>
#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/strerror.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <freeradius-devel/tls/openssl_user_macros.h>
#  include <openssl/hmac.h>

static _Thread_local EVP_MD_CTX *md5_hmac_ctx;

static int _hmac_md5_ctx_free_on_exit(void *arg)
{
	EVP_MD_CTX_free(arg);
	return 0;
}

/** Calculate HMAC using OpenSSL's MD5 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.
 * @return
 *	- 0 on success.
 *      - -1 on error.
 */
int fr_hmac_md5(uint8_t digest[MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		uint8_t const *key, size_t key_len)
{
	EVP_MD_CTX *ctx;
 	EVP_PKEY *pkey;

	if (unlikely(!md5_hmac_ctx)) {
		ctx = EVP_MD_CTX_new();
		if (unlikely(!ctx)) {
			fr_strerror_const("Failed allocating EVP_MD_CTX for HMAC-MD5");
			return -1;
		}
		EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_ONESHOT);
		fr_atexit_thread_local(md5_hmac_ctx, _hmac_md5_ctx_free_on_exit, ctx);
	} else {
		ctx = md5_hmac_ctx;
	}

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
	if (unlikely(pkey == NULL)) {
		fr_strerror_const("Failed allocating pkey for HMAC-MD5");
		return -1;
	}

	if (unlikely(EVP_DigestSignInit(ctx, NULL, EVP_md5(), NULL, pkey) != 1)) {
		fr_strerror_const("Failed initialising EVP_MD_CTX for HMAC-MD5");
	error:
		EVP_PKEY_free(pkey);
		return -1;
	}
	if (unlikely(EVP_DigestSignUpdate(ctx, in, inlen) != 1)) {
		fr_strerror_const("Failed ingesting data for HMAC-MD5");
		goto error;
	}
	/*
	 *	OpenSSL <= 1.1.1 requires a non-null pointer for len
	 */
	if (unlikely(EVP_DigestSignFinal(ctx, digest, &(size_t){ MD5_DIGEST_LENGTH }) != 1)) {
		fr_strerror_const("Failed finalising HMAC-MD5");
		goto error;
	}

	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(ctx);

	return 0;
}
#else
/** Calculate HMAC using internal MD5 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.
 * @return
 *	- 0 on success.
 *      - -1 on error.
 */
int fr_hmac_md5(uint8_t digest[MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		uint8_t const *key, size_t key_len)
{
	fr_md5_ctx_t	*ctx;
	uint8_t		k_ipad[65];    /* inner padding - key XORd with ipad */
	uint8_t		k_opad[65];    /* outer padding - key XORd with opad */
	uint8_t		tk[16];
	int i;

	ctx = fr_md5_ctx_alloc_from_list();

	/* if key is longer than 64 bytes reset it to key=MD5(key) */
	if (key_len > 64) {
		fr_md5_update(ctx, key, key_len);
		fr_md5_final(tk, ctx);
		fr_md5_ctx_reset(ctx);

		key = tk;
		key_len = 16;
	}

	/*
	 * the HMAC_MD5 transform looks like:
	 *
	 * MD5(K XOR opad, MD5(K XOR ipad, in))
	 *
	 * where K is an n byte key
	 * ipad is the byte 0x36 repeated 64 times

	 * opad is the byte 0x5c repeated 64 times
	 * and in is the data being protected
	 */

	/* start out by storing key in pads */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for (i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	/*
	 * perform inner MD5
	 */
	fr_md5_update(ctx, k_ipad, 64);		/* start with inner pad */
	fr_md5_update(ctx, in, inlen);		/* then in of datagram */
	fr_md5_final(digest, ctx);		/* finish up 1st pass */


	/*
	 * perform outer MD5
	 */
	fr_md5_ctx_reset(ctx);
	fr_md5_update(ctx, k_opad, 64);		/* start with outer pad */
	fr_md5_update(ctx, digest, 16);		/* then results of 1st hash */
	fr_md5_final(digest, ctx);		/* finish up 2nd pass */

	fr_md5_ctx_free_from_list(&ctx);

	return 0;
}
#endif /* HAVE_OPENSSL_EVP_H */
