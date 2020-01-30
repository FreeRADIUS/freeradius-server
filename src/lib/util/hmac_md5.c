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

#include <freeradius-devel/util/md5.h>
#include <freeradius-devel/util/thread_local.h>

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/hmac.h>
#  include <freeradius-devel/tls/missing.h>

fr_thread_local_setup(HMAC_CTX *, md5_hmac_ctx); /* macro */

static void _hmac_md5_ctx_free_on_exit(void *arg)
{
	HMAC_CTX_free(arg);
}

/** Calculate HMAC using OpenSSL's MD5 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.
 *
 */
void fr_hmac_md5(uint8_t digest[MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		 uint8_t const *key, size_t key_len)
{
	HMAC_CTX *ctx;

	if (unlikely(!md5_hmac_ctx)) {
		ctx = HMAC_CTX_new();
		if (unlikely(!ctx)) return;
		fr_thread_local_set_destructor(md5_hmac_ctx, _hmac_md5_ctx_free_on_exit, ctx);
	} else {
		ctx = md5_hmac_ctx;
	}

#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
	/* Since MD5 is not allowed by FIPS, explicitly allow it. */
	HMAC_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif /* EVP_MD_CTX_FLAG_NON_FIPS_ALLOW */

	HMAC_Init_ex(ctx, key, key_len, EVP_md5(), NULL);
	HMAC_Update(ctx, in, inlen);
	HMAC_Final(ctx, digest, NULL);
	HMAC_CTX_reset(ctx);
}
#else
/** Calculate HMAC using internal MD5 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.
 *
 */
void fr_hmac_md5(uint8_t digest[MD5_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		 uint8_t const *key, size_t key_len)
{
	fr_md5_ctx_t	*ctx;
	uint8_t		k_ipad[65];    /* inner padding - key XORd with ipad */
	uint8_t		k_opad[65];    /* outer padding - key XORd with opad */
	uint8_t		tk[16];
	int i;

	ctx = fr_md5_ctx_alloc(true);

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

	fr_md5_ctx_free(&ctx);
}
#endif /* HAVE_OPENSSL_EVP_H */

/*
Test Vectors (Trailing '\0' of a character string not included in test):

  key =	 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
  key_len =     16 bytes
  data =	"Hi There"
  data_len =    8  bytes
  digest =      0x9294727a3638bb1c13f48ef8158bfc9d

  key =	 "Jefe"
  data =	"what do ya want for nothing?"
  data_len =    28 bytes
  digest =      0x750c783e6ab0b503eaa86e310a5db738

  key =	 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

  key_len       16 bytes
  data =	0xDDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD...
		..DDDDDDDDDDDDDDDDDDDD
  data_len =    50 bytes
  digest =      0x56be34521d144c88dbb8c733f0e8b3f6
*/

#ifdef TESTING
/*
 *  cc -DTESTING -I ../include/ hmac.c md5.c -o hmac
 *
 *  ./hmac Jefe "what do ya want for nothing?"
 */
int main(int argc, char **argv)
{
	uint8_t digest[16];
	char *key;
	int key_len;
	char *text;
	int text_len;
	int i;

	key = argv[1];
	key_len = strlen(key);

	text = argv[2];
	text_len = strlen(text);

	fr_hmac_md5(digest, text, text_len, key, key_len);

	for (i = 0; i < 16; i++) {
	printf("%02x", digest[i]);
	}
	printf("\n");

	exit(0);
	return 0;
}

#endif
