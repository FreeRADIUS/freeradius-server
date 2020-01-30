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

/** SHA1 HMAC not dependent on OpenSSL
 *
 * @note New code that needs fast or incremental HMACs should use the OpenSSL EVP_* HMAC
 *	interface instead, as that can take advantage of acceleration instructions provided
 *	by various CPUs (and provides an incremental hashing interface).
 *
 * Adapted from hmacmd5.c (HMAC-MD5).  Test cases from RFC2202.
 *
 * @file src/lib/util/hmac_sha1.c
 *
 * @author Michael Richardson (mcr@sandelman.ottawa.on.ca)
 *
 * @copyright 2003 Michael Richardson (mcr@sandelman.ottawa.on.ca)
 * @copyright 2000,2003,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/util/thread_local.h>

#ifdef HMAC_SHA1_DATA_PROBLEMS
unsigned int sha1_data_problems = 0;
#endif

#ifdef HAVE_OPENSSL_EVP_H
#  include <openssl/hmac.h>
#  include <freeradius-devel/tls/missing.h>

fr_thread_local_setup(HMAC_CTX *, sha1_hmac_ctx); /* macro */

static void _hmac_sha1_ctx_free_on_exit(void *arg)
{
	HMAC_CTX_free(arg);
}

/** Calculate HMAC using OpenSSL's SHA1 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.

 */
void fr_hmac_sha1(uint8_t digest[SHA1_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		  uint8_t const *key, size_t key_len)
{
	HMAC_CTX *ctx;

	if (unlikely(!sha1_hmac_ctx)) {
		ctx = HMAC_CTX_new();
		if (unlikely(!ctx)) return;
		fr_thread_local_set_destructor(sha1_hmac_ctx, _hmac_sha1_ctx_free_on_exit, ctx);
	} else {
		ctx = sha1_hmac_ctx;
	}

	HMAC_Init_ex(ctx, key, key_len, EVP_sha1(), NULL);
	HMAC_Update(ctx, in, inlen);
	HMAC_Final(ctx, digest, NULL);
	HMAC_CTX_reset(ctx);
}
#else
/** Calculate HMAC using internal SHA1 implementation
 *
 * @param digest Caller digest to be filled in.
 * @param in Pointer to data stream.
 * @param inlen length of data stream.
 * @param key Pointer to authentication key.
 * @param key_len Length of authentication key.
 */
void fr_hmac_sha1(uint8_t digest[static SHA1_DIGEST_LENGTH], uint8_t const *in, size_t inlen,
		  uint8_t const *key, size_t key_len)
{
	fr_sha1_ctx ctx;
	uint8_t k_ipad[65];    /* inner padding - key XORd with ipad */
	uint8_t k_opad[65];    /* outer padding - key XORd with opad */
	uint8_t tk[20];
	int i;
	/* if key is longer than 64 bytes reset it to key=SHA1(key) */
	if (key_len > 64) {

		fr_sha1_ctx      tctx;

		fr_sha1_init(&tctx);
		fr_sha1_update(&tctx, key, key_len);
		fr_sha1_final(tk, &tctx);

		key = tk;
		key_len = 20;
	}

#ifdef HMAC_SHA1_DATA_PROBLEMS
	if(sha1_data_problems)
	{
		int j,k;

		printf("\nhmac-sha1 key(%d): ", key_len);
		j=0; k=0;
		for (i = 0; i < key_len; i++) {
			if(j==4) {
				printf("_");
				j=0;
			}
			j++;

			printf("%02x", key[i]);
		}
		printf("\nDATA: (%d)    ",inlen);

		j=0; k=0;
		for (i = 0; i < inlen; i++) {
		  if(k==20) {
		    printf("\n	    ");
		    k=0;
		    j=0;
		  }
		  if(j==4) {
		    printf("_");
		    j=0;
		  }
		  k++;
		  j++;

		  printf("%02x", in[i]);
		}
		printf("\n");
	}
#endif


	/*
	 * the HMAC_SHA1 transform looks like:
	 *
	 * SHA1(K XOR opad, SHA1(K XOR ipad, in))
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
	 * perform inner SHA1
	 */
	fr_sha1_init(&ctx);				/* init ctx for 1st pass */
	fr_sha1_update(&ctx, k_ipad, 64);		/* start with inner pad */
	fr_sha1_update(&ctx, in, inlen);	/* then in of datagram */
	fr_sha1_final(digest, &ctx);		/* finish up 1st pass */
	/*
	 * perform outer SHA1
	 */
	fr_sha1_init(&ctx);				/* init ctx for 2nd pass */
	fr_sha1_update(&ctx, k_opad, 64);		/* start with outer pad */
	fr_sha1_update(&ctx, digest, 20);		/* then results of 1st hash */
	fr_sha1_final(digest, &ctx);		/* finish up 2nd pass */

#ifdef HMAC_SHA1_DATA_PROBLEMS
	if (sha1_data_problems) {
		int j;

		printf("\nhmac-sha1 mac(20): ");
		j=0;
		for (i = 0; i < 20; i++) {
			if(j==4) {
				printf("_");
				j=0;
			}
			j++;

			printf("%02x", digest[i]);
		}
		printf("\n");
	}
#endif
}
#endif /* HAVE_OPENSSL_EVP_H */

/*
Test Vectors (Trailing '\0' of a character string not included in test):

  key =	 "Jefe"
  data =	"what do ya want for nothing?"
  data_len =    28 bytes
  digest =	effcdf6ae5eb2fa2d27416d5f184df9c259a7c79

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
 *  cc -DTESTING -I ../include/ hmac.c sha1.c -o hmac
 *
 *  ./hmac Jefe "what do ya want for nothing?"
 */
int main(int argc, char **argv)
{
  uint8_t digest[20];
  char *key;
  int key_len;
  char *text;
  int text_len;
  int i;

  key = argv[1];
  key_len = strlen(key);

  text = argv[2];
  text_len = strlen(text);

  fr_hmac_sha1(digest, text, text_len, key, key_len);

  for (i = 0; i < 20; i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");

  exit(0);
  return 0;
}

#endif
