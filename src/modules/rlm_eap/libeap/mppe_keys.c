/*
 * mppe_keys.c
 *
 * Version:     $Id$
 *
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
 *
 * Copyright 2002  Axis Communications AB
 * Copyright 2006  The FreeRADIUS server project
 * Authors: Henrik Eriksson <henriken@axis.com> & Lars Viklund <larsv@axis.com>
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include "eap_tls.h"
#include <openssl/hmac.h>
#include <freeradius-devel/sha1.h>


/*
 * TLS PRF from RFC 2246
 */
static void P_hash(EVP_MD const *evp_md,
		   unsigned char const *secret, unsigned int secret_len,
		   unsigned char const *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	HMAC_CTX ctx_a, ctx_out;
	unsigned char a[HMAC_MAX_MD_CBLOCK];
	unsigned int size;

	HMAC_CTX_init(&ctx_a);
	HMAC_CTX_init(&ctx_out);
	HMAC_Init_ex(&ctx_a, secret, secret_len, evp_md, NULL);
	HMAC_Init_ex(&ctx_out, secret, secret_len, evp_md, NULL);

	size = HMAC_size(&ctx_out);

	/* Calculate A(1) */
	HMAC_Update(&ctx_a, seed, seed_len);
	HMAC_Final(&ctx_a, a, NULL);

	while (1) {
		/* Calculate next part of output */
		HMAC_Update(&ctx_out, a, size);
		HMAC_Update(&ctx_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			HMAC_Final(&ctx_out, a, NULL);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		HMAC_Final(&ctx_out, out, NULL);
		HMAC_Init_ex(&ctx_out, NULL, 0, NULL, NULL);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HMAC_Init_ex(&ctx_a, NULL, 0, NULL, NULL);
		HMAC_Update(&ctx_a, a, size);
		HMAC_Final(&ctx_a, a, NULL);
	}

	HMAC_CTX_cleanup(&ctx_a);
	HMAC_CTX_cleanup(&ctx_out);
	memset(a, 0, sizeof(a));
}

/*  EAP-FAST Pseudo-Random Function (T-PRF): RFC 4851, Section 5.5 */
void T_PRF(unsigned char const *secret, unsigned int secret_len,
	   char const *prf_label,
	   unsigned char const *seed,  unsigned int seed_len,
	   unsigned char *out, unsigned int out_len)
{
	size_t prf_size = strlen(prf_label);
	size_t pos;
	uint8_t	*buf;

	if (prf_size > 128) prf_size = 128;
	prf_size++;	/* include trailing zero */

	buf = talloc_size(NULL, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1);

	memcpy(buf + SHA1_DIGEST_LENGTH, prf_label, prf_size);
	memcpy(buf + SHA1_DIGEST_LENGTH + prf_size, seed, seed_len);
	*(uint16_t *)&buf[SHA1_DIGEST_LENGTH + prf_size + seed_len] = htons(out_len);
	buf[SHA1_DIGEST_LENGTH + prf_size + seed_len + 2] = 1;

	// T1 is just the seed
	fr_hmac_sha1(buf, buf + SHA1_DIGEST_LENGTH, prf_size + seed_len + 2 + 1, secret, secret_len);

#define MIN(a,b) (((a)>(b)) ? (b) : (a))
	memcpy(out, buf, MIN(out_len, SHA1_DIGEST_LENGTH));

	pos = SHA1_DIGEST_LENGTH;
	while (pos < out_len) {
		buf[SHA1_DIGEST_LENGTH + prf_size + seed_len + 2]++;

		fr_hmac_sha1(buf, buf, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1, secret, secret_len);
		memcpy(&out[pos], buf, MIN(out_len - pos, SHA1_DIGEST_LENGTH));

		if (out_len - pos <= SHA1_DIGEST_LENGTH)
			break;

		pos += SHA1_DIGEST_LENGTH;
	}

	memset(buf, 0, SHA1_DIGEST_LENGTH + prf_size + seed_len + 2 + 1);
	talloc_free(buf);
}

#ifndef NDEBUG
/*
 *	Only do this testing in development builds.
 */
#define	T_PRF_compare(x)	if (memcmp(x, x##_test, sizeof(x))) {					\
					fprintf(stderr, "T_PRF(%s) FAILED\n", #x);			\
					fprintf(stderr, "SRC\tGEN\n");					\
					for (size_t i = 0; i < sizeof(x); i++)				\
						fprintf(stderr, "%02x\t%02x\n", x[i], x##_test[i]);	\
					abort();							\
				}

static void __attribute__((constructor)) __test_T_PRF()
{

	// RFC4581 Appendix B.1 Key Derivation Test Vectors
	uint8_t pac_key[] = {
		0x0B, 0x97, 0x39, 0x0F, 0x37, 0x51, 0x78, 0x09, 0x81, 0x1E, 0xFD, 0x9C, 0x6E, 0x65, 0x94, 0x2B,
		0x63, 0x2C, 0xE9, 0x53, 0x89, 0x38, 0x08, 0xBA, 0x36, 0x0B, 0x03, 0x7C, 0xD1, 0x85, 0xE4, 0x14,
	};
	uint8_t random[] = {
		// server
		0x3F, 0xFB, 0x11, 0xC4, 0x6C, 0xBF, 0xA5, 0x7A, 0x54, 0x40, 0xDA, 0xE8, 0x22, 0xD3, 0x11, 0xD3,
		0xF7, 0x6D, 0xE4, 0x1D, 0xD9, 0x33, 0xE5, 0x93, 0x70, 0x97, 0xEB, 0xA9, 0xB3, 0x66, 0xF4, 0x2A,
		// client
		0x00, 0x00, 0x00, 0x02, 0x6A, 0x66, 0x43, 0x2A, 0x8D, 0x14, 0x43, 0x2C, 0xEC, 0x58, 0x2D, 0x2F,
		0xC7, 0x9C, 0x33, 0x64, 0xBA, 0x04, 0xAD, 0x3A, 0x52, 0x54, 0xD6, 0xA5, 0x79, 0xAD, 0x1E, 0x00,
	};
	uint8_t master_secret[] = {
		0x4A, 0x1A, 0x51, 0x2C, 0x01, 0x60, 0xBC, 0x02, 0x3C, 0xCF, 0xBC, 0x83, 0x3F, 0x03, 0xBC, 0x64,
		0x88, 0xC1, 0x31, 0x2F, 0x0B, 0xA9, 0xA2, 0x77, 0x16, 0xA8, 0xD8, 0xE8, 0xBD, 0xC9, 0xD2, 0x29,
		0x38, 0x4B, 0x7A, 0x85, 0xBE, 0x16, 0x4D, 0x27, 0x33, 0xD5, 0x24, 0x79, 0x87, 0xB1, 0xC5, 0xA2,
	};

	uint8_t master_secret_test[sizeof(master_secret)];
	T_PRF(pac_key, sizeof(pac_key), "PAC to master secret label hash", random, sizeof(random), master_secret_test, sizeof(master_secret));
	T_PRF_compare(master_secret);

	uint8_t session_key_seed[] = {
		0xD6, 0x4B, 0x7D, 0x72, 0x17, 0x59, 0x28, 0x05, 0xAF, 0xF9, 0xB7, 0xFF, 0x66, 0x6D, 0xA1, 0x96,
		0x8F, 0x0B, 0x5E, 0x06, 0x46, 0x7A, 0x44, 0x84, 0x64, 0xC1, 0xC8, 0x0C, 0x96, 0x44, 0x09, 0x98,
		0xFF, 0x92, 0xA8, 0xB4, 0xC6, 0x42, 0x28, 0x71,
	};
	uint8_t isk[32];
	memset(isk, 0, 32);
	uint8_t imck[] = {
		0x16, 0x15, 0x3C, 0x3F, 0x21, 0x55, 0xEF, 0xD9, 0x7F, 0x34, 0xAE, 0xC8, 0x1A, 0x4E, 0x66, 0x80,
		0x4C, 0xC3, 0x76, 0xF2, 0x8A, 0xA9, 0x6F, 0x96, 0xC2, 0x54, 0x5F, 0x8C, 0xAB, 0x65, 0x02, 0xE1,
		0x18, 0x40, 0x7B, 0x56, 0xBE, 0xEA, 0xA7, 0xC5, 0x76, 0x5D, 0x8F, 0x0B, 0xC5, 0x07, 0xC6, 0xB9,
		0x04, 0xD0, 0x69, 0x56, 0x72, 0x8B, 0x6B, 0xB8, 0x15, 0xEC, 0x57, 0x7B,
	};

	uint8_t imck_test[sizeof(imck)];
	T_PRF(session_key_seed, sizeof(session_key_seed), "Inner Methods Compound Keys", isk, sizeof(isk), imck_test, sizeof(imck_test));
	T_PRF_compare(imck);

	uint8_t simck1[] = {
		0x16, 0x15, 0x3C, 0x3F, 0x21, 0x55, 0xEF, 0xD9, 0x7F, 0x34, 0xAE, 0xC8, 0x1A, 0x4E, 0x66, 0x80,
		0x4C, 0xC3, 0x76, 0xF2, 0x8A, 0xA9, 0x6F, 0x96, 0xC2, 0x54, 0x5F, 0x8C, 0xAB, 0x65, 0x02, 0xE1,
		0x18, 0x40, 0x7B, 0x56, 0xBE, 0xEA, 0xA7, 0xC5,
	};
	uint8_t msk[] = {
		0x4D, 0x83, 0xA9, 0xBE, 0x6F, 0x8A, 0x74, 0xED, 0x6A, 0x02, 0x66, 0x0A, 0x63, 0x4D, 0x2C, 0x33,
		0xC2, 0xDA, 0x60, 0x15, 0xC6, 0x37, 0x04, 0x51, 0x90, 0x38, 0x63, 0xDA, 0x54, 0x3E, 0x14, 0xB9,
		0x27, 0x99, 0x18, 0x1E, 0x07, 0xBF, 0x0F, 0x5A, 0x5E, 0x3C, 0x32, 0x93, 0x80, 0x8C, 0x6C, 0x49,
		0x67, 0xED, 0x24, 0xFE, 0x45, 0x40, 0xA0, 0x59, 0x5E, 0x37, 0xC2, 0xE9, 0xD0, 0x5D, 0x0A, 0xE3,
	};

	uint8_t msk_test[sizeof(msk)];
	T_PRF(simck1, sizeof(simck1), "Session Key Generating Function", NULL, 0, msk_test, sizeof(msk_test));
	T_PRF_compare(msk);

	uint8_t emsk[] = {
		0x3A, 0xD4, 0xAB, 0xDB, 0x76, 0xB2, 0x7F, 0x3B, 0xEA, 0x32, 0x2C, 0x2B, 0x74, 0xF4, 0x28, 0x55,
		0xEF, 0x2D, 0xBA, 0x78, 0xC9, 0x57, 0x2F, 0x0D, 0x06, 0xCD, 0x51, 0x7C, 0x20, 0x93, 0x98, 0xA9,
		0x76, 0xEA, 0x70, 0x21, 0xD7, 0x0E, 0x25, 0x54, 0x97, 0xED, 0xB2, 0x8A, 0xF6, 0xED, 0xFD, 0x0A,
		0x2A, 0xE7, 0xA1, 0x58, 0x90, 0x10, 0x50, 0x44, 0xB3, 0x82, 0x85, 0xDB, 0x06, 0x14, 0xD2, 0xF9,
	};

	uint8_t emsk_test[sizeof(emsk)];
	T_PRF(simck1, sizeof(simck1), "Extended Session Key Generating Function", NULL, 0, emsk_test, sizeof(emsk_test));
	T_PRF_compare(emsk);
}
#endif	/* NDEBUG */

static void PRF(unsigned char const *secret, unsigned int secret_len,
		unsigned char const *seed,   unsigned int seed_len,
		unsigned char *out, unsigned char *buf, unsigned int out_len)
{
	unsigned int i;
	unsigned int len = (secret_len + 1) / 2;
	uint8_t const *s1 = secret;
	uint8_t const *s2 = secret + (secret_len - len);

	P_hash(EVP_md5(),  s1, len, seed, seed_len, out, out_len);
	P_hash(EVP_sha1(), s2, len, seed, seed_len, buf, out_len);

	for (i=0; i < out_len; i++) {
		out[i] ^= buf[i];
	}
}

#define EAPTLS_MPPE_KEY_LEN     32

/** Generate keys according to RFC 2716 and add to the reply
 *
 */
void eap_tls_gen_mppe_keys(REQUEST *request, SSL *s, char const *prf_label)
{
	uint8_t out[4 * EAPTLS_MPPE_KEY_LEN];
	uint8_t *p;
	size_t prf_size;

	prf_size = strlen(prf_label);

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, out, sizeof(out), prf_label, prf_size, NULL, 0, 0) != 1) /* Fallback */
#endif

	{
		uint8_t seed[64 + (2 * SSL3_RANDOM_SIZE)];
		uint8_t buf[4 * EAPTLS_MPPE_KEY_LEN];

		p = seed;

		memcpy(p, prf_label, prf_size);
		p += prf_size;

		memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		prf_size += SSL3_RANDOM_SIZE;

		memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
		prf_size += SSL3_RANDOM_SIZE;

		PRF(s->session->master_key, s->session->master_key_length,
		    seed, prf_size, out, buf, sizeof(out));
	}

	RDEBUG2("Adding session keys");
	p = out;
	eap_add_reply(request, "MS-MPPE-Recv-Key", p, EAPTLS_MPPE_KEY_LEN);
	p += EAPTLS_MPPE_KEY_LEN;
	eap_add_reply(request, "MS-MPPE-Send-Key", p, EAPTLS_MPPE_KEY_LEN);

	eap_add_reply(request, "EAP-MSK", out, 64);
	eap_add_reply(request, "EAP-EMSK", out + 64, 64);
}


/*
 *	Generate the challenge using a PRF label.
 *
 *	It's in the TLS module simply because it's only a few lines
 *	of code, and it needs access to the TLS PRF functions.
 */
void eap_tls_gen_challenge(SSL *s, uint8_t *buffer, size_t size, char const *prf_label)
{
	uint8_t out[32], buf[32];
	uint8_t seed[128 + 2*SSL3_RANDOM_SIZE];
	uint8_t *p = seed;
	size_t len;

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, buffer, size, prf_label,
				       strlen(prf_label), NULL, 0, 0) == 1) return;

#endif

	len = strlen(prf_label);
	if (len > 128) len = 128;

	memcpy(p, prf_label, len);
	p += len;
	memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	PRF(s->session->master_key, s->session->master_key_length,
	    seed, p - seed, out, buf, sizeof(out));
	memcpy(buffer, out, size);
}

/*
 *	Actually generates EAP-Session-Id, which is an internal server
 *	attribute.  Not all systems want to send EAP-Key-Name
 */
void eap_tls_gen_eap_key(RADIUS_PACKET *packet, SSL *s, uint32_t header)
{
	VALUE_PAIR *vp;
	uint8_t *p;

	vp = fr_pair_afrom_num(packet, 0, PW_EAP_SESSION_ID);
	if (!vp) return;

	p = talloc_array(vp, uint8_t, 1 + 2 * SSL3_RANDOM_SIZE);
	p[0] = header & 0xff;

#ifdef HAVE_SSL_GET_CLIENT_RANDOM
	SSL_get_client_random(s, p + 1, SSL3_RANDOM_SIZE);
	SSL_get_server_random(s, p + 1 + SSL3_RANDOM_SIZE, SSL3_RANDOM_SIZE);
#else
	memcpy(p + 1, s->s3->client_random, SSL3_RANDOM_SIZE);
	memcpy(p + 1 + SSL3_RANDOM_SIZE,
	       s->s3->server_random, SSL3_RANDOM_SIZE);
#endif
	fr_pair_value_memsteal(vp, p);
	fr_pair_add(&packet->vps, vp);
}
