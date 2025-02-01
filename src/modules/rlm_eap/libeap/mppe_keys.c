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
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <freeradius-devel/openssl3.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10101000L
#include <openssl/kdf.h>

void TLS_PRF(SSL *ssl,
	     unsigned char *sec, size_t seclen,
	     struct iovec *iov, size_t iovcnt,
	     unsigned char *key, size_t keylen)
{
	const EVP_MD *md = SSL_CIPHER_get_handshake_digest(SSL_get_current_cipher(ssl));
	EVP_MD *unconst_md;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);

	EVP_PKEY_derive_init(pctx);

	memcpy(&unconst_md, &md, sizeof(md)); /* const issues */
	EVP_PKEY_CTX_set_tls1_prf_md(pctx, unconst_md);

	EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen);

	for (unsigned int i = 0; i < iovcnt; i++) {
		EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, iov[i].iov_base, iov[i].iov_len);
	}

	EVP_PKEY_derive(pctx, key, &keylen);

	EVP_PKEY_CTX_free(pctx);
}
#endif

/*
 *	TLS P_hash from RFC 2246/5246 section 5
 */
static void P_hash(EVP_MD const *evp_md,
		   unsigned char const *secret, unsigned int secret_len,
		   unsigned char const *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	HMAC_CTX *ctx_a, *ctx_out;
	unsigned char a[EVP_MAX_MD_SIZE];
	unsigned int size = EVP_MAX_MD_SIZE;
	unsigned int digest_len;

	ctx_a = HMAC_CTX_new();
	ctx_out = HMAC_CTX_new();
	HMAC_Init_ex(ctx_a, secret, secret_len, evp_md, NULL);
	HMAC_Init_ex(ctx_out, secret, secret_len, evp_md, NULL);

	/* Calculate A(1) */
	HMAC_Update(ctx_a, seed, seed_len);
	HMAC_Final(ctx_a, a, &size);

	while (1) {
		/* Calculate next part of output */
		HMAC_Update(ctx_out, a, size);
		HMAC_Update(ctx_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			digest_len = EVP_MAX_MD_SIZE;
			HMAC_Final(ctx_out, a, &digest_len);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		digest_len = EVP_MAX_MD_SIZE;
		HMAC_Final(ctx_out, out, &digest_len);
		HMAC_Init_ex(ctx_out, NULL, 0, NULL, NULL);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HMAC_Init_ex(ctx_a, NULL, 0, NULL, NULL);
		HMAC_Update(ctx_a, a, size);
		digest_len = EVP_MAX_MD_SIZE;
		HMAC_Final(ctx_a, a, &digest_len);
	}

	HMAC_CTX_free(ctx_a);
	HMAC_CTX_free(ctx_out);
	memset(a, 0, sizeof(a));
}

/*
 *	TLS PRF from RFC 2246 section 5
 */
static void PRF(unsigned char const *secret, unsigned int secret_len,
		unsigned char const *seed,   unsigned int seed_len,
		unsigned char *out, unsigned int out_len)
{
	uint8_t buf[out_len + (out_len % SHA_DIGEST_LENGTH)];
	unsigned int i;

	unsigned int len = (secret_len + 1) / 2;
	uint8_t const *s1 = secret;
	uint8_t const *s2 = secret + (secret_len - len);

	EVP_MD const *md5 = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	EVP_MD *md5_to_free = NULL;

	/*
	 *	If we are using OpenSSL >= 3.0 and FIPS mode is
	 *	enabled, we need to load the default provider in a
	 *	standalone context in order to access MD5.
	 */
	OSSL_LIB_CTX	*libctx = NULL;
	OSSL_PROVIDER	*default_provider = NULL;

	if (EVP_default_properties_is_fips_enabled(NULL)) {
		libctx = OSSL_LIB_CTX_new();
		default_provider = OSSL_PROVIDER_load(libctx, "default");

		if (!default_provider) {
			ERROR("Failed loading OpenSSL default provider.");
			return;
		}

		md5_to_free = EVP_MD_fetch(libctx, "MD5", NULL);
		if (!md5_to_free) {
			ERROR("Failed loading OpenSSL MD5 function.");
			return;
		}

		md5 = md5_to_free;
	} else {
		md5 = EVP_md5();
	}
#else
	md5 = EVP_md5();
#endif

	P_hash(md5, s1, len, seed, seed_len, out, out_len);
	P_hash(EVP_sha1(), s2, len, seed, seed_len, buf, out_len);

	for (i = 0; i < out_len; i++) {
		out[i] ^= buf[i];
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (libctx) {
		OSSL_PROVIDER_unload(default_provider);
		OSSL_LIB_CTX_free(libctx);
		EVP_MD_free(md5_to_free);
	}
#endif
}

/*
 *	TLS 1.2 PRF from RFC 5246 section 5
 */
static void PRFv12(unsigned char const *secret, unsigned int secret_len,
		   unsigned char const *seed,   unsigned int seed_len,
		   unsigned char *out, unsigned int out_len)
{
	P_hash(EVP_sha256(), secret, secret_len, seed, seed_len, out, out_len);
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
	if (seed) memcpy(buf + SHA1_DIGEST_LENGTH + prf_size, seed, seed_len);
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

#define EAPTLS_MPPE_KEY_LEN     32

/*
 *	Generate keys according to RFC 5216 (section 2.3)
 */
void eaptls_gen_keys_only(UNUSED REQUEST *request, SSL *s, char const *label, uint8_t const *context, UNUSED size_t context_size, uint8_t *out, size_t outlen)
{
	size_t len = strlen(label);

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, out, outlen, label, len, context, context_size, context != NULL) != 1) {
		ERROR("Failed generating keying material");
		return;
	}
#else
	{
		uint8_t *p;
		uint8_t seed[64 + (2 * SSL3_RANDOM_SIZE) + (context ? 2 + context_size : 0)];
		uint8_t buf[4 * EAPTLS_MPPE_KEY_LEN];

		p = seed;

		memcpy(p, label, len);
		p += len;

		memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		len += SSL3_RANDOM_SIZE;

		memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		len += SSL3_RANDOM_SIZE;

		if (context) {
			/* cloned and reversed FR_PUT_LE16 */
			p[0] = ((uint16_t) (context_size)) >> 8;
			p[1] = ((uint16_t) (context_size)) & 0xff;
			p += 2;
			len += 2;
			memcpy(p, context, context_size);
			p += context_size;
			len += context_size;
		}

		PRF(s->session->master_key, s->session->master_key_length,
		    seed, len, out, buf, outlen);
	}
#endif
}

/*
 *	Generate keys according to RFC 5216 (section 2.3) and add to reply
 */
void eaptls_gen_mppe_keys(REQUEST *request, SSL *s, char const *label, uint8_t const *context, UNUSED size_t context_size)
{
	uint8_t out[4 * EAPTLS_MPPE_KEY_LEN];
	uint8_t *p;

	eaptls_gen_keys_only(request, s, label, context, context_size, out, sizeof(out));

	/*
	 *	Add these before the MPPE keys for TEAP.
	 */
	eap_add_reply(request, "EAP-MSK", out, 64);
	eap_add_reply(request, "EAP-EMSK", out + 64, 64);

	p = out;
	eap_add_reply(request, "MS-MPPE-Recv-Key", p, EAPTLS_MPPE_KEY_LEN);
	p += EAPTLS_MPPE_KEY_LEN;
	eap_add_reply(request, "MS-MPPE-Send-Key", p, EAPTLS_MPPE_KEY_LEN);
}

#define FR_TLS_PRF_CHALLENGE		"ttls challenge"

/*
 *	Generate the TTLS challenge
 *
 *	It's in the TLS module simply because it's only a few lines
 *	of code, and it needs access to the TLS PRF functions.
 */
void eapttls_gen_challenge(SSL *s, uint8_t *buffer, size_t size)
{
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, buffer, size, FR_TLS_PRF_CHALLENGE,
				       sizeof(FR_TLS_PRF_CHALLENGE)-1, NULL, 0, 0) != 1) {
		ERROR("Failed generating keying material");
	}
#else
	uint8_t out[32], buf[32];
	uint8_t seed[sizeof(FR_TLS_PRF_CHALLENGE)-1 + 2*SSL3_RANDOM_SIZE];
	uint8_t *p = seed;

	memcpy(p, FR_TLS_PRF_CHALLENGE, sizeof(FR_TLS_PRF_CHALLENGE)-1);
	p += sizeof(FR_TLS_PRF_CHALLENGE)-1;
	memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	memcpy(p, s->s3->server_random, SSL3_RANDOM_SIZE);

	PRF(s->session->master_key, s->session->master_key_length,
	    seed, sizeof(seed), out, buf, sizeof(out));
	memcpy(buffer, out, size);
#endif
}

#define FR_TLS_EXPORTER_METHOD_ID	"EXPORTER_EAP_TLS_Method-Id"

/*
 *	Actually generates EAP-Session-Id, which is an internal server
 *	attribute.  Not all systems want to send EAP-Key-Name.
 */
void eaptls_gen_eap_key(eap_handler_t *handler)
{
	RADIUS_PACKET *packet = handler->request->reply;
	tls_session_t *tls_session = handler->opaque;
	SSL *s = tls_session->ssl;
	VALUE_PAIR *vp;
	uint8_t *buff, *p;
	uint8_t type = handler->type & 0xff;

	vp = fr_pair_afrom_num(packet, PW_EAP_SESSION_ID, 0);
	if (!vp) return;

	vp->vp_length = 1 + 2 * SSL3_RANDOM_SIZE;
	buff = p = talloc_array(vp, uint8_t, vp->vp_length);

	*p++ = type;

	switch (SSL_version(tls_session->ssl)) {
	case TLS1_VERSION:
	case TLS1_1_VERSION:
	case TLS1_2_VERSION:
		SSL_get_client_random(s, p, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		SSL_get_server_random(s, p, SSL3_RANDOM_SIZE);
		break;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#ifdef TLS1_3_VERSION
	case TLS1_3_VERSION:
#endif
	default:
	{
		uint8_t const context[] = { type };

		if (SSL_export_keying_material(s, p, 2 * SSL3_RANDOM_SIZE,
					       FR_TLS_EXPORTER_METHOD_ID, sizeof(FR_TLS_EXPORTER_METHOD_ID)-1,
					       context, sizeof(context), 1) != 1) {
			ERROR("Failed generating keying material");
			return;
		}
	}
#endif
	}

	vp->vp_octets = buff;
	fr_pair_add(&packet->vps, vp);
}

/*
 *	Same as before, but for EAP-FAST the order of {server,client}_random is flipped
 */
void eap_fast_tls_gen_challenge(SSL *s, int version, uint8_t *buffer, size_t size, char const *prf_label)
{
	uint8_t *p;
	size_t len, master_key_len;
	uint8_t seed[128 + 2*SSL3_RANDOM_SIZE];
	uint8_t master_key[SSL_MAX_MASTER_KEY_LENGTH];

	len = strlen(prf_label);
	if (len > 128) len = 128;

	p = seed;
	memcpy(p, prf_label, len);
	p += len;
	SSL_get_server_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	SSL_get_client_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	master_key_len = SSL_SESSION_get_master_key(SSL_get_session(s), master_key, sizeof(master_key));

	if (version == TLS1_2_VERSION)
		PRFv12(master_key, master_key_len, seed, p - seed, buffer, size);
	else
		PRF(master_key, master_key_len, seed, p - seed, buffer, size);
}
