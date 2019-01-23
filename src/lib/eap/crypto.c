/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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

/**
 * $Id$
 * @file lib/eap/crypto.c
 * @brief MPPE key calculation API
 *
 * @author Henrik Eriksson <henriken@axis.com>
 * @author Lars Viklund <larsv@axis.com>
 *
 * @copyright 2002  Axis Communications AB
 * @copyright 2006  The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

#include <openssl/hmac.h>

#include <freeradius-devel/util/sha1.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/tls/missing.h>

#include "tls.h"
#include "base.h"
#include "attrs.h"

static void crypto_rfc4346_p_hash(uint8_t *out, size_t out_len,
				  EVP_MD const *evp_md,
				  uint8_t const *secret, size_t secret_len,
				  uint8_t const *seed,  size_t seed_len)
{
	HMAC_CTX *ctx_a, *ctx_out;
	uint8_t a[HMAC_MAX_MD_CBLOCK];
	size_t size;

	ctx_a = HMAC_CTX_new();
	ctx_out = HMAC_CTX_new();
#ifdef EVP_MD_CTX_FLAG_NON_FIPS_ALLOW
	HMAC_CTX_set_flags(ctx_a, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
	HMAC_CTX_set_flags(ctx_out, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);
#endif
	HMAC_Init_ex(ctx_a, secret, secret_len, evp_md, NULL);
	HMAC_Init_ex(ctx_out, secret, secret_len, evp_md, NULL);

	size = HMAC_size(ctx_out);

	/* Calculate A(1) */
	HMAC_Update(ctx_a, seed, seed_len);
	HMAC_Final(ctx_a, a, NULL);

	while (1) {
		/* Calculate next part of output */
		HMAC_Update(ctx_out, a, size);
		HMAC_Update(ctx_out, seed, seed_len);

		/* Check if last part */
		if (out_len < size) {
			HMAC_Final(ctx_out, a, NULL);
			memcpy(out, a, out_len);
			break;
		}

		/* Place digest in output buffer */
		HMAC_Final(ctx_out, out, NULL);
		HMAC_Init_ex(ctx_out, NULL, 0, NULL, NULL);
		out += size;
		out_len -= size;

		/* Calculate next A(i) */
		HMAC_Init_ex(ctx_a, NULL, 0, NULL, NULL);
		HMAC_Update(ctx_a, a, size);
		HMAC_Final(ctx_a, a, NULL);
	}

	HMAC_CTX_free(ctx_a);
	HMAC_CTX_free(ctx_out);
#ifdef __STDC_LIB_EXT1__
	memset_s(a, 0, sizeof(a), sizeof(a));
#else
	memset(a, 0, sizeof(a));
#endif
}


void eap_crypto_rfc4346_prf(uint8_t *out, size_t out_len, uint8_t *scratch,
			    uint8_t const *secret, size_t secret_len,
			    uint8_t const *seed, size_t seed_len)
{
	unsigned int	i;
	unsigned int	len = (secret_len + 1) / 2;
	uint8_t const	*s1 = secret;
	uint8_t const	*s2 = secret + (secret_len - len);

	crypto_rfc4346_p_hash(out, out_len, EVP_md5(), s1, len, seed, seed_len);
	crypto_rfc4346_p_hash(scratch, out_len, EVP_sha1(), s2, len, seed, seed_len);

	for (i = 0; i < out_len; i++) out[i] ^= scratch[i];
}

#define EAP_TLS_MPPE_KEY_LEN     32

/** Generate keys according to RFC 2716 and add to the reply
 *
 */
void eap_crypto_mppe_keys(REQUEST *request, SSL *ssl, char const *prf_label, size_t prf_label_len)
{
	uint8_t		out[4 * EAP_TLS_MPPE_KEY_LEN];
	uint8_t		*p;
	size_t		seed_len = prf_label_len;
	size_t		master_key_len;
	uint8_t		seed[64 + (2 * SSL3_RANDOM_SIZE)];
	uint8_t		scratch[sizeof(out)];
	uint8_t		master_key[SSL_MAX_MASTER_KEY_LENGTH];

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(ssl, out, sizeof(out), prf_label, prf_label_len, NULL, 0, 0) != 1) /* Fallback */
#endif

	{
		p = seed;
		memcpy(p, prf_label, seed_len);
		p += seed_len;

		(void) SSL_get_client_random(ssl, p, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		seed_len += SSL3_RANDOM_SIZE;

		(void) SSL_get_server_random(ssl, p, SSL3_RANDOM_SIZE);
		seed_len += SSL3_RANDOM_SIZE;

		master_key_len = SSL_SESSION_get_master_key(SSL_get_session(ssl), master_key, sizeof(master_key));
		eap_crypto_rfc4346_prf(out, sizeof(out), scratch, master_key, master_key_len, seed, seed_len);
	}

	RDEBUG2("Adding session keys");
	p = out;
	eap_add_reply(request, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(request, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	eap_add_reply(request, attr_eap_msk, out, 64);
	eap_add_reply(request, attr_eap_emsk, out + 64, 64);
}


/*
 *	Generate the challenge using a PRF label.
 *
 *	It's in the TLS module simply because it's only a few lines
 *	of code, and it needs access to the TLS PRF functions.
 */
void eap_crypto_challenge(SSL *s, uint8_t *buffer, uint8_t *scratch, size_t size, char const *prf_label)
{
	uint8_t		*p;
	size_t		len, master_key_len;
	uint8_t		master_key[SSL_MAX_MASTER_KEY_LENGTH];
	uint8_t		seed[128 + (2 * SSL3_RANDOM_SIZE)];

#if OPENSSL_VERSION_NUMBER >= 0x10001000L
	if (SSL_export_keying_material(s, buffer, size, prf_label,
				       strlen(prf_label), NULL, 0, 0) == 1) return;

#endif

	len = strlen(prf_label);
	if (len > 128) len = 128;

	p = seed;
	memcpy(p, prf_label, len);
	p += len;

	(void) SSL_get_client_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;
	(void) SSL_get_server_random(s, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	master_key_len = SSL_SESSION_get_master_key(SSL_get_session(s), master_key, sizeof(master_key));
	eap_crypto_rfc4346_prf(buffer, size, scratch, master_key, master_key_len, seed, p - seed);
}

int eap_crypto_tls_session_id(TALLOC_CTX *ctx, uint8_t **out,
			      SSL *ssl, uint8_t eap_type,
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			      UNUSED
#endif
			      char const *prf_label,
#if OPENSSL_VERSION_NUMBER < 0x10100000L
			      UNUSED
#endif
			      size_t prf_len)
{
	uint8_t		*buff = NULL, *p;

	*out = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	if (!prf_label) goto random_based_session_id;

	switch (SSL_SESSION_get_protocol_version(SSL_get_session(ssl))) {
	case SSL2_VERSION:	/* Should never happen */
	case SSL3_VERSION:	/* Should never happen */
		return - 1;

	case TLS1_VERSION:	/* No Method ID */
	case TLS1_1_VERSION:	/* No Method ID */
	case TLS1_2_VERSION:	/* No Method ID */
	random_based_session_id:
#endif
		MEM(buff = p = talloc_array(ctx, uint8_t, sizeof(eap_type) + (2 * SSL3_RANDOM_SIZE)));
		*p++ = eap_type;

		SSL_get_client_random(ssl, p, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;
		SSL_get_server_random(ssl, p, SSL3_RANDOM_SIZE);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		break;

	/*
	 *	Session-Id = <EAP-Type> || Method-Id
	 *	Method-Id = TLS-Exporter("EXPORTER_EAP_TLS_Method-Id", "", 64)
	 */
#  ifdef TLS1_3_VERSION
	case TLS1_3_VERSION:
#  endif
	default:
	{
		MEM(buff = p = talloc_array(ctx, uint8_t, sizeof(eap_type) + 64));
		*p++ = eap_type;
		SSL_export_keying_material(ssl, p, 64, prf_label, prf_len, NULL, 0, 0);
	}
		break;
	}
#endif
	*out = buff;

	return 0;
}
