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

/**
 * $Id$
 *
 * @file tls/utils.c
 * @brief TLS utility functions
 *
 * @copyright 2018 The FreeRADIUS server project
 */

#include <openssl/ssl.h>
#include <freeradius-devel/server/base.h>

#include "base.h"
#include "missing.h"

/** PKEY types (friendly names)
 *
 */
static fr_table_num_sorted_t const pkey_types[] = {
	{ L("DH"),		EVP_PKEY_DH		},
	{ L("DSA"),	EVP_PKEY_DSA		},
	{ L("EC"),		EVP_PKEY_EC		},
	{ L("RSA"),	EVP_PKEY_RSA		}
};
static size_t pkey_types_len = NUM_ELEMENTS(pkey_types);

/** Returns a friendly identifier for the public key type of a certificate
 *
 * @param[in] cert	The X509 cert to return the type of.
 * @return the type string.
 */
char const *fr_tls_utils_x509_pkey_type(X509 *cert)
{
	EVP_PKEY	*pkey;
	int		pkey_type;
	char const	*type_str;

	if (!cert) return NULL;

	pkey = X509_get_pubkey(cert);
	if (!pkey) return NULL;

	pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
	type_str = fr_table_str_by_value(pkey_types, pkey_type, OBJ_nid2sn(pkey_type));
	EVP_PKEY_free(pkey);

	return type_str;
}

/** Returns the OpenSSL keyblock size
 *
 * @copyright (c) 2002-2016, Jouni Malinen (j@w1.fi) and contributors
 * All Rights Reserved.
 *
 * These programs are licensed under the BSD license (the one with
 * advertisement clause removed).
 *
 * this function shamelessly stolen from from
 * hostap:src/crypto/tls_openssl.c:openssl_get_keyblock_size()
 *
 * @param[in] request The current request.
 * @param[in] ssl The current SSL session.
 * @return
 *	- -1 problem with the session.
 *	- >=0 length of the block.
 */
int fr_tls_utils_keyblock_size_get(REQUEST *request, SSL *ssl)
{
	const EVP_CIPHER *c;
	const EVP_MD *h;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	int md_size;

	if (ssl->enc_read_ctx == NULL || ssl->enc_read_ctx->cipher == NULL || ssl->read_hash == NULL)
		return -1;

	c = ssl->enc_read_ctx->cipher;
	h = EVP_MD_CTX_md(ssl->read_hash);
	if (h)
		md_size = EVP_MD_size(h);
	else if (ssl->s3)
		md_size = ssl->s3->tmp.new_mac_secret_size;
	else
		return -1;

	RDEBUG2("OpenSSL: keyblock size: key_len=%d MD_size=%d "
		   "IV_len=%d", EVP_CIPHER_key_length(c), md_size,
		   EVP_CIPHER_iv_length(c));
	return 2 * (EVP_CIPHER_key_length(c) +
		    md_size +
		    EVP_CIPHER_iv_length(c));
#else
	const SSL_CIPHER *ssl_cipher;
	int cipher, digest;

	ssl_cipher = SSL_get_current_cipher(ssl);
	if (!ssl_cipher)
		return -1;
	cipher = SSL_CIPHER_get_cipher_nid(ssl_cipher);
	digest = SSL_CIPHER_get_digest_nid(ssl_cipher);
	RDEBUG2("OpenSSL: cipher nid %d digest nid %d", cipher, digest);
	if (cipher < 0 || digest < 0)
		return -1;
	c = EVP_get_cipherbynid(cipher);
	h = EVP_get_digestbynid(digest);
	if (!c || !h)
		return -1;

	RDEBUG2("OpenSSL: keyblock size: key_len=%d MD_size=%d IV_len=%d",
		   EVP_CIPHER_key_length(c), EVP_MD_size(h),
		   EVP_CIPHER_iv_length(c));
	return 2 * (EVP_CIPHER_key_length(c) + EVP_MD_size(h) +
		    EVP_CIPHER_iv_length(c));
#endif
}

/** Convert OpenSSL's ASN1_TIME to an epoch time
 *
 * @param[out] out	Where to write the time_t.
 * @param[in] asn1	The ASN1_TIME to convert.
 * @return
 *	- 0 success.
 *	- -1 on failure.
 */
int fr_tls_utils_asn1time_to_epoch(time_t *out, ASN1_TIME const *asn1)
{
	struct		tm t;
	char const	*p = (char const *)asn1->data, *end = p + strlen(p);

	memset(&t, 0, sizeof(t));

	if (asn1->type == V_ASN1_UTCTIME) {/* two digit year */
		if ((end - p) < 2) {
			fr_strerror_printf("ASN1 date string too short, expected 2 additional bytes, got %zu bytes",
					   end - p);
			return -1;
		}

		t.tm_year = (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		if (t.tm_year < 70) t.tm_year += 100;
	} else if (asn1->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		if ((end - p) < 4) {
			fr_strerror_printf("ASN1 string too short, expected 4 additional bytes, got %zu bytes",
					   end - p);
			return -1;
		}

		t.tm_year = (*(p++) - '0') * 1000;
		t.tm_year += (*(p++) - '0') * 100;
		t.tm_year += (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		t.tm_year -= 1900;
	}

	if ((end - p) < 4) {
		fr_strerror_printf("ASN1 string too short, expected 10 additional bytes, got %zu bytes",
				   end - p);
		return -1;
	}

	t.tm_mon = (*(p++) - '0') * 10;
	t.tm_mon += (*(p++) - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (*(p++) - '0') * 10;
	t.tm_mday += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_hour = (*(p++) - '0') * 10;
	t.tm_hour += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_min = (*(p++) - '0') * 10;
	t.tm_min += (*(p++) - '0');

	if ((end - p) < 2) goto done;
	t.tm_sec = (*(p++) - '0') * 10;
	t.tm_sec += (*(p++) - '0');

	/* ASN1_TIME is UTC, so get the UTC time */
done:
	*out = timegm(&t);

	return 0;
}

