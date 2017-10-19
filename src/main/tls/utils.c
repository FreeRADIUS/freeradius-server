#include <openssl/ssl.h>
#include <freeradius-devel/radiusd.h>

/** Returns the OpenSSL keyblock size
 *
 * Copyright (c) 2002-2016, Jouni Malinen <j@w1.fi> and contributors
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
int tls_utils_keyblock_size_get(REQUEST *request, SSL *ssl)
{
	const EVP_CIPHER *c;
	const EVP_MD *h;
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
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
int tls_utils_asn1time_to_epoch(time_t *out, ASN1_TIME const *asn1)
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

	/* ASN1_TIME is UTC, but mktime will treat it as being in the local timezone */
done:
	*out = mktime(&t) + timezone;

	return 0;
}

