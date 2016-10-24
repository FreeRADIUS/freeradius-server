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
int tls_keyblock_size_get(REQUEST *request, SSL *ssl)
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
