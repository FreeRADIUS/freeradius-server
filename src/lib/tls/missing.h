#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <openssl/opensslv.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
#  define EVP_MD_CTX_new EVP_MD_CTX_create
#  define EVP_MD_CTX_free EVP_MD_CTX_destroy
#  define EVP_MD_CTX_reset EVP_MD_CTX_cleanup

/*
 *	OpenSSL compatibility, to avoid ifdef's through the rest of the code.
 */
static inline size_t SSL_get_client_random(const SSL *s, unsigned char *out, size_t outlen)
{
	if (!outlen) return sizeof(s->s3->client_random);

	if (outlen > sizeof(s->s3->client_random)) outlen = sizeof(s->s3->client_random);

	memcpy(out, s->s3->client_random, outlen);
	return outlen;
}

static inline size_t SSL_get_server_random(const SSL *s, unsigned char *out, size_t outlen)
{
	if (!outlen) return sizeof(s->s3->server_random);

	if (outlen > sizeof(s->s3->server_random)) outlen = sizeof(s->s3->server_random);

	memcpy(out, s->s3->server_random, outlen);
	return outlen;
}

static inline size_t SSL_SESSION_get_master_key(const SSL_SESSION *s, unsigned char *out, size_t outlen)
{
	if (!outlen) return s->master_key_length;

	if (outlen > (size_t)s->master_key_length) outlen = (size_t)s->master_key_length;

	memcpy(out, s->master_key, outlen);
	return outlen;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10001000L
#  define ssl_session ssl->session
#else
#  define ssl_session session
#endif
