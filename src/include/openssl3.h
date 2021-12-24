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
#ifndef FR_OPENSSL3_H
#define FR_OPENSSL3_H
/**
 * $Id$
 *
 * @file openssl3.h
 * @brief Wrappers to shut up OpenSSL3
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */

RCSIDH(openssl3_h, "$Id$")

/*
 *	The HMAC APIs are deprecated in OpenSSL3.  We don't want to
 *	fill the code with ifdef's, so we define some horrific
 *	wrappers here.
 *
 *	This file should be included AFTER all OpenSSL header files.
 */
#if HAVE_OPENSSL_SSL_H
#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define HMAC_CTX \
	EVP_MD_CTX

#define HMAC_CTX_new \
	EVP_MD_CTX_create

#define HMAC_Init_ex(_ctx, _str, _len, _md, _NULL) \
	do { \
		EVP_DigestInit_ex(_ctx, _md, _NULL); \
		EVP_DigestUpdate(_ctx, _str, _len); \
	} while (0)

#define HMAC_Update(_ctx, _str, _len) \
	EVP_DigestUpdate(_ctx, _str, _len)

#define HMAC_Final(_ctx, _digest, _len) \
	EVP_DigestFinal_ex(_ctx, _digest, _len)

#define HMAC_CTX_free(_ctx) \
	EVP_MD_CTX_destroy(_ctx);

#endif	/* OPENSSL_VERSION_NUMBER */
#endif
#endif /* FR_OPENSSL3_H */
