/*
 * fast-crypto.c  Cryptographic functions for EAP-FAST.
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
 * Copyright 2016 Alan DeKok <aland@freeradius.org>
 * Copyright 2016 The FreeRADIUS server project
 */

RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <stdio.h>
#include <freeradius-devel/libradius.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>

#include "eap_fast_crypto.h"

#  define DEBUG			if (fr_debug_lvl && fr_log_fp) fr_printf_log

static void debug_errors(void)
{
	unsigned long errCode;

	while((errCode = ERR_get_error())) {
		char *err = ERR_error_string(errCode, NULL);
		DEBUG("EAP-FAST error in OpenSSL - %s", err);
	}
}

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode
int eap_fast_encrypt(uint8_t const *plaintext, size_t plaintext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *key, uint8_t *iv, unsigned char *ciphertext,
		     uint8_t *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		debug_errors();
		return -1;
	};

	/* Initialise the encryption operation. */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		debug_errors();
		return -1;
	};

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		debug_errors();
		return -1;
	};

	/* Initialise key and IV */
	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
		debug_errors();
		return -1;
	};

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		debug_errors();
		return -1;
	};

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		debug_errors();
		return -1;
	};
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		debug_errors();
		return -1;
	};
	ciphertext_len += len;

	/* Get the tag */
	if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
		debug_errors();
		return -1;
	};

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int eap_fast_decrypt(uint8_t const *ciphertext, size_t ciphertext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *tag, uint8_t const *key, uint8_t const *iv, uint8_t *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		debug_errors();
		return -1;
	};

	/* Initialise the decryption operation. */
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
		debug_errors();
		return -1;
	};

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		debug_errors();
		return -1;
	};

	/* Initialise key and IV */
	if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
		debug_errors();
		return -1;
	};

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		debug_errors();
		return -1;
	};

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		debug_errors();
		return -1;
	};
	plaintext_len = len;

	{
		unsigned char *tmp;

		memcpy(&tmp, &tag, sizeof(tmp));

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tmp)) {
			debug_errors();
			return -1;
		};
	}

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if (ret == 0) return -1;

	/* Success */
	plaintext_len += len;
	return plaintext_len;
}
