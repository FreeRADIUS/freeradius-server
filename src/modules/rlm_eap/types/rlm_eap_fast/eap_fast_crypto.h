#pragma once
/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file eap_fast_crypto.h
 * @brief Crypto function declarations.
 *
 * @author Alexander Clouter (alex@digriz.org.uk)
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSIDH(eap_fast_crypto_h, "$Id$")

void T_PRF(unsigned char const *secret, unsigned int secret_len, char const *prf_label, unsigned char const *seed, unsigned int seed_len, unsigned char *out, unsigned int out_len) CC_HINT(nonnull(1,3,6));

int eap_fast_encrypt(uint8_t const *plaintext, size_t plaintext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *key, uint8_t *iv, unsigned char *ciphertext,
		     uint8_t *tag);

int eap_fast_decrypt(uint8_t const *ciphertext, size_t ciphertext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *tag, uint8_t const *key, uint8_t const *iv, uint8_t *plaintext);

void eap_fast_tls_gen_challenge(SSL *ssl, uint8_t *buffer, uint8_t *scratch, size_t size, char const *prf_label) CC_HINT(nonnull);
