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
#ifndef _EAP_TEAP_CRYPTO_H
#define _EAP_TEAP_CRYPTO_H

RCSIDH(eap_teap_crypto_h, "$Id$")


int eap_teap_encrypt(uint8_t const *plaintext, size_t plaintext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *key, uint8_t *iv, unsigned char *ciphertext,
		     uint8_t *tag);

int eap_teap_decrypt(uint8_t const *ciphertext, size_t ciphertext_len,
		     uint8_t const *aad, size_t aad_len,
		     uint8_t const *tag, uint8_t const *key, uint8_t const *iv, uint8_t *plaintext);

#endif /* _EAP_TEAP_CRYPTO_H */
