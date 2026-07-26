/*
 * eap_psk.h
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
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */

#ifndef _EAP_PSK_H
#define _EAP_PSK_H

RCSIDH(eap_psk_h, "$Id$")

#include "eap.h"

/*
 *	EAP-PSK (RFC 4764) is built entirely on AES-128, so every
 *	cryptographic value is 16 bytes.
 */
#define EAP_PSK_RAND_LEN	16	/* RAND_S and RAND_P */
#define EAP_PSK_MAC_LEN		16	/* MAC_P and MAC_S (AES-CMAC tags) */
#define EAP_PSK_PSK_LEN		16	/* the pre-shared key */
#define EAP_PSK_AK_LEN		16	/* authentication key */
#define EAP_PSK_KDK_LEN		16	/* key-derivation key */
#define EAP_PSK_TEK_LEN		16	/* transient EAP key */
#define EAP_PSK_MSK_LEN		64
#define EAP_PSK_EMSK_LEN	64
#define EAP_PSK_NONCE_LEN	4	/* the PCHANNEL nonce/counter, on the wire */
#define EAP_PSK_TAG_LEN		16	/* EAX authentication tag */

/*
 *	Flags field.  The 2-bit T subfield (the message number) is in the two
 *	high-order bits.
 */
#define EAP_PSK_T_MASK		0xc0
#define EAP_PSK_FLAGS_FIRST	0x00	/* T=0, first message  (server -> peer) */
#define EAP_PSK_FLAGS_SECOND	0x40	/* T=1, second message (peer -> server) */
#define EAP_PSK_FLAGS_THIRD	0x80	/* T=2, third message  (server -> peer) */
#define EAP_PSK_FLAGS_FOURTH	0xc0	/* T=3, fourth message (peer -> server) */

/*
 *	Protected result indication (R), the two high-order bits of the
 *	(encrypted) PCHANNEL payload byte.  E (the extension bit) is the next
 *	bit; EAP-PSK standard authentication always sets E=0.
 */
#define EAP_PSK_R_CONT		1
#define EAP_PSK_R_DONE_SUCCESS	2
#define EAP_PSK_R_DONE_FAILURE	3

#define EAP_PSK_R(_b)		(((_b) >> 6) & 0x03)
#define EAP_PSK_PAYLOAD(_r)	(uint8_t)(((_r) & 0x03) << 6)	/* R, E=0, Reserved=0 */

/*
 *	The PCHANNEL for standard authentication: a 4-byte nonce, a 16-byte
 *	tag, and a single encrypted payload byte (R || E || Reserved).
 */
#define EAP_PSK_PCHANNEL_LEN	(EAP_PSK_NONCE_LEN + EAP_PSK_TAG_LEN + 1)

/*
 *	The EAX header authenticated by the protected channel is the first 22
 *	bytes of the EAP packet: the 4-byte EAP header, the 1-byte EAP Type,
 *	the 1-byte EAP-PSK Flags, and the 16-byte RAND_S.
 */
#define EAP_PSK_HEADER_LEN	(4 + 1 + 1 + EAP_PSK_RAND_LEN)

typedef enum {
	EAP_PSK_STATE_INIT = 0,		/* first message sent, expecting the second */
	EAP_PSK_STATE_MSG3_SENT		/* third message sent, expecting the fourth */
} eap_psk_state_t;

/*
 *	Kept in handler->opaque across the two round trips.
 */
typedef struct eap_psk_session {
	eap_psk_state_t	state;
	uint8_t		rand_s[EAP_PSK_RAND_LEN];
	uint8_t		tek[EAP_PSK_TEK_LEN];		/* valid once the second message is processed */
	uint8_t		msk[EAP_PSK_MSK_LEN];
	uint8_t		emsk[EAP_PSK_EMSK_LEN];
} eap_psk_session_t;

/*
 *	Key setup and session-key derivation (eap_psk.c).  All return 0 on
 *	success, < 0 on (OpenSSL) failure.
 */
int	eap_psk_derive_ak_kdk(uint8_t const psk[EAP_PSK_PSK_LEN],
			      uint8_t ak[EAP_PSK_AK_LEN], uint8_t kdk[EAP_PSK_KDK_LEN]);

int	eap_psk_derive_keys(uint8_t const kdk[EAP_PSK_KDK_LEN],
			    uint8_t const rand_p[EAP_PSK_RAND_LEN],
			    uint8_t tek[EAP_PSK_TEK_LEN],
			    uint8_t msk[EAP_PSK_MSK_LEN],
			    uint8_t emsk[EAP_PSK_EMSK_LEN]);

/*
 *	MAC_P = CMAC-AES-128(AK, ID_P || ID_S || RAND_S || RAND_P)
 *	MAC_S = CMAC-AES-128(AK, ID_S || RAND_P)
 */
int	eap_psk_mac_p(uint8_t const ak[EAP_PSK_AK_LEN],
		      uint8_t const *id_p, size_t id_p_len,
		      uint8_t const *id_s, size_t id_s_len,
		      uint8_t const rand_s[EAP_PSK_RAND_LEN],
		      uint8_t const rand_p[EAP_PSK_RAND_LEN],
		      uint8_t mac_p[EAP_PSK_MAC_LEN]);

int	eap_psk_mac_s(uint8_t const ak[EAP_PSK_AK_LEN],
		      uint8_t const *id_s, size_t id_s_len,
		      uint8_t const rand_p[EAP_PSK_RAND_LEN],
		      uint8_t mac_s[EAP_PSK_MAC_LEN]);

/*
 *	The protected channel (EAX mode with AES-128, keyed with TEK).  The
 *	nonce is the 4-byte counter (0 for the third message, 1 for the
 *	fourth); it is zero-padded to 16 bytes inside these functions.
 *	_decrypt() verifies the tag before decrypting, and returns < 0 if the
 *	tag is invalid.
 */
int	eap_psk_pchannel_encrypt(uint8_t const tek[EAP_PSK_TEK_LEN], uint32_t nonce,
				 uint8_t const *header, size_t header_len,
				 uint8_t const *plain, size_t plain_len,
				 uint8_t *cipher, uint8_t tag[EAP_PSK_TAG_LEN]);

int	eap_psk_pchannel_decrypt(uint8_t const tek[EAP_PSK_TEK_LEN], uint32_t nonce,
				 uint8_t const *header, size_t header_len,
				 uint8_t const *cipher, size_t cipher_len,
				 uint8_t const tag[EAP_PSK_TAG_LEN],
				 uint8_t *plain);

#endif /*_EAP_PSK_H*/
