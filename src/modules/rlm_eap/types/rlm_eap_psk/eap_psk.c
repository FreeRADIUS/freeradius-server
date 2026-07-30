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
 * @file eap_psk.c
 * @brief The cryptographic primitives of EAP-PSK (RFC 4764).
 *
 * EAP-PSK is built entirely on AES-128.  This file implements, using the
 * OpenSSL EVP and CMAC APIs:
 *
 *   - the key setup (PSK -> AK, KDK),
 *   - the session-key derivation (KDK, RAND_P -> TEK, MSK, EMSK),
 *   - the two authentication MACs (MAC_P and MAC_S), and
 *   - the EAX protected channel (encrypt / decrypt-and-verify).
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#include <freeradius-devel/util/misc.h>

#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>

#include "eap_psk.h"

/*
 *	A single AES-128 ECB block encryption: out = AES-128(key, in).  Both
 *	buffers are exactly 16 bytes.  Returns 0 on success, < 0 on failure.
 */
static int aes128_ecb_block(uint8_t const key[16], uint8_t const in[16], uint8_t out[16])
{
	EVP_CIPHER_CTX	*ctx;
	int		len;
	int		rcode = -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	/*
	 *	Disable padding so that a single 16-byte input block yields
	 *	exactly 16 bytes out, with no trailing PKCS#7 block.
	 */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) goto done;
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (EVP_EncryptUpdate(ctx, out, &len, in, 16) != 1) goto done;
	if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1) goto done;

	rcode = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return rcode;
}

/*
 *	AES-128 in counter mode.  OpenSSL uses the 16-byte IV as the initial
 *	counter block and increments the whole 128-bit value as a big-endian
 *	integer, which is exactly what EAX (and hence EAP-PSK) requires.
 *	CTR is symmetric, so this is used for both encrypt and decrypt.
 */
static int aes128_ctr(uint8_t const key[16], uint8_t const ctr[16],
		      uint8_t const *in, size_t len, uint8_t *out)
{
	int		rcode = -1;
	int		outl;
	EVP_CIPHER_CTX	*ctx;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, ctr) != 1) goto done;

	if (EVP_EncryptUpdate(ctx, out, &outl, in, (int) len) != 1) goto done;
	if (EVP_EncryptFinal_ex(ctx, out + outl, &outl) != 1) goto done;

	rcode = 0;

done:
	EVP_CIPHER_CTX_free(ctx);
	return rcode;
}

/*
 *	The "modified counter mode" of RFC 4764 section 3.1 / 3.2.  It is a
 *	length-increasing function that expands one 16-byte input block into
 *	'count' output blocks:
 *
 *		hash    = AES-128(key, input)
 *		out_i   = AES-128(key, hash XOR c_i)	for i = 1 .. count
 *
 *	where c_i is the integer i encoded as a 16-byte block.  Since i is
 *	always small (<= 9) only the low-order byte is ever non-zero.
 *
 *	'out' must be large enough for count * 16 bytes.
 */
static int eap_psk_counter_mode(uint8_t const key[16], uint8_t const input[16],
				size_t count, uint8_t *out)
{
	size_t	i;
	uint8_t		hash[16];
	uint8_t		block[16];

	if (aes128_ecb_block(key, input, hash) < 0) return -1;

	for (i = 1; i <= count; i++) {
		memcpy(block, hash, sizeof(block));
		block[15] ^= (uint8_t) i;

		if (aes128_ecb_block(key, block, out + ((i - 1) * 16)) < 0) return -1;
	}

	return 0;
}

/*
 *	Key setup: derive AK (counter 1) and KDK (counter 2) from the PSK,
 *	using a constant all-zero input block.  See RFC 4764 Figure 3.
 */
int eap_psk_derive_ak_kdk(uint8_t const psk[EAP_PSK_PSK_LEN],
			  uint8_t ak[EAP_PSK_AK_LEN], uint8_t kdk[EAP_PSK_KDK_LEN])
{
	uint8_t	input[16];
	uint8_t	out[2 * 16];

	memset(input, 0, sizeof(input));

	if (eap_psk_counter_mode(psk, input, 2, out) < 0) return -1;

	memcpy(ak, out, EAP_PSK_AK_LEN);
	memcpy(kdk, out + 16, EAP_PSK_KDK_LEN);

	return 0;
}

/*
 *	Session-key derivation: expand RAND_P under KDK into nine output
 *	blocks.  Block 1 is the TEK, blocks 2..5 are the MSK, and blocks
 *	6..9 are the EMSK.  See RFC 4764 Figure 7.
 */
int eap_psk_derive_keys(uint8_t const kdk[EAP_PSK_KDK_LEN],
			uint8_t const rand_p[EAP_PSK_RAND_LEN],
			uint8_t tek[EAP_PSK_TEK_LEN],
			uint8_t msk[EAP_PSK_MSK_LEN],
			uint8_t emsk[EAP_PSK_EMSK_LEN])
{
	uint8_t	out[9 * 16];

	if (eap_psk_counter_mode(kdk, rand_p, 9, out) < 0) return -1;

	memcpy(tek,  out,           EAP_PSK_TEK_LEN);	/* block 1 */
	memcpy(msk,  out + 1 * 16,  EAP_PSK_MSK_LEN);	/* blocks 2..5 */
	memcpy(emsk, out + 5 * 16,  EAP_PSK_EMSK_LEN);	/* blocks 6..9 */

	return 0;
}

/*
 *	AES-128 CMAC over one or more concatenated buffers.  A NULL buffer is
 *	skipped, so callers can pass a fixed set of segments.
 *
 *	The low-level CMAC API is used because it is portable across
 *	OpenSSL 1.1 and 3.x; OpenSSL 3.0 deprecates it in favour of EVP_MAC,
 *	so the deprecation warning is suppressed the same way the rest of the
 *	tree handles deprecated OpenSSL calls.
 */
DIAG_OFF(deprecated-declarations)
static int eap_psk_cmac(uint8_t const key[16],
			uint8_t const *seg1, size_t len1,
			uint8_t const *seg2, size_t len2,
			uint8_t const *seg3, size_t len3,
			uint8_t const *seg4, size_t len4,
			uint8_t mac[16])
{
	int		rcode = -1;
	size_t		maclen;
	CMAC_CTX	*ctx;

	ctx = CMAC_CTX_new();
	if (!ctx) return -1;

	if (CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) != 1) goto done;

	if (seg1 && (len1 > 0) && (CMAC_Update(ctx, seg1, len1) != 1)) goto done;
	if (seg2 && (len2 > 0) && (CMAC_Update(ctx, seg2, len2) != 1)) goto done;
	if (seg3 && (len3 > 0) && (CMAC_Update(ctx, seg3, len3) != 1)) goto done;
	if (seg4 && (len4 > 0) && (CMAC_Update(ctx, seg4, len4) != 1)) goto done;

	if (CMAC_Final(ctx, mac, &maclen) != 1) goto done;
	if (maclen != 16) goto done;

	rcode = 0;

done:
	CMAC_CTX_free(ctx);
	return rcode;
}
DIAG_ON(deprecated-declarations)

/*
 *	MAC_P = CMAC-AES-128(AK, ID_P || ID_S || RAND_S || RAND_P)
 */
int eap_psk_mac_p(uint8_t const ak[EAP_PSK_AK_LEN],
		  uint8_t const *id_p, size_t id_p_len,
		  uint8_t const *id_s, size_t id_s_len,
		  uint8_t const rand_s[EAP_PSK_RAND_LEN],
		  uint8_t const rand_p[EAP_PSK_RAND_LEN],
		  uint8_t mac_p[EAP_PSK_MAC_LEN])
{
	return eap_psk_cmac(ak,
			    id_p, id_p_len,
			    id_s, id_s_len,
			    rand_s, EAP_PSK_RAND_LEN,
			    rand_p, EAP_PSK_RAND_LEN,
			    mac_p);
}

/*
 *	MAC_S = CMAC-AES-128(AK, ID_S || RAND_P)
 */
int eap_psk_mac_s(uint8_t const ak[EAP_PSK_AK_LEN],
		  uint8_t const *id_s, size_t id_s_len,
		  uint8_t const rand_p[EAP_PSK_RAND_LEN],
		  uint8_t mac_s[EAP_PSK_MAC_LEN])
{
	return eap_psk_cmac(ak,
			    id_s, id_s_len,
			    rand_p, EAP_PSK_RAND_LEN,
			    NULL, 0,
			    NULL, 0,
			    mac_s);
}

/*
 *	The tweaked OMAC used by EAX:
 *
 *		OMAC^t(M) = CMAC(K, [t]_16 || M)
 *
 *	where [t]_16 is the integer t encoded as a 16-byte block.  t is only
 *	ever 0, 1 or 2 here, so only the low-order byte is non-zero.
 */
static int eap_psk_omac(uint8_t const key[16], uint8_t t,
			uint8_t const *data, size_t data_len,
			uint8_t out[16])
{
	uint8_t	tweak[16];

	memset(tweak, 0, sizeof(tweak));
	tweak[15] = t;

	return eap_psk_cmac(key,
			    tweak, sizeof(tweak),
			    data, data_len,
			    NULL, 0,
			    NULL, 0,
			    out);
}

/*
 *	Build the 16-byte EAX nonce block from the 4-byte EAP-PSK Nonce N.
 *	N is padded with 96 zero high-order bits, i.e. 12 zero bytes followed
 *	by the 4-byte big-endian counter.
 */
static void eap_psk_nonce_block(uint32_t nonce, uint8_t block[16])
{
	memset(block, 0, 16);
	block[12] = (uint8_t) (nonce >> 24);
	block[13] = (uint8_t) (nonce >> 16);
	block[14] = (uint8_t) (nonce >> 8);
	block[15] = (uint8_t) (nonce);
}

/*
 *	EAX encrypt.  Computes:
 *
 *		N' = OMAC^0(nonce_block)
 *		H' = OMAC^1(header)
 *		C  = CTR_{N'}(plain)
 *		C' = OMAC^2(C)
 *		tag = N' XOR H' XOR C'
 *
 *	'cipher' receives plain_len bytes; 'tag' receives 16 bytes.  Either
 *	the plaintext or its length may be zero (EAP-PSK only ever protects a
 *	single byte, but the code does not rely on that).
 */
int eap_psk_pchannel_encrypt(uint8_t const tek[EAP_PSK_TEK_LEN], uint32_t nonce,
			     uint8_t const *header, size_t header_len,
			     uint8_t const *plain, size_t plain_len,
			     uint8_t *cipher, uint8_t tag[EAP_PSK_TAG_LEN])
{
	size_t		i;
	uint8_t		nonce_block[16];
	uint8_t		n_omac[16], h_omac[16], c_omac[16];

	eap_psk_nonce_block(nonce, nonce_block);

	if (eap_psk_omac(tek, 0, nonce_block, sizeof(nonce_block), n_omac) < 0) return -1;
	if (eap_psk_omac(tek, 1, header, header_len, h_omac) < 0) return -1;

	if ((plain_len > 0) &&
	    (aes128_ctr(tek, n_omac, plain, plain_len, cipher) < 0)) return -1;

	if (eap_psk_omac(tek, 2, cipher, plain_len, c_omac) < 0) return -1;

	for (i = 0; i < EAP_PSK_TAG_LEN; i++) {
		tag[i] = n_omac[i] ^ h_omac[i] ^ c_omac[i];
	}

	return 0;
}

/*
 *	EAX decrypt-and-verify.  Recomputes the tag over the received cipher
 *	text and header, and compares it (in constant time) against the
 *	received tag.  Only if the tags match is the cipher text decrypted
 *	into 'plain'.
 *
 *	Returns 0 if the tag is valid, < 0 on a bad tag or an OpenSSL error.
 */
int eap_psk_pchannel_decrypt(uint8_t const tek[EAP_PSK_TEK_LEN], uint32_t nonce,
			     uint8_t const *header, size_t header_len,
			     uint8_t const *cipher, size_t cipher_len,
			     uint8_t const tag[EAP_PSK_TAG_LEN],
			     uint8_t *plain)
{
	size_t		i;
	uint8_t		nonce_block[16];
	uint8_t		n_omac[16], h_omac[16], c_omac[16];
	uint8_t		want[16];

	eap_psk_nonce_block(nonce, nonce_block);

	if (eap_psk_omac(tek, 0, nonce_block, sizeof(nonce_block), n_omac) < 0) return -1;
	if (eap_psk_omac(tek, 1, header, header_len, h_omac) < 0) return -1;
	if (eap_psk_omac(tek, 2, cipher, cipher_len, c_omac) < 0) return -1;

	for (i = 0; i < EAP_PSK_TAG_LEN; i++) {
		want[i] = n_omac[i] ^ h_omac[i] ^ c_omac[i];
	}

	/*
	 *	Verify the tag BEFORE decrypting, as required by RFC
	 *	4764 section 3.3.  Use a constant-time comparison in
	 *	order to avoid a timing oracle.
	 */
	if (fr_digest_cmp(want, tag, EAP_PSK_TAG_LEN) != 0) return -1;

	if ((cipher_len > 0) &&
	    (aes128_ctr(tek, n_omac, cipher, cipher_len, plain) < 0)) return -1;

	return 0;
}
