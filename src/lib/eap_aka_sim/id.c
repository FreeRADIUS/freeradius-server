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

/**
 * @file src/lib/eap_aka_sim/id.c
 * @brief EAP-SIM/EAP-AKA identity detection, creation, and decyption.
 *
 * @copyright 2017 The FreeRADIUS server project
 */
#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/util/base64.h>
#include <freeradius-devel/util/rand.h>
#include <openssl/evp.h>
#include "base.h"
#include "id.h"

#define us(x) (uint8_t) x

fr_table_num_sorted_t const fr_aka_sim_id_request_table[] = {
	{ L("Any-Id-Req"),		AKA_SIM_ANY_ID_REQ		},
	{ L("FullAuth-Id-Req"),	AKA_SIM_FULLAUTH_ID_REQ		},
	{ L("no"),			AKA_SIM_NO_ID_REQ		},	/* Used for config parsing */
	{ L("none"),		AKA_SIM_NO_ID_REQ		},
	{ L("Permanent-Id-Req"),	AKA_SIM_PERMANENT_ID_REQ	},
};
size_t fr_aka_sim_id_request_table_len = NUM_ELEMENTS(fr_aka_sim_id_request_table);

fr_table_num_sorted_t const fr_aka_sim_id_method_table[] = {
	{ L("AKA'"),		AKA_SIM_METHOD_HINT_AKA_PRIME	},
	{ L("AKA"),		AKA_SIM_METHOD_HINT_AKA		},
	{ L("SIM"),		AKA_SIM_METHOD_HINT_SIM		},
};
size_t fr_aka_sim_id_method_table_len = NUM_ELEMENTS(fr_aka_sim_id_method_table);

/** Find where the identity ends
 *
 * @param[in] nai	we're attempting to split.
 * @param[in] nai_len	The length of the NAI string.
 * @return
 *	- How long the identity portion of the NAI is.
 */
size_t fr_aka_sim_id_user_len(char const *nai, size_t nai_len)
{
	char const *p;

	p = (char *)memchr((uint8_t const *)nai, '@', nai_len);
	if (!p) return nai_len;

	return p - nai;
}

/** Find where in the NAI string the domain starts
 *
 * @param[in] nai	we're attempting to split.
 * @param[in] nai_len	The length of the NAI string.
 * @return
 *	- A pointer to where the domain portion of the domain starts.
 *	- NULL if there was no @ in the identity.
 */
char const *fr_aka_sim_domain(char const *nai, size_t nai_len)
{
	char const *p;

	p = (char *)memchr((uint8_t const *)nai, '@', nai_len);
	if (!p) return NULL;

	return p + 1;
}

/** Extract the MCC and MCN from the 3GPP domain
 *
 * 3GPP Root NAI domain format wlan.mnc<MNC>.mcc<MCC>.3gppnetwork.org.
 *
 * @param[out] mnc		Mobile network code.
 * @param[out] mcc		Mobile country code.
 * @param[in] domain		to parse.
 * @param[in] domain_len	Length of the domain component.
 * @return
 *	- number of bytes parsed.
 *	- <= 0 on error - The negative offset of where parsing failed.
 */
ssize_t fr_aka_sim_3gpp_root_nai_domain_mcc_mnc(uint16_t *mnc, uint16_t *mcc,
						char const *domain, size_t domain_len)
{
	char const *p = domain, *end = p + domain_len;
	char *q;
	unsigned long num;

	if (((p + 8) < end) || (CRYPTO_memcmp(p, "wlan.mnc", 8) != 0)) return -1;
	p += 8;

	if (((p + 3) < end)) {
		fr_strerror_printf("Missing MNC component");
		return (domain - p);
	}
	num = strtoul(p, &q, 10);
	if (*q != '.') {
		fr_strerror_printf("Invalid MCN component");
		return (domain - q);
	}
	*mnc = (uint16_t)num;
	p = q + 1;

	if (((p + 3) < end) || (CRYPTO_memcmp(p, "mcc", 3) != 0)) {
		fr_strerror_printf("Missing MCC component");
		return (domain - p);
	}
	num = strtoul(p, &q, 10);
	if (*q != '.') {
		fr_strerror_printf("Invalid MCC component");
		return (domain - q);
	}
	*mcc = (uint16_t)num;

	p = q + 1;
	if (((p + 15) < end) || (CRYPTO_memcmp(p, "3gppnetwork.org", 15) != 0)) {
		fr_strerror_printf("Missing 3gppnetwork.org suffix");
		return (domain - p);
	}
	p += 15;

	if (p != end) {
		fr_strerror_printf("Trailing garbage");
		return (domain - p);
	}

	return p - domain;
}

/** Determine what type of ID was provided in the initial identity response
 *
 * @param[out] hint	Whether this is a hint to do EAP-SIM or EAP-AKA[']:
 *	- AKA_SIM_METHOD_HINT_AKA_PRIME		this ID was generated during an EAP-AKA' exchange
 *						or the supplicant hints it wants to perform EAP-AKA'.
 *	- AKA_SIM_METHOD_HINT_AKA		this ID was generated during an EAP-AKA exchange
 *						or the supplicant hints it wants to perform EAP-AKA.
 *	- AKA_SIM_METHOD_HINT_SIM		this IS was generated during an EAP-SIM exchange
 *						or the supplicant hints it wants to perform EAP-SIM.
 *	- AKA_SIM_METHOD_HINT_UNKNOWN		we don't know what type of authentication generated
 *						this ID or which one to start.
 * @param[out] type	What type of identity this is:
 *	- AKA_SIM_ID_TYPE_PERMANENT		if the ID is an IMSI.
 *	- AKA_SIM_ID_TYPE_PSEUDONYM		if the ID is a freeform pseudonym.
 *	- AKA_SIM_ID_TYPE_FASTAUTH		if the ID is a fastauth identity.
 *	- AKA_SIM_ID_TYPE_UNKNOWN		if we can't determine what sort of ID this is.
 * @param[in] id	the NAI string provided.
 * @param[in] id_len	the length of the NAI string.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_id_type(fr_aka_sim_id_type_t *type, fr_aka_sim_method_hint_t *hint, char const *id, size_t id_len)
{
	size_t i;

	if (id_len < 1) {
		*hint = AKA_SIM_METHOD_HINT_UNKNOWN;
		*type = AKA_SIM_ID_TYPE_UNKNOWN;
		fr_strerror_printf("ID length too short");
		return -1;
	}

	/*
	 *	Just get the length of the ID between the start
	 *	and the first '@'.  Returns the length of the
	 *	entire string if no '@' found, so works with
	 *	full NAI strings and Stripped-User-Name.
	 */
	id_len = fr_aka_sim_id_user_len(id, id_len);

	/*
	 *	Permanent ID format check
	 */
	switch (id[0]) {
	case ID_TAG_SIM_PERMANENT:
	case ID_TAG_AKA_PERMANENT:
	case ID_TAG_AKA_PRIME_PERMANENT:
		if (id_len > 16) {
			fr_strerror_printf("IMSI too long, expected <= 16 bytes got %zu bytes", id_len);
			goto bad_format;
		}

		for (i = 1; i < id_len; i++) {
			if (!isdigit(id[i])) {
				fr_strerror_printf("Invalid digit '%pV' in IMSI \"%pV\"",
						   fr_box_strvalue_len(&id[i], 1),
						   fr_box_strvalue_len(id, id_len));
				goto bad_format;
			}
		}

		switch (id[0]) {
		case ID_TAG_SIM_PERMANENT:
			*hint = AKA_SIM_METHOD_HINT_SIM;
			*type = AKA_SIM_ID_TYPE_PERMANENT;	/* All digits */
			return 0;

		case ID_TAG_AKA_PERMANENT:
			*hint = AKA_SIM_METHOD_HINT_AKA;
			*type = AKA_SIM_ID_TYPE_PERMANENT;	/* All digits */
			return 0;

		case ID_TAG_AKA_PRIME_PERMANENT:
			*hint = AKA_SIM_METHOD_HINT_AKA_PRIME;
			*type = AKA_SIM_ID_TYPE_PERMANENT;	/* All Digits */
			return 0;

		default:
			break;
		}
		break;

	default:
		break;
	}

bad_format:
	/*
	 *	Pseudonym
	 */
	switch (id[0]) {
	case ID_TAG_SIM_PSEUDONYM:
		*hint = AKA_SIM_METHOD_HINT_SIM;
		*type = AKA_SIM_ID_TYPE_PSEUDONYM;
		return 0;

	case ID_TAG_AKA_PSEUDONYM:
		*hint = AKA_SIM_METHOD_HINT_AKA;
		*type = AKA_SIM_ID_TYPE_PSEUDONYM;
		return 0;

	case ID_TAG_AKA_PRIME_PSEUDONYM:
		*hint = AKA_SIM_METHOD_HINT_AKA_PRIME;
		*type = AKA_SIM_ID_TYPE_PSEUDONYM;
		return 0;

	/*
	 *	Fast reauth identity
	 */
	case ID_TAG_SIM_FASTAUTH:
		*hint = AKA_SIM_METHOD_HINT_SIM;
		*type = AKA_SIM_ID_TYPE_FASTAUTH;
		return 0;

	case ID_TAG_AKA_FASTAUTH:
		*hint = AKA_SIM_METHOD_HINT_AKA;
		*type = AKA_SIM_ID_TYPE_FASTAUTH;
		return 0;

	case ID_TAG_AKA_PRIME_FASTAUTH:
		*hint = AKA_SIM_METHOD_HINT_AKA_PRIME;
		*type = AKA_SIM_ID_TYPE_FASTAUTH;
		return 0;

	case ID_TAG_SIM_PERMANENT:
		*hint = AKA_SIM_METHOD_HINT_UNKNOWN;
		*type = AKA_SIM_ID_TYPE_UNKNOWN;
		fr_strerror_printf_push("Got SIM-Permanent-ID tag, but identity is not a permanent ID");
		return -1;

	case ID_TAG_AKA_PERMANENT:
		*hint = AKA_SIM_METHOD_HINT_UNKNOWN;
		*type = AKA_SIM_ID_TYPE_UNKNOWN;
		fr_strerror_printf_push("Got AKA-Permanent-ID tag, but identity is not a permanent ID");
		return -1;

	default:
		*hint = AKA_SIM_METHOD_HINT_UNKNOWN;
		*type = AKA_SIM_ID_TYPE_UNKNOWN;
		fr_strerror_printf_push("Unrecognised tag '%pV'", fr_box_strvalue_len(id, 1));
		return -1;
	}
}

static char hint_byte_matrix[AKA_SIM_METHOD_HINT_MAX][AKA_SIM_ID_TYPE_MAX] = {
	[AKA_SIM_METHOD_HINT_SIM] = {
		[AKA_SIM_ID_TYPE_PERMANENT]	= ID_TAG_SIM_PERMANENT,
		[AKA_SIM_ID_TYPE_PSEUDONYM]	= ID_TAG_SIM_PSEUDONYM,
		[AKA_SIM_ID_TYPE_FASTAUTH]	= ID_TAG_SIM_PERMANENT,
		[AKA_SIM_ID_TYPE_UNKNOWN]	= '\0',
	},
	[AKA_SIM_METHOD_HINT_AKA] = {
		[AKA_SIM_ID_TYPE_PERMANENT]	= ID_TAG_AKA_PERMANENT,
		[AKA_SIM_ID_TYPE_PSEUDONYM]	= ID_TAG_AKA_PSEUDONYM,
		[AKA_SIM_ID_TYPE_FASTAUTH]	= ID_TAG_AKA_PERMANENT,
		[AKA_SIM_ID_TYPE_UNKNOWN]	= '\0',
	},
	[AKA_SIM_METHOD_HINT_AKA_PRIME] = {
		[AKA_SIM_ID_TYPE_PERMANENT]	= ID_TAG_AKA_PRIME_PERMANENT,
		[AKA_SIM_ID_TYPE_PSEUDONYM]	= ID_TAG_AKA_PRIME_PSEUDONYM,
		[AKA_SIM_ID_TYPE_FASTAUTH]	= ID_TAG_AKA_PRIME_PERMANENT,
		[AKA_SIM_ID_TYPE_UNKNOWN]	= '\0',
	},
	[AKA_SIM_METHOD_HINT_UNKNOWN] = {
		'\0'	/* Should set for all elements */
	}
};

/** Return the expected identity hint for a given type/method combination
 *
 * @param[in] type	Whether this is a permanent, pseudonym or fastauth ID
 * @param[in] method	What EAP-Method the identity hints at.
 * @return
 *	- An IMSI tag byte [0-9] (ASCII)
 *	- '\0' if either the method or type values are unknown.
 */
char fr_aka_sim_hint_byte(fr_aka_sim_id_type_t type, fr_aka_sim_method_hint_t method)
{
	return hint_byte_matrix[method][type];
}

/** Create a 3gpp pseudonym from a permanent ID
 *
 * @param[out] out	Where to write the resulting pseudonym, must be a buffer of
 *			exactly AKA_SIM_3GPP_PSEUDONYM_LEN + 1 bytes.
 * @param[in] imsi	Permanent ID to derive pseudonym from.  Note: If the IMSI is less than
 *			15 digits it will be rpadded with zeros.
 * @param[in] imsi_len	Length of the IMSI. Must be between 1-15.
 * @param[in] tag	Tag value to prepend to the pseudonym. This field is 6 bits (0-63).
 * @param[in] key_ind	Key indicator (or key index), the key number used to produce
 *			the encr ID.  There may be up to 16 keys in use at any one
 *			time. This field is 4 bits (0-15).
 * @param[in] key	as described by the 'Security aspects of non-3GPP accesses' document.
 *			Must be 128 bits (16 bytes).
 * @return
 *	- 0 on success.
 *	- -1 if any of the parameters were invalid.
 */
int fr_aka_sim_id_3gpp_pseudonym_encrypt(char out[AKA_SIM_3GPP_PSEUDONYM_LEN + 1],
					 char const *imsi, size_t imsi_len,
					 uint8_t tag, uint8_t key_ind, uint8_t const key[16])
{
	uint8_t		padded[16];				/* Random (8 bytes) + Compressed (8 bytes) */
	uint8_t		encr[16];				/* aes_ecb(padded) */
	size_t		encr_len, len = 0;

	char		*out_p = out;

	char const	*p = imsi, *end = p + imsi_len;
	uint8_t		*u_p, *u_end;
	uint32_t	rand[2];
	uint8_t		*compressed = padded + sizeof(rand);	/* Part of padded which contains the compressed IMSI */

	EVP_CIPHER_CTX	*evp_ctx;

	if (unlikely(key_ind > 15)) {				/* 4 bits */
		fr_strerror_printf("Invalid key indicator value, expected value between 0-15, got %u", key_ind);
		return -1;
	}
	if (unlikely(tag > 63)) {				/* 6 bits */
		fr_strerror_printf("Invalid tag value, expected value between 0-63, got %u", tag);
		return -1;
	}

	/*
	 *	Technically the IMSI number is between 14-15, but this
	 *	encryption scheme only works for 15 char IMSIs.
	 */
	if (unlikely(imsi_len != AKA_SIM_IMSI_MAX_LEN)) {
		fr_strerror_printf("Invalid ID len, expected length of 15, got %zu", imsi_len);
		return -1;
	}
	if (unlikely(!key)) {
		fr_strerror_printf("Provided key was NULL");
		return -1;
	}

	memset(padded, 0, sizeof(padded));			/* So we don't output garbage if imsi_len < 15 */

	/*
	 *	ID is an odd length (15).
	 */
	*compressed++ = (0xf0 | (*p++ - '0'));

	/*
	 *	Because we know the remaining IMSI length
	 *	is a multiple of two, we can consume it
	 *	2 bytes at a time (omnomnom).
	 */
	while (p < end) {
		if (unlikely(!isdigit((char)p[0]) || !isdigit((char)p[1]))) {
			fr_strerror_printf("IMSI contains invalid character");
			return -1;
		}

		*compressed++ = ((p[0] - '0') << 4) | (p[1] - '0');
		p += 2;
	}

	/*
	 *	Add 8 bytes of random data to pad out the
	 *	compressed IMSI to a multiple of 16 (needed
	 *	to help secure AES-ECB).
	 */
	rand[0] = fr_rand();
	rand[1] = fr_rand();

	memcpy(padded, (uint8_t *)rand, sizeof(rand));

	/*
	 *	Now we have to encrypt the padded IMSI with AES-ECB
	 */
	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("Failed allocating EVP context");
		return -1;
	}

	if (unlikely(EVP_EncryptInit_ex(evp_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)) {
		tls_strerror_printf("Failed initialising AES-128-ECB context");
	error:
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
	}

	/*
	 *	By default OpenSSL will try and pad out a 16 byte
	 *	plaintext to 32 bytes so that it's detectable that
	 *	there was padding.
	 *
	 *	In this case we know the length of the plaintext
	 *	we're trying to recover, so we explicitly tell
	 *	OpenSSL not to pad here, and not to expected padding
	 *	when decrypting.
	 */
	EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
	if (unlikely(EVP_EncryptUpdate(evp_ctx, encr, (int *)&len, padded, sizeof(padded)) != 1)) {
		tls_strerror_printf("Failed encrypting padded IMSI");
		goto error;
	}
	encr_len = len;

	if (unlikely(EVP_EncryptFinal_ex(evp_ctx, encr + len, (int *)&len) != 1)) {
		tls_strerror_printf("Failed finalising encrypted IMSI");
		goto error;
	}
	encr_len += len;

	/*
	 *	Ciphertext should be same length as plaintext.
	 */
	if (unlikely(encr_len != sizeof(padded))) {
		fr_strerror_printf("Invalid ciphertext length, expected %zu, got %zu", sizeof(padded), encr_len);
		goto error;
	}

	EVP_CIPHER_CTX_free(evp_ctx);

	/*
	 *	Now encode the entire output as base64.
	 */
	u_p = encr;
	u_end = u_p + encr_len;

	/*
	 *	Consume tag (6 bits) + key_ind (4 bits) + encr[0] (8 bits) = 18 bits (or 3 bytes of b64)
	 */
	*out_p++ = fr_base64_str[tag & 0x3f];							/* 6 bits tag */
	*out_p++ = fr_base64_str[((key_ind & 0x0f) << 2) | ((u_p[0] & 0xc0) >> 6)];		/* 4 bits key_ind + 2 high bits encr[0] */
	*out_p++ = fr_base64_str[u_p[0] & 0x3f];						/* 6 low bits of encr[0] */
	u_p++;

	/*
	 *	Consume 3 bytes of input for 4 bytes of b64 (5 iterations)
	 */
	while (u_p < u_end) {
		*out_p++ = fr_base64_str[(u_p[0] & 0xfc) >> 2];					/* 6 high bits of p[0] */
		*out_p++ = fr_base64_str[((u_p[0] & 0x03) << 4) | ((u_p[1] & 0xf0) >> 4)];	/* 2 low bits of p[0] + 4 high bits of p[1] */
		*out_p++ = fr_base64_str[((u_p[1] & 0x0f) << 2) | ((u_p[2] & 0xc0) >> 6)];	/* 4 low bits of p[1] + 2 high bits of p[2] */
		*out_p++ = fr_base64_str[u_p[2] & 0x3f];					/* 6 low bits of p[2] */
		u_p += 3;
	}
	if ((out_p - out) != AKA_SIM_3GPP_PSEUDONYM_LEN) {
		fr_strerror_printf("Base64 output length invalid, expected %i bytes, got %zu bytes",
				   AKA_SIM_3GPP_PSEUDONYM_LEN, out_p - out);
		return -1;
	}

	out[AKA_SIM_3GPP_PSEUDONYM_LEN] = '\0';

	return 0;
}

/** Return the tag from a 3gpp pseudonym
 *
 * @param[in] encr_id	The 3gpp pseudonym.
 *
 * @return the tag associated with the pseudonym.
 */
uint8_t fr_aka_sim_id_3gpp_pseudonym_tag(char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN])
{
	return fr_base64_sextet[us(encr_id[0])];
}

/** Return the key index from a 3gpp pseudonym
 *
 * @param[in] encr_id	The 3gpp pseudonym.
 *
 * @return the key index associated with the pseudonym.
 */
uint8_t fr_aka_sim_id_3gpp_pseudonym_key_index(char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN])
{
	return ((fr_base64_sextet[us(encr_id[1])] & 0x3c) >> 2);
}

/** Decrypt the 3GPP pseudonym
 *
 * @param[out] out		Where to write the decypted, uncompressed IMSI.
 * @param[in] encr_id		to decypt. Will read exactly 23 bytes from the buffer.
 * @param[in] key		to use to decrypt the encrypted and compressed IMSI.
 *				Must be 128 bits (16 bytes).
 * @return
 *	- 0 on success.
 *	- -1 if any of the parameters were invalid.
 */
int fr_aka_sim_id_3gpp_pseudonym_decrypt(char out[AKA_SIM_IMSI_MAX_LEN + 1],
				     char const encr_id[AKA_SIM_3GPP_PSEUDONYM_LEN], uint8_t const key[16])
{
	EVP_CIPHER_CTX	*evp_ctx;

	char		*out_p = out;

	uint8_t		dec[16];
	uint8_t		*dec_p = dec;

	uint8_t		decr[16];
	uint8_t		*compressed = decr + 8;		/* Pointer into plaintext after the random component */
	size_t		decr_len;

	char const	*p = encr_id, *end = p + AKA_SIM_3GPP_PSEUDONYM_LEN;

	size_t		len = 0;
	int		i;

	for (i = 0; i < AKA_SIM_3GPP_PSEUDONYM_LEN; i++) {
		if (!fr_is_base64(encr_id[i])) {
			fr_strerror_printf("Encrypted IMSI contains non-base64 char '%pV'",
					   fr_box_strvalue_len(&encr_id[i], 1));
			return -1;
		}
	}

	*dec_p++ = (((fr_base64_sextet[us(p[1])] & 0x03) << 6) | fr_base64_sextet[us(p[2])]);
	p += 3;

	while (p < end) {
		*dec_p++ = ((fr_base64_sextet[us(p[0])] << 2) | (fr_base64_sextet[us(p[1])] >> 4));
		*dec_p++ = ((fr_base64_sextet[us(p[1])] << 4) & 0xf0) | (fr_base64_sextet[us(p[2])] >> 2);
		*dec_p++ = ((fr_base64_sextet[us(p[2])] << 6) & 0xc0) | fr_base64_sextet[us(p[3])];

		p += 4;	/* 32bit input -> 24bit output */
	}

	evp_ctx = EVP_CIPHER_CTX_new();
	if (!evp_ctx) {
		tls_strerror_printf("Failed allocating EVP context");
		return -1;
	}

	if (unlikely(EVP_DecryptInit_ex(evp_ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)) {
		tls_strerror_printf("Failed initialising AES-128-ECB context");
	error:
		EVP_CIPHER_CTX_free(evp_ctx);
		return -1;
	}

	/*
	 *	By default OpenSSL expects 16 bytes of plaintext
	 *	to produce 32 bytes of ciphertext, due to padding
	 *	being added if the plaintext is a multiple of 16.
	 *
	 *	There's no way for OpenSSL to determine if a
	 *	16 byte ciphertext was padded or not, so we need to
	 *	inform OpenSSL explicitly that there's no padding.
	 */
	EVP_CIPHER_CTX_set_padding(evp_ctx, 0);
	if (unlikely(EVP_DecryptUpdate(evp_ctx, decr, (int *)&len, dec, sizeof(dec)) != 1)) {
		tls_strerror_printf("Failed decypting IMSI");
		goto error;
	}
	decr_len = len;

	if (unlikely(EVP_DecryptFinal_ex(evp_ctx, decr + len, (int *)&len) != 1)) {
		tls_strerror_printf("Failed finalising decypted IMSI");
		goto error;
	}
	decr_len += len;

	/*
	 *	This should never happen, and probably means that
	 *	some sort of memory corruption has occured.
	 */
	if (unlikely(decr_len > (AKA_SIM_IMSI_MAX_LEN + 1))) {
		fr_strerror_printf("Decrypted data len invalid.  Expected %i bytes, got %zu bytes",
				   (AKA_SIM_IMSI_MAX_LEN + 1), decr_len);
		goto error;
	}

	/*
	 *	Decompress the IMSI
	 *
	 *	The first 8 octets are a junk random value which
	 *	we ignore.
	 */
	*out_p++ = (compressed[0] & 0x0f) + '0';
	for (i = 1; i < 8; i++) {
		*out_p++ = ((compressed[i] & 0xf0) >> 4) + '0';
		*out_p++ = (compressed[i] & 0x0f) + '0';
	}

	EVP_CIPHER_CTX_free(evp_ctx);

	out[AKA_SIM_IMSI_MAX_LEN] = '\0';

	return 0;
}

#ifdef TESTING_SIM_ID
/*
 *  cc id.c -g3 -Wall -DHAVE_DLFCN_H -DTESTING_SIM_ID -DWITH_TLS -I../../../../ -I../../../ -I ../base/ -I /usr/local/opt/openssl/include/ -include ../include/build.h -L /usr/local/opt/openssl/lib/ -l ssl -l crypto -l talloc -L ../../../../../build/lib/local/.libs/ -lfreeradius-server -lfreeradius-tls -lfreeradius-util -o test_sim_id && ./test_sim_id
 */
#include <stddef.h>
#include <stdbool.h>
#include <freeradius-devel/util/acutest.h>

void test_encrypt_decypt_key0(void)
{
	char const	id[] = "001234554321001";
	char const	key[] = "1234567812345678";
	uint8_t		tag;
	uint8_t		key_ind;
	char const	*log;

	char		encrypted_id[AKA_SIM_3GPP_PSEUDONYM_LEN + 1];
	char		decrypted_id[sizeof(id)];

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_encrypt(encrypted_id, id, sizeof(id) - 1, 6, 0, (uint8_t const *)key) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	tag = fr_aka_sim_id_3gpp_pseudonym_tag(encrypted_id);
	TEST_CHECK(tag == 6);
	key_ind = fr_aka_sim_id_3gpp_pseudonym_key_index(encrypted_id);
	TEST_CHECK(key_ind == 0);

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_decrypt(decrypted_id, encrypted_id, (uint8_t const *)key) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	TEST_CHECK(memcmp(id, decrypted_id, 15) == 0);
}

void test_encrypt_decypt_key1(void)
{
	char const	id[] = "001234554321001";
	char const	key[] = "1234567812345678";
	uint8_t		tag;
	uint8_t		key_ind;
	char const	*log;

	char		encrypted_id[AKA_SIM_3GPP_PSEUDONYM_LEN + 1];
	char		decrypted_id[sizeof(id)];

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_encrypt(encrypted_id, id, sizeof(id) - 1, 11, 1, (uint8_t const *)key) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	tag = fr_aka_sim_id_3gpp_pseudonym_tag(encrypted_id);
	TEST_CHECK(tag == 11);
	key_ind = fr_aka_sim_id_3gpp_pseudonym_key_index(encrypted_id);
	TEST_CHECK(key_ind == 1);

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_decrypt(decrypted_id, encrypted_id, (uint8_t const *)key) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	TEST_CHECK(memcmp(id, decrypted_id, 15) == 0);
}

void test_encrypt_decypt_key16(void)
{
	char const	id[] = "001234554321001";
	char const	key0[] = "1234567812345678";
	char const	key1[] = "2222222288888888";
	char const	key2[] = "2222222299999999";
	char const	key3[] = "2222222200000000";
	char const	key4[] = "2222222211111111";
	char const	key5[] = "2222222222222222";
	char const	key6[] = "2222222233333333";
	char const	key7[] = "2222222244444444";
	char const	key8[] = "2222222255555555";
	char const	key9[] = "2222222266666666";
	char const	key10[] = "2222222277777777";
	char const	key11[] = "1111111188888888";
	char const	key12[] = "2222222288888888";
	char const	key13[] = "3333333388888888";
	char const	key14[] = "4444444488888888";
	char const	key15[] = "5555555588888888";
	char const	*keys[] = { key0, key1, key2, key3, key4, key5,
				    key6, key7, key8, key9, key10, key11,
				    key12, key13, key14, key15 };
	uint8_t		tag;
	uint8_t		key_ind;
	char const	*log;

	char		encrypted_id[AKA_SIM_3GPP_PSEUDONYM_LEN + 1];
	char		decrypted_id[sizeof(id)];

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_encrypt(encrypted_id, id, sizeof(id) - 1,
							9, 15, (uint8_t const *)keys[15]) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	tag = fr_aka_sim_id_3gpp_pseudonym_tag(encrypted_id);
	TEST_CHECK(tag == 9);
	key_ind = fr_aka_sim_id_3gpp_pseudonym_key_index(encrypted_id);
	TEST_CHECK(key_ind == 15);

	TEST_CHECK(fr_aka_sim_id_3gpp_pseudonym_decrypt(decrypted_id, encrypted_id, (uint8_t const *)keys[key_ind]) == 0);
	while ((log = fr_strerror_pop())) printf("%s\n", log);

	TEST_CHECK(memcmp(id, decrypted_id, 15) == 0);
}

TEST_LIST = {
	/*
	 *	Initialisation
	 */
	{ L("encrypt_decrypt key0"),	test_encrypt_decypt_key0 },
	{ L("encrypt_decrypt key1"),	test_encrypt_decypt_key1 },
	{ L("encrypt_decrypt key16"),	test_encrypt_decypt_key16 },

	{ NULL }
};
#endif
