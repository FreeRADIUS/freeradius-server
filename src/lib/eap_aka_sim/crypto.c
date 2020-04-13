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
 * @file src/lib/eap_aka_sim/crypto.c
 * @brief Calculate keys from GSM vectors.
 *
 * The development of the original EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa). The original EAP-SIM PRF functions were written
 * by Michael Richardson <mcr@sandelman.ottawa.on.ca>, but these have since been
 * replaced.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2003-2018 The FreeRADIUS server project
 * @copyright 2016-2018 Network RADIUS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include <freeradius-devel/protocol/eap/aka-sim/dictionary.h>

#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/sim/common.h>
#include <freeradius-devel/sim/milenage.h>
#include <freeradius-devel/tls/base.h>
#include <freeradius-devel/util/proto.h>
#include <freeradius-devel/util/rand.h>
#include <freeradius-devel/util/sha1.h>
#include <openssl/evp.h>

#include "base.h"
#include "attrs.h"

/** Free OpenSSL memory associated with our checkcode ctx
 *
 * @param[in] checkcode to free.
 * @return 0
 */
static int _fr_aka_sim_crypto_free_checkcode(fr_aka_sim_checkcode_t *checkcode)
{
	if (checkcode->md_ctx) EVP_MD_CTX_destroy(checkcode->md_ctx);
	return 0;
}

/** Initialise checkcode message digest
 *
 * @param[in] ctx		to allocate checkcode structure in.
 * @param[out] checkcode	a new checkcode structure.
 * @param[in] md		to use when calculating the checkcode,
 *				either EVP_sha1(), or EVP_sha256().
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_init_checkcode(TALLOC_CTX *ctx, fr_aka_sim_checkcode_t **checkcode, EVP_MD const *md)
{
	*checkcode = talloc_zero(ctx, fr_aka_sim_checkcode_t);
	if (!*checkcode) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	(*checkcode)->md_ctx = EVP_MD_CTX_create();
	if (!(*checkcode)->md_ctx) {
		tls_strerror_printf("Failed creating MD ctx");
	error:
		TALLOC_FREE(*checkcode);
		return -1;
	}
	if (EVP_DigestInit_ex((*checkcode)->md_ctx, md, NULL) != 1) {
		tls_strerror_printf("Failed intialising MD ctx");
		goto error;
	}

	talloc_set_destructor(*checkcode, _fr_aka_sim_crypto_free_checkcode);

	return 0;
}

/** Digest a packet, updating the checkcode
 *
 * Call #fr_aka_sim_crypto_finalise_checkcode to obtain the final checkcode value.
 *
 * @param[in,out] checkcode	if *checkcode is NULL, a new checkcode structure
 *				will be allocated and the message digest context
 *				will be initialised before the provided
 *				eap_packet is fed into the digest.
 * @param[in] eap_packet	to digest.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_update_checkcode(fr_aka_sim_checkcode_t *checkcode, eap_packet_t *eap_packet)
{
	uint16_t		packet_len;
	eap_packet_raw_t	eap_hdr;

	eap_hdr.code = eap_packet->code;
	eap_hdr.id = eap_packet->id;
	packet_len = htons((sizeof(eap_hdr) + eap_packet->type.length) & UINT16_MAX); /* EAP Header + Method + SIM data */
	memcpy(&eap_hdr.length, &packet_len, sizeof(packet_len));
	eap_hdr.data[0] = eap_packet->type.num;

	/*
	 *	Digest the header
	 */
	if (EVP_DigestUpdate(checkcode->md_ctx, &eap_hdr, sizeof(eap_hdr)) != 1) {
		tls_strerror_printf("Failed digesting EAP header");
		return -1;
	}

	/*
	 *	Digest the packet
	 */
	if (EVP_DigestUpdate(checkcode->md_ctx, eap_packet->type.data, eap_packet->type.length) != 1) {
		tls_strerror_printf("Failed digesting packet data");
		return -1;
	}

	return 0;
}

/** Write out the final checkcode value
 *
 * @param[out] out		Where to write the checkcode value.  Must be at least 20
 *				bytes if MD was SHA1, or 32 bytes if MD was SHA256.
 * @param[in,out] checkcode	structure to get final digest from and to tree.
 * @return
 *	- <= 0 on failure.
 *	- > 0 the number of bytes written to out.
 */
ssize_t fr_aka_sim_crypto_finalise_checkcode(uint8_t *out, fr_aka_sim_checkcode_t **checkcode)
{
	unsigned int len;

	if (EVP_DigestFinal_ex((*checkcode)->md_ctx, out, &len) != 1) {
		tls_strerror_printf("Failed finalising checkcode digest");
		TALLOC_FREE(*checkcode);
		return -1;
	}

	TALLOC_FREE(*checkcode);

	return len;
}

/** Locate the start of the AT_MAC value in the buffer
 *
 * @param[out] out	The start of the digest portion of the AT_MAC attribute.
 * @param[in] data	to search for the AT_MAC in.
 * @param[in] data_len	size of the data.
 * @return
 *	- 1 if we couldn't find a MAC.
 *	- 0 if we found and zeroed out the mac field.
 *	- -1 if the field was malformed.
 */
static int fr_aka_sim_find_mac(uint8_t const **out, uint8_t *data, size_t data_len)
{
	uint8_t *p = data, *end = p + data_len;
	size_t len;

	*out = NULL;

	p += 3;	/* Skip header */
	while ((p + 2) < end) {
		if (p[0] == FR_MAC) {
			len = p[1] << 2;
			if ((p + len) > end) {
				fr_strerror_printf("Malformed AT_MAC: Length (%zu) exceeds buffer (%zu)", len, end - p);
				return -1;
			}

			if (len != AKA_SIM_MAC_SIZE) {
				fr_strerror_printf("Malformed AT_MAC: Length (%zu) incorrect (%u)",
						   len, AKA_SIM_MAC_SIZE);
				return -1;
			}
			*out = p + 4;

			return 0;
		}
		p += p[1] << 2;		/* Advance */
	}

	fr_strerror_printf("No MAC attribute found");

	return 1;
}

/** Calculate the digest value for a packet
 *
 * Run a digest over a fake EAP header, the entire SIM packet and any extra HMAC data,
 * writing a truncated (16 byte) digest value to out.
 *
 * @note The 16 byte digest field in the packet must have either been zeroed out before
 *	 this function is called (as it is when encoding data), or zero_mac must be set
 *	 to true.
 *
 * @note This function uses the EVP_* signing functions.  Do not be tempted to swap them
 *	 for the HMAC functions, as the EVP interface may be hardware accelerated but
 *	 the HMAC interface is purely a software implementation.
 *
 * @param[out] out		Where to write the digest.
 * @param[in] eap_packet	to extract header values from.
 * @param[in] zero_mac		Assume the mac field is not zeroed (i.e. received packet)
 *				and skip it during mac calculation feeding in 16 zeroed
 *				bytes in its place.
 * @param[in] md		to use to create the HMAC.
 * @param[in] key		to use to sign the packet.
 * @param[in] key_len		Length of the key.
 * @param[in] hmac_extra	data to concatenate with the packet when calculating the HMAC
 *				(may be NULL).
 * @param[in] hmac_extra_len	Length of hmac_extra (may be zero).
 * @return
 *	- < 0 on failure.
 *	- 0 if there's no MAC attribute to verify.
 *	- > 0 the number of bytes written to out.
 */
ssize_t fr_aka_sim_crypto_sign_packet(uint8_t out[static AKA_SIM_MAC_DIGEST_SIZE],
				      eap_packet_t *eap_packet, bool zero_mac,
				      EVP_MD const *md, uint8_t const *key, size_t const key_len,
				      uint8_t const *hmac_extra, size_t const hmac_extra_len)
{
	EVP_MD_CTX		*md_ctx = NULL;
	EVP_PKEY		*pkey;

	uint8_t			digest[SHA256_DIGEST_LENGTH];
	size_t			digest_len = 0;
	uint8_t	const		*mac;
	uint8_t			*p = eap_packet->type.data, *end = p + eap_packet->type.length;

	eap_packet_raw_t	eap_hdr;
	uint16_t		packet_len;

	if (unlikely(!eap_packet)) {
		fr_strerror_printf("Invalid argument: eap_packet is NULL");
		return -1;
	}

	if (unlikely(!md)) {
		fr_strerror_printf("Invalid argument: md is NULL");
		return -1;
	}

	if (unlikely(!key) || (key_len == 0)) {
		fr_strerror_printf("Invalid argument: key is NULL");
		return -1;
	}

	FR_PROTO_HEX_DUMP(key, key_len, "MAC key");
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
	if (!pkey) {
		tls_strerror_printf("Failed creating HMAC signing key");
	error:
		if (pkey) EVP_PKEY_free(pkey);
		if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx) {
		tls_strerror_printf("Failed creating HMAC ctx");
		goto error;
	}

	if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey) != 1) {
		tls_strerror_printf("Failed initialising digest");
		goto error;
	}

	/*
	 *	The HMAC has to be over the entire packet, which
	 *	we don't get access too.  So we create a fake EAP
	 *	header now, and feed that into the HMAC function.
	 */
	eap_hdr.code = eap_packet->code;
	eap_hdr.id = eap_packet->id;
	packet_len = htons((sizeof(eap_hdr) + eap_packet->type.length) & UINT16_MAX); /* EAP Header + Method + SIM data */
	memcpy(&eap_hdr.length, &packet_len, sizeof(packet_len));
	eap_hdr.data[0] = eap_packet->type.num;

	FR_PROTO_HEX_DUMP((uint8_t *)&eap_hdr, sizeof(eap_hdr), "MAC digest input (eap header)");
	if (EVP_DigestSignUpdate(md_ctx, &eap_hdr, sizeof(eap_hdr)) != 1) {
		tls_strerror_printf("Failed digesting EAP data");
		goto error;
	}

	/*
	 *	Digest the packet up to the AT_MAC, value, then
	 *	digest 16 bytes of zero.
	 */
	if (zero_mac) {
		switch (fr_aka_sim_find_mac(&mac, p, end - p)) {
		case 0:
		{
			uint8_t zero[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			FR_PROTO_HEX_DUMP(p, mac - p, "MAC digest input");

			/*
			 *	Digest everything up to the hash
			 *	part of the AT_MAC, including
			 *	AT_MAC header and reserved bytes.
			 */
			if (EVP_DigestSignUpdate(md_ctx, p, mac - p) != 1) {
				tls_strerror_printf("Failed digesting packet data (before MAC)");
				goto error;
			}
			p += mac - p;


			FR_PROTO_HEX_DUMP(zero, sizeof(zero), "MAC digest input");
			/*
			 *	Feed in 16 bytes of zeroes to
			 *	simulated the zeroed out Mac.
			 */
			if (EVP_DigestSignUpdate(md_ctx, zero, sizeof(zero)) != 1) {
				tls_strerror_printf("Failed digesting zeroed MAC");
				goto error;
			}
			p += sizeof(zero);
		}
			break;

		case 1:
			return 0;

		case -1:
			fr_assert(0);	/* Should have been checked by encoder or decoder */
			goto error;
		}
	}

	if (p < end) {
		FR_PROTO_HEX_DUMP(p, (end - p), "MAC digest input");

		/*
		 *	Digest the rest of the packet.
		 */
		if (EVP_DigestSignUpdate(md_ctx, p, end - p) != 1) {
			tls_strerror_printf("Failed digesting packet data");
			goto error;
		}
	}

	/*
	 *	Digest any HMAC concatenated data
	 *
	 *	Some subtypes require the HMAC to be calculated over
	 *	a concatenation of packet data, and something extra...
	 */
	if (hmac_extra) {
		FR_PROTO_HEX_DUMP(hmac_extra, hmac_extra_len, "MAC digest input (extra)");
		if (EVP_DigestSignUpdate(md_ctx, hmac_extra, hmac_extra_len) != 1) {
			tls_strerror_printf("Failed digesting HMAC extra data");
			goto error;
		}
	}

	if (EVP_DigestSignFinal(md_ctx, digest, &digest_len) != 1) {
		tls_strerror_printf("Failed finalising digest");
		goto error;
	}

	FR_PROTO_HEX_DUMP(digest, digest_len, "MAC");

	/*
	 *	Truncate by four bytes.
	 */
	memcpy(out, digest, 16);

	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(md_ctx);

	return 16;	/* AT_MAC (1), LEN (1), RESERVED (2) */
}

/** Key Derivation Function as described in RFC4186 (EAP-SIM) section 7
 *
 @verbatim
	MK     = SHA1(Identity|n*Kc| NONCE_MT| Version List| Selected Version)
	FK     = PRF(MK)
	K_encr = FK[0..127]
	K_aut  = FK[128..255]
	MSK    = FK[256..767]
	EMSK   = FK[768..1279]
 @endverbatim
 * @note expects keys to contain a AKA_SIM_VECTOR_GSM.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_gsm_kdf_0(fr_aka_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];

	uint8_t		buf[AKA_SIM_MAX_STRING_LENGTH + sizeof(keys->gsm.nonce_mt) + 2 + sizeof(keys->gsm.version_select)];
	uint8_t		*p;

	if (!fr_cond_assert(keys->vector_type == AKA_SIM_VECTOR_GSM)) return -1;

	/*
	 *	Our stack buffer should be large enough in
	 *	all cases.
	 */
	if (!fr_cond_assert((keys->identity_len +
			    (AKA_SIM_VECTOR_GSM_KC_SIZE * 3) +
			    sizeof(keys->gsm.nonce_mt) +
			    keys->gsm.version_list_len +
			    sizeof(keys->gsm.version_select)) <= sizeof(buf))) return -1;

	p = buf;
	memcpy(p, keys->identity, keys->identity_len);
	p += keys->identity_len;

	memcpy(p, keys->gsm.vector[0].kc, AKA_SIM_VECTOR_GSM_KC_SIZE);
	p += AKA_SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.vector[1].kc, AKA_SIM_VECTOR_GSM_KC_SIZE);
	p += AKA_SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.vector[2].kc, AKA_SIM_VECTOR_GSM_KC_SIZE);
	p += AKA_SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.nonce_mt, sizeof(keys->gsm.nonce_mt));
	p += sizeof(keys->gsm.nonce_mt);

	memcpy(p, keys->gsm.version_list, keys->gsm.version_list_len);
	p += keys->gsm.version_list_len;

	memcpy(p, keys->gsm.version_select, sizeof(keys->gsm.version_select));
	p += sizeof(keys->gsm.version_select);

	FR_PROTO_HEX_DUMP(buf, p - buf, "Identity || n*Kc || NONCE_MT || Version List || Selected Version");

	/*
	 *	Do the master key first
	 */
	fr_sha1_init(&context);
	fr_sha1_update(&context, buf, p - buf);
	fr_sha1_final(keys->mk, &context);

	FR_PROTO_HEX_DUMP(keys->mk, sizeof(keys->mk), "Master key");

	/*
	 *	Now use the PRF to expand it, generated
	 *	k_aut, k_encr, MSK and EMSK.
	 */
	fr_aka_sim_fips186_2prf(fk, keys->mk);

	/*
	 *	Split up the result
	 */
	p = fk;
	memcpy(keys->k_encr, p, 16);				/* 128 bits for encryption */
	p += 16;
	FR_PROTO_HEX_DUMP(keys->k_encr, sizeof(keys->k_encr), "K_encr");

	memcpy(keys->k_aut, p, EAP_AKA_SIM_AUTH_SIZE);		/* 128 bits for auth */
	p += EAP_AKA_SIM_AUTH_SIZE;
	keys->k_aut_len = EAP_AKA_SIM_AUTH_SIZE;
	FR_PROTO_HEX_DUMP(keys->k_aut, keys->k_aut_len, "K_aut");

	memcpy(keys->msk, p, 64);				/* 64 bytes for Master Session Key */
	p += 64;
	FR_PROTO_HEX_DUMP(keys->msk, sizeof(keys->msk), "K_msk");

	memcpy(keys->emsk, p, 64);				/* 64 bytes for Extended Master Session Key */
	FR_PROTO_HEX_DUMP(keys->emsk, sizeof(keys->emsk), "K_emsk");

	return 0;
}

/** Key Derivation Function as described in RFC4187 (EAP-AKA) section 7
 *
 * @note expects keys to contain a AKA_SIM_VECTOR_UMTS.
 *
 @verbatim
	MK     = SHA1(Identity|IK|CK)
	FK     = PRF(MK)
	K_encr = FK[0..127]
	K_aut  = FK[128..255]
	MSK    = FK[256..767]
	EMSK   = FK[768..1279]
 @endverbatim
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_umts_kdf_0(fr_aka_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[AKA_SIM_MAX_STRING_LENGTH + sizeof(keys->umts.vector.ik) + sizeof(keys->umts.vector.ck)];
	uint8_t		*p;
	size_t		blen;

	if (!fr_cond_assert(keys->vector_type == AKA_SIM_VECTOR_UMTS)) return - 1;

	/*
	 *	Our stack buffer should be large enough in
	 *	all cases.
	 */
	if (!fr_cond_assert((keys->identity_len +
			     sizeof(keys->umts.vector.ik) +
			     sizeof(keys->umts.vector.ck)) <= sizeof(buf))) return -1;

	p = buf;
	memcpy(p, keys->identity, keys->identity_len);
	p += keys->identity_len;

	memcpy(p, keys->umts.vector.ik, sizeof(keys->umts.vector.ik));
	p += sizeof(keys->umts.vector.ik);

	memcpy(p, keys->umts.vector.ck, sizeof(keys->umts.vector.ck));
	p += sizeof(keys->umts.vector.ck);

	blen = p - buf;

	/* do the master key first */
	fr_sha1_init(&context);
	fr_sha1_update(&context, buf, blen);
	fr_sha1_final(keys->mk, &context);

	/*
   	 * now use the PRF to expand it, generated k_aut, k_encr,
	 * MSK and EMSK.
	 */
	fr_aka_sim_fips186_2prf(fk, keys->mk);

	/* split up the result */
	p = fk;

	memcpy(keys->k_encr, p, 16);				/* 128 bits for encryption    */
	p += 16;

	memcpy(keys->k_aut, p, EAP_AKA_AUTH_SIZE);		/* 128 bits for auth */
	p += EAP_AKA_AUTH_SIZE;
	keys->k_aut_len = EAP_AKA_AUTH_SIZE;

	memcpy(keys->msk, p, 64);				/* 64 bytes for Master Session Key */
	p += 64;

	memcpy(keys->emsk, p, 64);				/* 64 bytes for Extended Master Session Key */

	return 0;
}

/** Key Derivation Function (CK', IK') as specified in 3GPP.33.402
 *
 @verbatim
	CK' || IK' = HMAC-SHA-256(Key, S)
	S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
	Key = CK || IK
	FC = 0x20
	P0 = access network identity (3GPP TS 24.302)
	L0 = length of acceess network identity (2 octets, big endian)
	P1 = SQN xor AK (if AK is not used, AK is treated as 000..0
	L1 = 0x00 0x06
 @endverbatim
 *
 * @note expects keys to contain a AKA_SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int ck_ik_prime_derive(fr_aka_sim_keys_t *keys)
{
	uint8_t		digest[sizeof(keys->ik_prime) + sizeof(keys->ck_prime)];
	size_t		len;

	uint8_t		sqn_ak_buff[MILENAGE_SQN_SIZE];
	uint16_t	l0, l1;

	uint8_t		k[sizeof(keys->umts.vector.ik) + sizeof(keys->umts.vector.ck)];
	uint8_t		s[sizeof(uint8_t) + AKA_SIM_MAX_STRING_LENGTH + sizeof(l0) + AKA_SIM_SQN_AK_SIZE + sizeof(l1)];

	uint8_t		*p = s;

	size_t		s_len;
	EVP_PKEY	*pkey;
	EVP_MD_CTX	*md_ctx = NULL;

	if (!fr_cond_assert(keys->vector_type == AKA_SIM_VECTOR_UMTS)) return -1;

	uint48_to_buff(sqn_ak_buff, keys->sqn ^ uint48_from_buff(keys->umts.vector.ak));

	/*
	 *	Our stack buffer should be large enough in
	 *	all cases.
	 */
	if (!fr_cond_assert((sizeof(uint8_t) +
			     keys->network_len +
			     sizeof(l0) +
			     AKA_SIM_SQN_AK_SIZE +
			     sizeof(l1)) <= sizeof(s))) return -1;

	FR_PROTO_HEX_DUMP(keys->network, keys->network_len, "Network");
	FR_PROTO_HEX_DUMP(keys->umts.vector.ck, sizeof(keys->umts.vector.ck), "CK");
	FR_PROTO_HEX_DUMP(keys->umts.vector.ik, sizeof(keys->umts.vector.ik), "IK");
	FR_PROTO_HEX_DUMP(sqn_ak_buff, AKA_SIM_SQN_AK_SIZE, "SQN ⊕ AK");

	/*
	 *	FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
	 */
	*p++ = 0x20;
	memcpy(p, keys->network, keys->network_len);
	p += keys->network_len;

	l0 = htons((uint16_t)keys->network_len);
	memcpy(p, &l0, sizeof(l0));
	p += sizeof(l0);

	memcpy(p, sqn_ak_buff, AKA_SIM_SQN_AK_SIZE);
	p += AKA_SIM_SQN_AK_SIZE;

	l1 = htons(AKA_SIM_SQN_AK_SIZE);
	memcpy(p, &l1, sizeof(l1));
	p += sizeof(l1);

	s_len = p - s;

	FR_PROTO_HEX_DUMP(s, s_len, "FC || P0 || L0 || P1 || L1 || ... || Pn || Ln");

	/*
	 *	CK || IK
	 */
	p = k;
	memcpy(p, keys->umts.vector.ck, sizeof(keys->umts.vector.ck));
	p += sizeof(keys->umts.vector.ck);
	memcpy(p, keys->umts.vector.ik, sizeof(keys->umts.vector.ik));

	FR_PROTO_HEX_DUMP(k, sizeof(k), "CK || IK");

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, k, sizeof(k));
	if (!pkey) {
		tls_strerror_printf("Failed creating HMAC signing key");
	error:
		if (pkey) EVP_PKEY_free(pkey);
		if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx) {
		tls_strerror_printf("Failed creating HMAC ctx");
		goto error;
	}

	if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		tls_strerror_printf("Failed initialising digest");
		goto error;
	}

	if (EVP_DigestSignUpdate(md_ctx, s, s_len) != 1) goto error;
	if (EVP_DigestSignFinal(md_ctx, digest, &len) != 1) goto error;

	memcpy(keys->ik_prime, digest, sizeof(keys->ik_prime));
	memcpy(keys->ck_prime, digest + sizeof(keys->ik_prime), sizeof(keys->ck_prime));

	FR_PROTO_HEX_DUMP(keys->ck_prime, sizeof(keys->ck_prime), "CK'");
	FR_PROTO_HEX_DUMP(keys->ik_prime, sizeof(keys->ik_prime), "IK'");

	EVP_MD_CTX_destroy(md_ctx);;
	EVP_PKEY_free(pkey);

	return 0;
}

/** PRF as described in RFC 5448 (EAP-AKA') section 3.4.1
 *
 @verbatim
	PRF'(K,S) = T1 | T2 | T3 | T4 | ...

	where:
	T1 = HMAC-SHA-256 (K, S | 0x01)
	T2 = HMAC-SHA-256 (K, T1 | S | 0x02)
	T3 = HMAC-SHA-256 (K, T2 | S | 0x03)
	T4 = HMAC-SHA-256 (K, T3 | S | 0x04)
	...
 @endverbatim
 *
 * PRF' produces as many bits of output as is needed.
 *
 * @param[out] out	Where to write the output of the PRF.
 * @param[in] outlen	how many bytes need to be generated.
 * @param[in] key	for the PRF (K).
 * @param[in] key_len	Length of key data.
 * @param[in] in	Data to feed into the PRF (S).
 * @param[in] in_len	Length of input data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int aka_prime_prf(uint8_t *out, size_t outlen,
			 uint8_t const *key, size_t key_len, uint8_t const *in, size_t in_len)
{
	uint8_t		*p = out, *end = p + outlen;
	uint8_t		c = 0;
	uint8_t		digest[SHA256_DIGEST_LENGTH];
	EVP_PKEY	*pkey;
	EVP_MD_CTX	*md_ctx = NULL;

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
	if (!pkey) {
		tls_strerror_printf("Failed creating HMAC signing key");
	error:
		if (pkey) EVP_PKEY_free(pkey);
		if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx) {
		tls_strerror_printf("Failed creating HMAC ctx");
		goto error;
	}

	if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
		tls_strerror_printf("Failed initialising digest");
		goto error;
	}

	while (p < end) {
		size_t len;
		size_t copy;

		c++;

		if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto error;
		if ((p != out) && EVP_DigestSignUpdate(md_ctx, digest, sizeof(digest)) != 1) goto error;/* Ingest last round */
		if (EVP_DigestSignUpdate(md_ctx, in, in_len) != 1) goto error;				/* Ingest s */
		if (EVP_DigestSignUpdate(md_ctx, &c, sizeof(c)) != 1) goto error;			/* Ingest round number */
		if (EVP_DigestSignFinal(md_ctx, digest, &len) != 1) goto error;				/* Output T(i) */

		copy = end - p;
		if (copy > SHA256_DIGEST_LENGTH) copy = SHA256_DIGEST_LENGTH;

		memcpy(p, digest, copy);
		p += copy;
	}

	EVP_MD_CTX_destroy(md_ctx);;
	EVP_PKEY_free(pkey);

	return 0;
}

/** Key Derivation Function as described in RFC 5448 (EAP-AKA') section 3.3
 *
 @verbatim
	MK     = PRF'(IK'|CK',"EAP-AKA'"|Identity)
	K_encr = MK[0..127]
	K_aut  = MK[128..383]
	K_re   = MK[384..639]
	MSK    = MK[640..1151]
	EMSK   = MK[1152..1663]
 @endverbatim
 *
 * @note expects keys to contain a AKA_SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_umts_kdf_1(fr_aka_sim_keys_t *keys)
{
	uint8_t k[sizeof(keys->ck_prime) + sizeof(keys->ik_prime)];
#define KDF_1_S_STATIC	"EAP-AKA'"
	uint8_t s[(sizeof(KDF_1_S_STATIC) - 1) + AKA_SIM_MAX_STRING_LENGTH];
	uint8_t *p = s;

	uint8_t	mk[208];
	size_t	s_len;

	ck_ik_prime_derive(keys);

	if (!fr_cond_assert(keys->vector_type == AKA_SIM_VECTOR_UMTS)) return -1;

	/*
	 *	build s, a concatenation of EAP-AKA' and Identity
	 */
	if (!fr_cond_assert((sizeof(KDF_1_S_STATIC) - 1) + keys->identity_len <= sizeof(s))) return -1;

	memcpy(p, KDF_1_S_STATIC, sizeof(KDF_1_S_STATIC) - 1);
	p += sizeof(KDF_1_S_STATIC) - 1;

	memcpy(p, keys->identity, keys->identity_len);
	p += keys->identity_len;

	s_len = p - s;

	/*
	 *	build k, a concatenation of IK' and CK'
	 */
	p = k;
	memcpy(p, keys->ck_prime, sizeof(keys->ck_prime));
	p += sizeof(keys->ck_prime);

	memcpy(p, keys->ik_prime, sizeof(keys->ik_prime));

	/*
	 *	Feed into PRF
	 */
	if (aka_prime_prf(mk, sizeof(mk), k, sizeof(k), s, s_len) < 0) return -1;

	/*
	 *	Split the PRF output into separate keys
	 */
	p = mk;
	memcpy(keys->k_encr, p, 16);    			/* 128 bits for encryption    */
	p += 16;

	memcpy(keys->k_aut,  p, EAP_AKA_PRIME_AUTH_SIZE);	/* 256 bits for aut */
	p += EAP_AKA_PRIME_AUTH_SIZE;
	keys->k_aut_len = EAP_AKA_PRIME_AUTH_SIZE;

	memcpy(keys->k_re, p, 32);				/* 256 bits for reauthentication key */
	p += 32;

	memcpy(keys->msk, p, sizeof(keys->msk));		/* 64 bytes for Master Session Key */
	p += sizeof(keys->msk);

	memcpy(keys->emsk, p, sizeof(keys->emsk));		/* 64 bytes for Extended Master Session Key */

	return 0;
}


/** Initialise fr_aka_sim_keys_t with EAP-SIM reauthentication data
 *
 * Generates a new nonce_s and copies the mk and counter values into the fr_aka_sim_keys_t.
 *
 * @param[out] keys	structure to populate.
 * @param[in] mk	from original authentication.
 * @param[in] counter	re-authentication counter.
 */
void fr_aka_sim_crypto_keys_init_kdf_0_reauth(fr_aka_sim_keys_t *keys,
					      uint8_t const mk[static AKA_SIM_MK_SIZE], uint16_t counter)
{
	uint32_t nonce_s[4];

	/*
	 *	Copy in master key
	 */
	memcpy(keys->mk, mk, sizeof(keys->mk));

	keys->reauth.counter = counter;

	nonce_s[0] = fr_rand();
	nonce_s[1] = fr_rand();
	nonce_s[2] = fr_rand();
	nonce_s[3] = fr_rand();
	memcpy(keys->reauth.nonce_s, (uint8_t *)&nonce_s, sizeof(keys->reauth.nonce_s));
}

/** Initialise fr_aka_sim_keys_t with EAP-AKA['] reauthentication data
 *
 * Generates a new nonce_s and copies the mk and counter values into the fr_aka_sim_keys_t.
 *
 * @param[out] keys	structure to populate.
 * @param[in] k_re	from original authentication.
 * @param[in] counter	re-authentication counter.
 */
void fr_aka_sim_crypto_keys_init_umts_kdf_1_reauth(fr_aka_sim_keys_t *keys,
						   uint8_t const k_re[static AKA_SIM_K_RE_SIZE], uint16_t counter)
{
	uint32_t nonce_s[4];

	/*
	 *	Copy in master key
	 */
	memcpy(keys->k_re, k_re, sizeof(keys->k_re));

	keys->reauth.counter = counter;

	nonce_s[0] = fr_rand();
	nonce_s[1] = fr_rand();
	nonce_s[2] = fr_rand();
	nonce_s[3] = fr_rand();
	memcpy(keys->reauth.nonce_s, (uint8_t *)&nonce_s, sizeof(keys->reauth.nonce_s));
}

/** Key Derivation Function (Fast-Reauthentication) as described in RFC4186/7 (EAP-SIM/AKA) section 7
 *
 @verbatim
	XKEY' = SHA1(Identity|counter|NONCE_S|MK)
	FK    = PRF(XKEY')
	MSK   = FK[0..511]
	EMSK  = FK[512..1023]
 @endverbatim
 *
 * Derives new MSK, EMSK, k_aut, k_encr
 *
 * Use #fr_aka_sim_crypto_keys_init_kdf_0_reauth to populate the #fr_aka_sim_keys_t structure.
 *
 * @note expects keys to contain a populated mk, none_s and counter values.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_kdf_0_reauth(fr_aka_sim_keys_t *keys)
{
	EVP_MD_CTX	*md_ctx;
	uint8_t		fk[160];

	uint8_t		buf[384];
	uint8_t		*p;

	size_t		need;
	unsigned int	len = 0;

	/*
	 *	RFC 4187 Section 5.1
	 *	...
	 *	"On full authentication, both the server and
   	 *	the peer initialize the counter to one."
	 */
	if (keys->reauth.counter == 0) {
		fr_strerror_printf("Re-authentication counter not initialised, must be >= 1");
		return -1;
	}

	need = keys->identity_len + sizeof(uint16_t) + AKA_SIM_NONCE_S_SIZE + sizeof(keys->mk);
	if (need > sizeof(buf)) {
		fr_strerror_printf("Identity too long. PRF input is %zu bytes, input buffer is %zu bytes",
				   need, sizeof(buf));
		return -1;
	}

	/*
	 *	Re-derive k_aut and k_encr from the original Master Key
	 *	These keys stay the same over multiple re-auth attempts.
	 */
	fr_aka_sim_fips186_2prf(fk, keys->mk);

	p = fk;
	memcpy(keys->k_encr, p, 16);				/* 128 bits for encryption */
	p += 16;
	FR_PROTO_HEX_DUMP(keys->k_encr, sizeof(keys->k_encr), "K_encr");

	memcpy(keys->k_aut,  p, EAP_AKA_SIM_AUTH_SIZE);		/* 128 bits for auth */

	keys->k_aut_len = EAP_AKA_SIM_AUTH_SIZE;
	FR_PROTO_HEX_DUMP(keys->k_aut, keys->k_aut_len, "K_aut");

	/*
	 *	Derive a new MSK and EMSK
	 *
	 *	New PRF input is:
	 *	XKEY' = SHA1(Identity|counter|NONCE_S| MK)
	 */

	/*
	 *	Identity
	 */
	p = buf;
	memcpy(p, keys->identity, keys->identity_len);
	p += keys->identity_len;
	FR_PROTO_HEX_DUMP(keys->identity, keys->identity_len, "identity");

	/*
	 *	Counter
	 */
	*p++ = ((keys->reauth.counter & 0xff00) >> 8);
	*p++ = (keys->reauth.counter & 0x00ff);

	/*
	 *	nonce_s
	 */
	memcpy(p, keys->reauth.nonce_s, sizeof(keys->reauth.nonce_s));
	p += sizeof(keys->reauth.nonce_s);

	/*
	 *	Master key
	 */
	memcpy(p, keys->mk, sizeof(keys->mk));
	p += sizeof(keys->mk);

	FR_PROTO_HEX_DUMP(buf, p - buf, "Identity || counter || NONCE_S || MK");

	/*
	 *	Digest re-auth key with SHA1
	 */
	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx) {
		tls_strerror_printf("Failed creating MD ctx");
	error:
		EVP_MD_CTX_destroy(md_ctx);
		return -1;
	}

	if (EVP_DigestInit_ex(md_ctx, EVP_sha1(), NULL) != 1) {
		tls_strerror_printf("Failed initialising digest");
		goto error;
	}

	if (EVP_DigestUpdate(md_ctx, buf, p - buf) != 1) {
		tls_strerror_printf("Failed digesting crypto data");
		goto error;
	}

	if (EVP_DigestFinal_ex(md_ctx, keys->reauth.xkey_prime, &len) != 1) {
		tls_strerror_printf("Failed finalising digest");
		goto error;
	}

	EVP_MD_CTX_destroy(md_ctx);

	FR_PROTO_HEX_DUMP(keys->reauth.xkey_prime, sizeof(keys->reauth.xkey_prime), "xkey'");

	/*
	 *	Expand XKEY' with PRF
	 */
	fr_aka_sim_fips186_2prf(fk, keys->reauth.xkey_prime);

	/*
	 *	Split up the result
	 */
	p = fk;
	memcpy(keys->msk, p, 64);				/* 64 bytes for Master Session Key */
	p += 64;
	FR_PROTO_HEX_DUMP(keys->msk, sizeof(keys->msk), "K_msk");

	memcpy(keys->emsk, p, 64);				/* 64 bytes for Extended Master Session Key */
	FR_PROTO_HEX_DUMP(keys->emsk, sizeof(keys->emsk), "K_emsk");

	return 0;
}

/** Key Derivation Function (Fast-Reauthentication) as described in RFC 5448 (EAP-AKA') section 3.3
 *
 @verbatim
	MK   = PRF'(K_re,"EAP-AKA' re-auth"|Identity|counter|NONCE_S)
	MSK  = MK[0..511]
	EMSK = MK[512..1023]
 @endverbatim
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_aka_sim_crypto_umts_kdf_1_reauth(fr_aka_sim_keys_t *keys)
{
#define KDF_1_S_REAUTH_STATIC	"EAP-AKA' re-auth"
	uint8_t s[(sizeof(KDF_1_S_REAUTH_STATIC) - 1) + AKA_SIM_MAX_STRING_LENGTH + sizeof(uint16_t) + AKA_SIM_NONCE_S_SIZE];
	uint8_t *p = s;

	uint8_t	mk[128];

	if (!fr_cond_assert(((sizeof(KDF_1_S_REAUTH_STATIC) - 1) +
			     keys->identity_len +
			     sizeof(uint16_t) +
			     AKA_SIM_NONCE_S_SIZE) <= sizeof(s))) return -1;

	/*
	 *	"EAP-AKA' re-auth"
	 */
	memcpy(p, KDF_1_S_REAUTH_STATIC, sizeof(KDF_1_S_REAUTH_STATIC) - 1);
	p += sizeof(KDF_1_S_REAUTH_STATIC) - 1;

	/*
	 *	Identity
	 */
	memcpy(p, keys->identity, keys->identity_len);
	p += keys->identity_len;
	FR_PROTO_HEX_DUMP(keys->identity, keys->identity_len, "identity");

	/*
	 *	Counter
	 */
	*p++ = ((keys->reauth.counter & 0xff00) >> 8);
	*p++ = (keys->reauth.counter & 0x00ff);

	/*
	 *	nonce_s
	 */
	memcpy(p, keys->reauth.nonce_s, sizeof(keys->reauth.nonce_s));
	p += sizeof(keys->reauth.nonce_s);

	FR_PROTO_HEX_DUMP(s, p - s, "\"EAP-AKA' re-auth\" || Identity || counter || NONCE_S");

	/*
	 *	Feed into PRF
	 */
	if (aka_prime_prf(mk, sizeof(mk), keys->k_re, sizeof(keys->k_re), s, p - s) < 0) return -1;

	FR_PROTO_HEX_DUMP(mk, sizeof(mk), "mk");

	p = mk;
	memcpy(keys->msk, p, sizeof(keys->msk));			/* 64 bytes for Master Session Key */
	p += sizeof(keys->msk);
	FR_PROTO_HEX_DUMP(keys->msk, sizeof(keys->msk), "K_msk");

	memcpy(keys->emsk, p, sizeof(keys->msk));			/* 64 bytes for Extended Master Session Key */
	FR_PROTO_HEX_DUMP(keys->emsk, sizeof(keys->emsk), "K_emsk");

	return 0;
}

/** Dump the current state of all keys associated with the EAP SIM session
 *
 * @param[in] request	The current request.
 * @param[in] keys	SIM keys associated with the session.
 */
void fr_aka_sim_crypto_keys_log(REQUEST *request, fr_aka_sim_keys_t *keys)
{
	RDEBUG3("KDF inputs");

	RINDENT();
	RHEXDUMP_INLINE3(keys->identity, keys->identity_len,
			"Identity     :");
	switch (keys->vector_type) {
	case AKA_SIM_VECTOR_GSM:
	{
		unsigned int i;

		RHEXDUMP_INLINE3(keys->gsm.nonce_mt, sizeof(keys->gsm.nonce_mt),
				"nonce_mt     :");

		RHEXDUMP_INLINE3(keys->gsm.version_list, keys->gsm.version_list_len,
				"version_list :");

		for (i = 0; i < keys->gsm.num_vectors; i++) {
			RHEXDUMP_INLINE3(keys->gsm.vector[i].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE,
					 "[%i] RAND    :", i);
			RHEXDUMP_INLINE3(keys->gsm.vector[i].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE,
					 "[%i] SRES    :", i);
			RHEXDUMP_INLINE3(keys->gsm.vector[i].kc, AKA_SIM_VECTOR_GSM_KC_SIZE,
					 "[%i] KC      :", i);
		}
	}
		break;

	case AKA_SIM_VECTOR_UMTS:
		RHEXDUMP_INLINE3(keys->umts.vector.autn, AKA_SIM_VECTOR_UMTS_AUTN_SIZE,
				 "AUTN         :");

		RHEXDUMP_INLINE3(keys->umts.vector.ck, AKA_SIM_VECTOR_UMTS_CK_SIZE,
				 "CK           :");

		RHEXDUMP_INLINE3(keys->umts.vector.ik, AKA_SIM_VECTOR_UMTS_IK_SIZE,
				 "IK           :");

		RHEXDUMP_INLINE3(keys->umts.vector.rand, AKA_SIM_VECTOR_UMTS_RAND_SIZE,
				 "RAND         :");

		RHEXDUMP_INLINE3(keys->umts.vector.xres, keys->umts.vector.xres_len,
				"XRES         :");

		RHEXDUMP_INLINE3(keys->ck_prime, AKA_SIM_VECTOR_UMTS_CK_SIZE,
				 "CK'          :");

		RHEXDUMP_INLINE3(keys->ik_prime, AKA_SIM_VECTOR_UMTS_IK_SIZE,
				 "IK'          :");
		break;

	case AKA_SIM_VECTOR_UMTS_REAUTH_KDF_0_REAUTH:
		RHEXDUMP_INLINE3(keys->mk, sizeof(keys->mk),
				"MK           :");
		RDEBUG3(
				"counter      : %u", keys->reauth.counter);
		RHEXDUMP_INLINE3(keys->reauth.nonce_s, sizeof(keys->reauth.nonce_s),
				"nonce_s      :");
		break;

	case AKA_SIM_VECTOR_UMTS_REAUTH_KDF_1_REAUTH:
		RHEXDUMP_INLINE3(keys->k_re, sizeof(keys->k_re),
				"k_re         :");
		RDEBUG3(
				"counter      : %u", keys->reauth.counter);
		RHEXDUMP_INLINE3(keys->reauth.nonce_s, sizeof(keys->reauth.nonce_s),
				"nonce_s      :");
		break;

	case AKA_SIM_VECTOR_NONE:
		break;
	}
	REXDENT();

	RDEBUG3("Intermediary keys");
	RINDENT();
	switch (keys->vector_type) {
	case AKA_SIM_VECTOR_UMTS_REAUTH_KDF_0_REAUTH:
		RHEXDUMP_INLINE3(keys->reauth.xkey_prime, sizeof(keys->reauth.xkey_prime),
				"XKEY'        :");
		break;

	default:
		break;
	}
	REXDENT();

	RDEBUG3("PRF output");
	RINDENT();
	RHEXDUMP_INLINE3(keys->mk, sizeof(keys->mk),
			 "MK           :");
	RHEXDUMP_INLINE3(keys->k_re, sizeof(keys->k_re),
			 "k_re         :");
	RHEXDUMP_INLINE3(keys->k_aut, keys->k_aut_len,
			 "k_aut        :");
	RHEXDUMP_INLINE3(keys->k_encr, sizeof(keys->k_encr),
			 "k_encr       :");
	RHEXDUMP_INLINE3(keys->msk, sizeof(keys->msk),
			 "MSK          :");
	RHEXDUMP_INLINE3(keys->emsk, sizeof(keys->emsk),
			 "EMSK         :");
	REXDENT();
}


#ifdef TESTING_SIM_CRYPTO
/*
 *  cc crypto.c fips186prf.c -g3 -Wall -DHAVE_DLFCN_H -DTESTING_SIM_CRYPTO -DWITH_TLS -I../../../../ -I../../../ -I ../base/ -I /usr/local/opt/openssl/include/ -include ../include/build.h -L /usr/local/opt/openssl/lib/ -l ssl -l crypto -l talloc -L ../../../../../build/lib/local/.libs/ -lfreeradius-server -lfreeradius-tls -lfreeradius-util -o test_sim_crypto && ./test_sim_crypto
 */
#include <stddef.h>
#include <stdbool.h>
#include <freeradius-devel/util/acutest.h>

/*
 *	EAP-SIM (RFC4186) GSM authentication vectors
 */
static fr_aka_sim_keys_t const rfc4186_vector0_in = {
	.identity = (uint8_t const *)"1244070100000001@eapsim.foo",
	.identity_len = sizeof("1244070100000001@eapsim.foo") - 1,

	.gsm = {
		.vector = {
			{
				.rand	= { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
					    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f },
				.sres	= { 0xd1, 0xd2, 0xd3, 0xd4 },
				.kc	= { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 }
			},
			{
				.rand	= { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
					    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f },
				.sres	= { 0xe1, 0xe2, 0xe3, 0xe4 },
				.kc	= { 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 }
			},
			{
				.rand	= { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
					    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f },
				.sres	= { 0xf1, 0xf2, 0xf3, 0xf4 },
				.kc	= { 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 }
			}
		},
		.nonce_mt = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
		.version_list = { 0x00, 0x01 },
		.version_list_len = 2,
		.version_select = { 0x00, 0x01 },
		.num_vectors = 3
	},
	.vector_type = AKA_SIM_VECTOR_GSM
};

static fr_aka_sim_keys_t const rfc4186_vector0_out = {
	.k_encr		= { 0x53, 0x6e, 0x5e, 0xbc, 0x44, 0x65, 0x58, 0x2a,
			    0xa6, 0xa8, 0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20 },
	.k_aut		= { 0x25, 0xaf, 0x19, 0x42, 0xef, 0xcb, 0xf4, 0xbc,
			    0x72, 0xb3, 0x94, 0x34, 0x21, 0xf2, 0xa9, 0x74 },
	.k_aut_len	= 16,
	.msk		= { 0x39, 0xd4, 0x5a, 0xea, 0xf4, 0xe3, 0x06, 0x01,
			    0x98, 0x3e, 0x97, 0x2b, 0x6c, 0xfd, 0x46, 0xd1,
			    0xc3, 0x63, 0x77, 0x33, 0x65, 0x69, 0x0d, 0x09,
			    0xcd, 0x44, 0x97, 0x6b, 0x52, 0x5f, 0x47, 0xd3,
			    0xa6, 0x0a, 0x98, 0x5e, 0x95, 0x5c, 0x53, 0xb0,
			    0x90, 0xb2, 0xe4, 0xb7, 0x37, 0x19, 0x19, 0x6a,
			    0x40, 0x25, 0x42, 0x96, 0x8f, 0xd1, 0x4a, 0x88,
			    0x8f, 0x46, 0xb9, 0xa7, 0x88, 0x6e, 0x44, 0x88 },
	.emsk		= { 0x59, 0x49, 0xea, 0xb0, 0xff, 0xf6, 0x9d, 0x52,
			    0x31, 0x5c, 0x6c, 0x63, 0x4f, 0xd1, 0x4a, 0x7f,
			    0x0d, 0x52, 0x02, 0x3d, 0x56, 0xf7, 0x96, 0x98,
			    0xfa, 0x65, 0x96, 0xab, 0xee, 0xd4, 0xf9, 0x3f,
			    0xbb, 0x48, 0xeb, 0x53, 0x4d, 0x98, 0x54, 0x14,
			    0xce, 0xed, 0x0d, 0x9a, 0x8e, 0xd3, 0x3c, 0x38,
			    0x7c, 0x9d, 0xfd, 0xab, 0x92, 0xff, 0xbd, 0xf2,
			    0x40, 0xfc, 0xec, 0xf6, 0x5a, 0x2c, 0x93, 0xb9 }
};

static void test_eap_sim_kdf_0_gsm(void)
{
	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc4186_vector0_in, sizeof(keys));

	ret = fr_aka_sim_crypto_gsm_kdf_0(&keys);
	TEST_CHECK(ret == 0);

	TEST_CHECK(memcmp(&rfc4186_vector0_out.k_encr, keys.k_encr, sizeof(keys.k_encr)) == 0);
	TEST_CHECK(rfc4186_vector0_out.k_aut_len == keys.k_aut_len);
	TEST_CHECK(memcmp(&rfc4186_vector0_out.k_aut, keys.k_aut, keys.k_aut_len) == 0);
	TEST_CHECK(memcmp(&rfc4186_vector0_out.msk, keys.msk, sizeof(keys.msk)) == 0);
	TEST_CHECK(memcmp(&rfc4186_vector0_out.emsk, keys.emsk, sizeof(keys.emsk)) == 0);
}

/*
 *	UMTS authentication vectors
 *
 *	Test vector from 18 from 3GPP TS 35.208 V9 (the same used by EAP-AKA')
 */
static fr_aka_sim_keys_t const rfc4187_vector0_in = {
	.identity = (uint8_t const *)"0555444333222111",
	.identity_len = sizeof("0555444333222111") - 1,

	.sqn	= 205964772668538,

	.umts = {
		.vector = {
			.rand		= { 0x81, 0xe9, 0x2b, 0x6c, 0x0e, 0xe0, 0xe1, 0x2e,
					    0xbc, 0xeb, 0xa8, 0xd9, 0x2a, 0x99, 0xdf, 0xa5 },
			.autn		= { 0xbb, 0x52, 0xe9, 0x1c, 0x74, 0x7a, 0xc3, 0xab,
					    0x2a, 0x5c, 0x23, 0xd1, 0x5e, 0xe3, 0x51, 0xd5 },
			.ik		= { 0x97, 0x44, 0x87, 0x1a, 0xd3, 0x2b, 0xf9, 0xbb,
					    0xd1, 0xdd, 0x5c, 0xe5, 0x4e, 0x3e, 0x2e, 0x5a },
			.ck		= { 0x53, 0x49, 0xfb, 0xe0, 0x98, 0x64, 0x9f, 0x94,
					    0x8f, 0x5d, 0x2e, 0x97, 0x3a, 0x81, 0xc0, 0x0f },
			.xres		= { 0x28, 0xd7, 0xb0, 0xf2, 0xa2, 0xec, 0x3d, 0xe5 },
			.xres_len	= 8
		}
	},
	.vector_type = AKA_SIM_VECTOR_UMTS
};

static fr_aka_sim_keys_t const rfc4187_vector0_out = {
	.k_encr		= { 0x18, 0xe8, 0xb2, 0x0b, 0xcd, 0xa7, 0x04, 0x86,
			    0xfd, 0x59, 0x59, 0x58, 0x6a, 0x9e, 0x7c, 0x3d },
	.k_aut		= { 0x18, 0xc0, 0x44, 0x07, 0x0e, 0x5e, 0x64, 0x2a,
			    0x26, 0x43, 0x87, 0x6f, 0xf7, 0xa8, 0x38, 0x12 },
	.k_aut_len	= 16,
	.msk		= { 0x35, 0x2f, 0xfa, 0xef, 0x2d, 0xf1, 0x20, 0xcb,
			    0x22, 0x41, 0x0b, 0x9c, 0x0b, 0x70, 0x62, 0x3c,
			    0xb5, 0xa3, 0x5b, 0xc9, 0xfc, 0xd6, 0xbc, 0xa0,
			    0xfc, 0x33, 0x7b, 0x48, 0xb1, 0x76, 0x30, 0x89,
			    0x0a, 0x03, 0x37, 0x5c, 0xfd, 0x1e, 0x64, 0xcb,
			    0xd6, 0xbf, 0x83, 0x04, 0x37, 0x4d, 0xd2, 0xe1,
			    0x39, 0xd6, 0x4e, 0xd1, 0xa6, 0xd6, 0x18, 0xff,
			    0xef, 0xb0, 0x8c, 0x26, 0xa6, 0xbb, 0x35, 0x85 },
	.emsk		= { 0x9e, 0x06, 0x59, 0xae, 0x03, 0x97, 0x7d, 0xcb,
			    0xb1, 0xd6, 0x4d, 0x24, 0x05, 0xe1, 0x10, 0x82,
			    0xa9, 0x1a, 0xdb, 0x9a, 0xc7, 0xf7, 0xbd, 0x0b,
			    0x74, 0xa6, 0x1e, 0xc0, 0xe9, 0x80, 0xb3, 0x6f,
			    0xa0, 0xc3, 0x98, 0x8b, 0x6e, 0x11, 0xef, 0x12,
			    0x52, 0x8e, 0x38, 0x04, 0xb3, 0x2d, 0xf1, 0xbc,
			    0x52, 0xf6, 0x24, 0x9f, 0xa9, 0x6d, 0xc9, 0x4c,
			    0x94, 0xa3, 0xd9, 0xb1, 0x48, 0xf4, 0xf9, 0x96 }
};

static void test_eap_aka_kdf_0_umts(void)
{
	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc4187_vector0_in, sizeof(keys));

	ret = fr_aka_sim_crypto_umts_kdf_0(&keys);
	TEST_CHECK(ret == 0);

	TEST_CHECK(memcmp(&rfc4187_vector0_out.k_encr, keys.k_encr, sizeof(keys.k_encr)) == 0);
	TEST_CHECK(rfc4187_vector0_out.k_aut_len == keys.k_aut_len);

	TEST_CHECK(memcmp(&rfc4187_vector0_out.k_aut, keys.k_aut, keys.k_aut_len) == 0);
	TEST_CHECK(memcmp(&rfc4187_vector0_out.msk, keys.msk, sizeof(keys.msk)) == 0);
	TEST_CHECK(memcmp(&rfc4187_vector0_out.emsk, keys.emsk, sizeof(keys.emsk)) == 0);
}

/*
 *	EAP-SIM (RFC4186) GSM re-authentication vectors
 */
static fr_aka_sim_keys_t const rfc4186_vector0_reauth_in = {
	.identity	= (uint8_t const *)"Y24fNSrz8BP274jOJaF17WfxI8YO7QX00pMXk9XMMVOw7broaNhTczuFq53aEpOkk3L0dm@eapsim.foo",
	.identity_len	= sizeof("Y24fNSrz8BP274jOJaF17WfxI8YO7QX00pMXk9XMMVOw7broaNhTczuFq53aEpOkk3L0dm@eapsim.foo") - 1,

	.reauth		= {
				.counter = 1,
				.nonce_s = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }
			  },
	.mk	= { 0xe5, 0x76, 0xd5, 0xca, 0x33, 0x2e, 0x99, 0x30,
			    0x01, 0x8b, 0xf1, 0xba, 0xee, 0x27, 0x63, 0xc7,
			    0x95, 0xb3, 0xc7, 0x12 },
};

static fr_aka_sim_keys_t const rfc4186_vector0_reauth_out = {
	.k_encr		= { 0x53, 0x6e, 0x5e, 0xbc, 0x44, 0x65, 0x58, 0x2a,
			    0xa6, 0xa8, 0xec, 0x99, 0x86, 0xeb, 0xb6, 0x20 },
	.k_aut		= { 0x25, 0xaf, 0x19, 0x42, 0xef, 0xcb, 0xf4, 0xbc,
			    0x72, 0xb3, 0x94, 0x34, 0x21, 0xf2, 0xa9, 0x74 },
	.k_aut_len	= 16,
	.msk		= { 0x62, 0x63, 0xf6, 0x14, 0x97, 0x38, 0x95, 0xe1,
			    0x33, 0x5f, 0x7e, 0x30, 0xcf, 0xf0, 0x28, 0xee,
			    0x21, 0x76, 0xf5, 0x19, 0x00, 0x2c, 0x9a, 0xbe,
			    0x73, 0x2f, 0xe0, 0xef, 0x00, 0xcf, 0x16, 0x7c,
			    0x75, 0x6d, 0x9e, 0x4c, 0xed, 0x6d, 0x5e, 0xd6,
			    0x40, 0xeb, 0x3f, 0xe3, 0x85, 0x65, 0xca, 0x07,
			    0x6e, 0x7f, 0xb8, 0xa8, 0x17, 0xcf, 0xe8, 0xd9,
			    0xad, 0xbc, 0xe4, 0x41, 0xd4, 0x7c, 0x4f, 0x5e },
	.emsk		= { 0x3d, 0x8f, 0xf7, 0x86, 0x3a, 0x63, 0x0b, 0x2b,
			    0x06, 0xe2, 0xcf, 0x20, 0x96, 0x84, 0xc1, 0x3f,
			    0x6b, 0x82, 0xf9, 0x92, 0xf2, 0xb0, 0x6f, 0x1b,
			    0x54, 0xbf, 0x51, 0xef, 0x23, 0x7f, 0x2a, 0x40,
			    0x1e, 0xf5, 0xe0, 0xd7, 0xe0, 0x98, 0xa3, 0x4c,
			    0x53, 0x3e, 0xae, 0xbf, 0x34, 0x57, 0x88, 0x54,
			    0xb7, 0x72, 0x15, 0x26, 0x20, 0xa7, 0x77, 0xf0,
			    0xe0, 0x34, 0x08, 0x84, 0xa2, 0x94, 0xfb, 0x73 }
};

static void test_eap_sim_kdf_0_reauth(void)
{
	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc4186_vector0_reauth_in, sizeof(keys));

	ret = fr_aka_sim_crypto_kdf_0_reauth(&keys);
	TEST_CHECK(ret == 0);

	TEST_CHECK(memcmp(&rfc4186_vector0_reauth_out.k_encr, keys.k_encr, sizeof(keys.k_encr)) == 0);
	TEST_CHECK(rfc4186_vector0_reauth_out.k_aut_len == keys.k_aut_len);
	TEST_CHECK(memcmp(&rfc4186_vector0_reauth_out.k_aut, keys.k_aut, keys.k_aut_len) == 0);
	TEST_CHECK(memcmp(&rfc4186_vector0_reauth_out.msk, keys.msk, sizeof(keys.msk)) == 0);
	TEST_CHECK(memcmp(&rfc4186_vector0_reauth_out.emsk, keys.emsk, sizeof(keys.emsk)) == 0);
}


/*
 *	EAP-AKA' (RFC5448) UMTS authentication vectors
 */
static fr_aka_sim_keys_t const rfc5448_vector0_in = {
	.identity = (uint8_t const *)"0555444333222111",
	.identity_len = sizeof("0555444333222111") - 1,

	.network = (uint8_t const *)"WLAN",
	.network_len = sizeof("WLAN") - 1,

	.sqn	= 205964772668538,

	.umts = {
		.vector = {
			.rand		= { 0x81, 0xe9, 0x2b, 0x6c, 0x0e, 0xe0, 0xe1, 0x2e,
					    0xbc, 0xeb, 0xa8, 0xd9, 0x2a, 0x99, 0xdf, 0xa5 },
			.autn		= { 0xbb, 0x52, 0xe9, 0x1c, 0x74, 0x7a, 0xc3, 0xab,
					    0x2a, 0x5c, 0x23, 0xd1, 0x5e, 0xe3, 0x51, 0xd5 },
			.ik		= { 0x97, 0x44, 0x87, 0x1a, 0xd3, 0x2b, 0xf9, 0xbb,
					    0xd1, 0xdd, 0x5c, 0xe5, 0x4e, 0x3e, 0x2e, 0x5a },
			.ck		= { 0x53, 0x49, 0xfb, 0xe0, 0x98, 0x64, 0x9f, 0x94,
					    0x8f, 0x5d, 0x2e, 0x97, 0x3a, 0x81, 0xc0, 0x0f },
			.xres		= { 0x28, 0xd7, 0xb0, 0xf2, 0xa2, 0xec, 0x3d, 0xe5 },
			.xres_len	= 8
		}
	},
	.vector_type = AKA_SIM_VECTOR_UMTS
};

static fr_aka_sim_keys_t const rfc5448_vector0_out = {
	.ik_prime	= { 0x00, 0x93, 0x96, 0x2d, 0x0d, 0xd8, 0x4a, 0xa5,
			    0x68, 0x4b, 0x04, 0x5c, 0x9e, 0xdf, 0xfa, 0x04 },
	.ck_prime	= { 0xcc, 0xfc, 0x23, 0x0c, 0xa7, 0x4f, 0xcc, 0x96,
			    0xc0, 0xa5, 0xd6, 0x11, 0x64, 0xf5, 0xa7, 0x6c },

	.k_encr		= { 0x76, 0x6f, 0xa0, 0xa6, 0xc3, 0x17, 0x17, 0x4b,
			    0x81, 0x2d, 0x52, 0xfb, 0xcd, 0x11, 0xa1, 0x79 },
	.k_aut		= { 0x08, 0x42, 0xea, 0x72, 0x2f, 0xf6, 0x83, 0x5b,
			    0xfa, 0x20, 0x32, 0x49, 0x9f, 0xc3, 0xec, 0x23,
			    0xc2, 0xf0, 0xe3, 0x88, 0xb4, 0xf0, 0x75, 0x43,
			    0xff, 0xc6, 0x77, 0xf1, 0x69, 0x6d, 0x71, 0xea },
	.k_aut_len	= 32,
	.k_re		= { 0xcf, 0x83, 0xaa, 0x8b, 0xc7, 0xe0, 0xac, 0xed,
			    0x89, 0x2a, 0xcc, 0x98, 0xe7, 0x6a, 0x9b, 0x20,
			    0x95, 0xb5, 0x58, 0xc7, 0x79, 0x5c, 0x70, 0x94,
			    0x71, 0x5c, 0xb3, 0x39, 0x3a, 0xa7, 0xd1, 0x7a },
	.msk		= { 0x67, 0xc4, 0x2d, 0x9a, 0xa5, 0x6c, 0x1b, 0x79,
			    0xe2, 0x95, 0xe3, 0x45, 0x9f, 0xc3, 0xd1, 0x87,
			    0xd4, 0x2b, 0xe0, 0xbf, 0x81, 0x8d, 0x30, 0x70,
			    0xe3, 0x62, 0xc5, 0xe9, 0x67, 0xa4, 0xd5, 0x44,
			    0xe8, 0xec, 0xfe, 0x19, 0x35, 0x8a, 0xb3, 0x03,
			    0x9a, 0xff, 0x03, 0xb7, 0xc9, 0x30, 0x58, 0x8c,
			    0x05, 0x5b, 0xab, 0xee, 0x58, 0xa0, 0x26, 0x50,
			    0xb0, 0x67, 0xec, 0x4e, 0x93, 0x47, 0xc7, 0x5a },
	.emsk		= { 0xf8, 0x61, 0x70, 0x3c, 0xd7, 0x75, 0x59, 0x0e,
			    0x16, 0xc7, 0x67, 0x9e, 0xa3, 0x87, 0x4a, 0xda,
			    0x86, 0x63, 0x11, 0xde, 0x29, 0x07, 0x64, 0xd7,
			    0x60, 0xcf, 0x76, 0xdf, 0x64, 0x7e, 0xa0, 0x1c,
			    0x31, 0x3f, 0x69, 0x92, 0x4b, 0xdd, 0x76, 0x50,
			    0xca, 0x9b, 0xac, 0x14, 0x1e, 0xa0, 0x75, 0xc4,
			    0xef, 0x9e, 0x80, 0x29, 0xc0, 0xe2, 0x90, 0xcd,
			    0xba, 0xd5, 0x63, 0x8b, 0x63, 0xbc, 0x23, 0xfb }
};

static void test_eap_aka_kdf_1_umts(void)
{
	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc5448_vector0_in, sizeof(keys));

	memcpy(keys.ck_prime, rfc5448_vector0_out.ck_prime, sizeof(keys.ck_prime));
	memcpy(keys.ik_prime, rfc5448_vector0_out.ik_prime, sizeof(keys.ik_prime));

	ret = fr_aka_sim_crypto_umts_kdf_1(&keys);
	TEST_CHECK(ret == 0);

	TEST_CHECK(memcmp(&rfc5448_vector0_out.k_encr, keys.k_encr, sizeof(keys.k_encr)) == 0);
	TEST_CHECK(rfc5448_vector0_out.k_aut_len == keys.k_aut_len);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.k_aut, keys.k_aut, keys.k_aut_len) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.k_re, keys.k_re, sizeof(keys.k_re)) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.msk, keys.msk, sizeof(keys.msk)) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.emsk, keys.emsk, sizeof(keys.emsk)) == 0);
}

static void test_eap_aka_derive_ck_ik(void)
{

	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc5448_vector0_in, sizeof(keys));
	ret = ck_ik_prime_derive(&keys);
	TEST_CHECK(ret == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.ck_prime, keys.ck_prime, sizeof(keys.ck_prime)) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.ik_prime, keys.ik_prime, sizeof(keys.ik_prime)) == 0);
}

/*
 *	EAP-AKA' (RFC5448) UMTS authentication vectors
 */
static fr_aka_sim_keys_t const rfc5448_vector0_reauth_in = {
	.identity = (uint8_t const *)"5555444333222111",
	.identity_len = sizeof("5555444333222111") - 1,

	.network = (uint8_t const *)"WLAN",
	.network_len = sizeof("WLAN") - 1,

	.reauth		= {
				.counter = 1,
				.nonce_s = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
					     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 }
			  },
	.k_encr		= { 0x76, 0x6f, 0xa0, 0xa6, 0xc3, 0x17, 0x17, 0x4b,
			    0x81, 0x2d, 0x52, 0xfb, 0xcd, 0x11, 0xa1, 0x79 },
	.k_aut		= { 0x08, 0x42, 0xea, 0x72, 0x2f, 0xf6, 0x83, 0x5b,
			    0xfa, 0x20, 0x32, 0x49, 0x9f, 0xc3, 0xec, 0x23,
			    0xc2, 0xf0, 0xe3, 0x88, 0xb4, 0xf0, 0x75, 0x43,
			    0xff, 0xc6, 0x77, 0xf1, 0x69, 0x6d, 0x71, 0xea },
	.k_aut_len	= 32,
	.k_re		= { 0xcf, 0x83, 0xaa, 0x8b, 0xc7, 0xe0, 0xac, 0xed,
			    0x89, 0x2a, 0xcc, 0x98, 0xe7, 0x6a, 0x9b, 0x20,
			    0x95, 0xb5, 0x58, 0xc7, 0x79, 0x5c, 0x70, 0x94,
			    0x71, 0x5c, 0xb3, 0x39, 0x3a, 0xa7, 0xd1, 0x7a }
};

/*
 *	Not tested against external source (yet)
 */
static fr_aka_sim_keys_t const rfc5448_vector0_reauth_out = {
	.k_encr		= { 0x76, 0x6f, 0xa0, 0xa6, 0xc3, 0x17, 0x17, 0x4b,
			    0x81, 0x2d, 0x52, 0xfb, 0xcd, 0x11, 0xa1, 0x79 },
	.k_aut		= { 0x08, 0x42, 0xea, 0x72, 0x2f, 0xf6, 0x83, 0x5b,
			    0xfa, 0x20, 0x32, 0x49, 0x9f, 0xc3, 0xec, 0x23,
			    0xc2, 0xf0, 0xe3, 0x88, 0xb4, 0xf0, 0x75, 0x43,
			    0xff, 0xc6, 0x77, 0xf1, 0x69, 0x6d, 0x71, 0xea },
	.k_aut_len	= 32,
	.msk		= { 0x28, 0xf2, 0xb9, 0x3a, 0x8e, 0xdc, 0x4a, 0x01,
			    0xb6, 0x9d, 0x37, 0x8b, 0xa6, 0x8a, 0x77, 0xbb,
			    0x01, 0x6c, 0x0f, 0xeb, 0xb7, 0x60, 0xdb, 0x98,
			    0x57, 0x99, 0x64, 0x99, 0x00, 0x00, 0x6f, 0x97,
			    0xa1, 0x76, 0x5c, 0x65, 0xf5, 0xd5, 0xbf, 0xde,
			    0xe7, 0x61, 0xba, 0x42, 0x92, 0xe4, 0x51, 0xd1,
			    0xa0, 0xc5, 0x7e, 0x76, 0xeb, 0x91, 0x3e, 0xe9,
			    0x95, 0xf5, 0xce, 0x6e, 0xb7, 0x98, 0x91, 0x38 },
	.emsk		= { 0xb9, 0x05, 0xa2, 0xf4, 0x67, 0xe0, 0xeb, 0x9a,
			    0xfb, 0xa4, 0x59, 0xa7, 0xd8, 0xa7, 0xc8, 0x77,
			    0xd5, 0xfa, 0x2e, 0x5e, 0xd3, 0x77, 0xf8, 0xc5,
			    0x2f, 0xa4, 0x86, 0xad, 0xf5, 0x15, 0x5e, 0xb7,
			    0x96, 0xac, 0xa9, 0x3e, 0xa3, 0xa9, 0x95, 0xe8,
			    0xa2, 0x34, 0x36, 0x54, 0x5a, 0xf1, 0x57, 0x22,
			    0xaa, 0x94, 0xb9, 0xfb, 0xd9, 0x06, 0x0c, 0x50,
			    0xa3, 0x56, 0xcc, 0xb4, 0xc7, 0x10, 0x0e, 0x66 }
};

static void test_eap_aka_kdf_1_reauth(void)
{
	fr_aka_sim_keys_t	keys;
	int		ret;

/*
	fr_debug_lvl = 4;
	printf("\n");
*/

	memcpy(&keys, &rfc5448_vector0_reauth_in, sizeof(keys));

	ret = fr_aka_sim_crypto_umts_kdf_1_reauth(&keys);
	TEST_CHECK(ret == 0);

	TEST_CHECK(memcmp(&rfc5448_vector0_reauth_out.k_encr, keys.k_encr, sizeof(keys.k_encr)) == 0);
	TEST_CHECK(rfc5448_vector0_reauth_out.k_aut_len == keys.k_aut_len);
	TEST_CHECK(memcmp(&rfc5448_vector0_reauth_out.k_aut, keys.k_aut, keys.k_aut_len) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_reauth_out.msk, keys.msk, sizeof(keys.msk)) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_reauth_out.emsk, keys.emsk, sizeof(keys.emsk)) == 0);
}


TEST_LIST = {
	/*
	 *	EAP-SIM
	 */
	{ "test_eap_sim_kdf_0_gsm",		test_eap_sim_kdf_0_gsm		},

	/*
	 *	EAP-AKA
	 */
	{ "test_eap_aka_kdf_0_umts",		test_eap_aka_kdf_0_umts		},

	/*
	 *	EAP-SIM/EAP-AKA
	 */
	{ "test_eap_sim_kdf_0_reauth",		test_eap_sim_kdf_0_reauth	},

	/*
	 *	EAP-AKA'
	 */
	{ "test_eap_aka_kdf_1_umts",		test_eap_aka_kdf_1_umts		},
	{ "test_eap_aka_derive_ck_ik",		test_eap_aka_derive_ck_ik	},
	{ "test_eap_aka_kdf_1_reauth",		test_eap_aka_kdf_1_reauth	},


	{ NULL }
};
#endif

