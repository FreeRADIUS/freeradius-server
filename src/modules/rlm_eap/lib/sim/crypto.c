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
 * @file rlm_eap/lib/sim/crypto.c
 * @brief Calculate keys from GSM vectors.
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * @copyright 2003-2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "eap_types.h"
#include "sim_proto.h"
#include <freeradius-devel/sha1.h>
#include <freeradius-devel/eap.sim.h>
#include <openssl/evp.h>

/** Free OpenSSL memory associated with our checkcode ctx
 *
 * @param[in] checkcode to free.
 * @return 0
 */
static int _fr_sim_crypto_free_checkcode(fr_sim_checkcode_t *checkcode)
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
int fr_sim_crypto_init_checkcode(TALLOC_CTX *ctx, fr_sim_checkcode_t **checkcode, EVP_MD const *md)
{
	*checkcode = talloc_zero(ctx, fr_sim_checkcode_t);
	if (!*checkcode) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	(*checkcode)->md_ctx = EVP_MD_CTX_create();
	if (!(*checkcode)->md_ctx) {
		tls_strerror_printf(true, "Failed creating MD ctx");
	error:
		TALLOC_FREE(*checkcode);
		return -1;
	}
	if (EVP_DigestInit_ex((*checkcode)->md_ctx, md, NULL) != 1) {
		tls_strerror_printf(true, "Failed intialising MD ctx");
		goto error;
	}

	talloc_set_destructor(*checkcode, _fr_sim_crypto_free_checkcode);

	return 0;
}

/** Digest a packet, updating the checkcode
 *
 * Call #fr_sim_crypto_finalise_checkcode to obtain the final checkcode value.
 *
 * @param[in,out] checkcode	if *checkcode is NULL, a new checkcode structure
 *				will be allocated and the message digest context
 *				will be initialised before the provided
 *				#eap_packet is fed into the digest.
 * @param[in] eap_packet	to digest.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_crypto_update_checkcode(fr_sim_checkcode_t *checkcode, eap_packet_t *eap_packet)
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
		tls_strerror_printf(true, "Failed digesting EAP header");
		return -1;
	}

	/*
	 *	Digest the packet
	 */
	if (EVP_DigestUpdate(checkcode->md_ctx, eap_packet->type.data, eap_packet->type.length) != 1) {
		tls_strerror_printf(true, "Failed digesting packet data");
		return -1;
	}

	return 0;
}

/** Write out the final checkcode value
 *
 * @param[out] out		Where to write the checkcode value.  Must be at least 20
 *				bytes if MD was SHA1, or 32 bytes if MD was SHA256.
 * @param[in] outlen		Length of the output buffer.
 * @param[in,out] checkcode	structure to get final digest from and to tree.
 * @return
 *	- <= 0 on failure.
 *	- > 0 the number of bytes written to out.
 */
ssize_t fr_sim_crypto_finalise_checkcode(uint8_t *out, fr_sim_checkcode_t **checkcode)
{
	unsigned int len;

	if (EVP_DigestFinal_ex((*checkcode)->md_ctx, out, &len) != 1) {
		tls_strerror_printf(true, "Failed finalising checkcode digest");
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
static int fr_sim_find_mac(uint8_t const **out, uint8_t *data, size_t data_len)
{
	uint8_t *p = data, *end = p + data_len;
	size_t len;

	*out = NULL;

	p += 3;	/* Skip header */
	while ((p + 2) < end) {
		if (p[0] == FR_SIM_MAC) {
			len = p[1] << 2;
			if ((p + len) > end) {
				fr_strerror_printf("Malformed AT_MAC: Length (%zu) exceeds buffer (%zu)", len, end - p);
				return -1;
			}

			if (len != SIM_MAC_SIZE) {
				fr_strerror_printf("Malformed AT_MAC: Length (%zu) incorrect (%u)",
						   len, SIM_MAC_SIZE);
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
ssize_t fr_sim_crypto_sign_packet(uint8_t out[16], eap_packet_t *eap_packet, bool zero_mac,
				  EVP_MD const *md, uint8_t const *key, size_t const key_len,
				  uint8_t const *hmac_extra, size_t const hmac_extra_len)
{
	EVP_MD_CTX		*md_ctx = NULL;
	EVP_PKEY		*pkey;

	uint8_t			digest[SHA1_DIGEST_LENGTH];
	size_t			digest_len = 0;
	uint8_t	const		*mac;
	uint8_t			*p = eap_packet->type.data, *end = p + eap_packet->type.length;

	eap_packet_raw_t	eap_hdr;
	uint16_t		packet_len;

	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, key_len);
	if (!pkey) {
		tls_strerror_printf(true, "Failed creating HMAC signing key");
	error:
		if (pkey) EVP_PKEY_free(pkey);
		if (md_ctx) EVP_MD_CTX_destroy(md_ctx);
		return -1;
	}

	md_ctx = EVP_MD_CTX_create();
	if (!md_ctx) {
		tls_strerror_printf(true, "Failed creating HMAC ctx");
		goto error;
	}

	if (EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey) != 1) {
		tls_strerror_printf(true, "Failed initialising digest");
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

	FR_PROTO_HEX_DUMP("hmac input eap_hdr", (uint8_t *)&eap_hdr, sizeof(eap_hdr));
	if (EVP_DigestSignUpdate(md_ctx, &eap_hdr, sizeof(eap_hdr)) != 1) {
		tls_strerror_printf(true, "Failed digesting EAP data");
		goto error;
	}

	/*
	 *	Digest the packet up to the AT_MAC, value, then
	 *	digest 16 bytes of zero.
	 */
	if (zero_mac) {
		switch (fr_sim_find_mac(&mac, p, end - p)) {
		case 0:
		{
			uint8_t zero[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			/*
			 *	Digest everything up to the hash
			 *	part of the AT_MAC, including
			 *	AT_MAC header and reserved bytes.
			 */
			if (EVP_DigestSignUpdate(md_ctx, p, mac - p) != 1) {
				tls_strerror_printf(true, "Failed digesting packet data (before MAC)");
				goto error;
			}
			p += mac - p;

			/*
			 *	Feed in 16 bytes of zeroes to
			 *	simulated the zeroed out Mac.
			 */
			if (EVP_DigestSignUpdate(md_ctx, zero, sizeof(zero)) != 1) {
				tls_strerror_printf(true, "Failed digesting zeroed MAC");
				goto error;
			}
			p += sizeof(zero);
		}
			break;

		case 1:
			return 0;

		case -1:
			rad_assert(0);	/* Should have been checked by encoder or decoder */
			goto error;
		}
	}

	/*
	 *	Digest the rest of the packet.
	 */
	if (EVP_DigestSignUpdate(md_ctx, p, end - p) != 1) {
		tls_strerror_printf(true, "Failed digesting packet data");
		goto error;
	}

	/*
	 *	Digest any HMAC concatenated data
	 *
	 *	Some subtypes require the HMAC to be calculated over
	 *	a concatenation of packet data, and something extra...
	 */
	if (hmac_extra) {
		FR_PROTO_HEX_DUMP("hmac input hmac_extra", hmac_extra, hmac_extra_len);
		if (EVP_DigestSignUpdate(md_ctx, hmac_extra, hmac_extra_len) != 1) {
			tls_strerror_printf(true, "Failed digesting HMAC extra data");
			goto error;
		}
	}

	if (EVP_DigestSignFinal(md_ctx, digest, &digest_len) != 1) {
		tls_strerror_printf(true, "Failed finalising digest");
		goto error;
	}

	if (!fr_cond_assert(digest_len == sizeof(digest))) goto error;

	FR_PROTO_HEX_DUMP("hmac output", digest, digest_len);

	/*
	 *	Truncate by four bytes.
	 */
	memcpy(out, digest, 16);

	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(md_ctx);

	return 16;	/* AT_MAC (1), LEN (1), RESERVED (2) */
}


/** RFC4186 Key Derivation Function
 *
 * @note expects keys to contain a SIM_VECTOR_GSM.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_crypto_kdf_0_gsm(fr_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[384];
	uint8_t		*p;
	uint8_t		blen;
	size_t		need;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_GSM)) return -1;

	need = keys->identity_len + (SIM_VECTOR_GSM_KC_SIZE * 3) + sizeof(keys->gsm.nonce_mt) +
	       keys->gsm.version_list_len + sizeof(keys->gsm.version_select);
	if (need > sizeof(buf)) {
		fr_strerror_printf("Identity too long. PRF input is %zu bytes, input buffer is %zu bytes",
				   need, sizeof(buf));
		return -1;
	}

	p = buf;
	memcpy(p, keys->identity, keys->identity_len);
	p = p + keys->identity_len;

	memcpy(p, keys->gsm.vector[0].kc, SIM_VECTOR_GSM_KC_SIZE);
	p = p+SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.vector[1].kc, SIM_VECTOR_GSM_KC_SIZE);
	p = p + SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.vector[2].kc, SIM_VECTOR_GSM_KC_SIZE);
	p = p + SIM_VECTOR_GSM_KC_SIZE;

	memcpy(p, keys->gsm.nonce_mt, sizeof(keys->gsm.nonce_mt));
	p = p + sizeof(keys->gsm.nonce_mt);

	memcpy(p, keys->gsm.version_list, keys->gsm.version_list_len);
	p = p + keys->gsm.version_list_len;

	memcpy(p, keys->gsm.version_select, sizeof(keys->gsm.version_select));
	p = p + sizeof(keys->gsm.version_select);

	blen = p - buf;

	/* do the master key first */
	fr_sha1_init(&context);
	fr_sha1_update(&context, buf, blen);
	fr_sha1_final(keys->master_key, &context);

	/*
	 * now use the PRF to expand it, generated k_aut, k_encr,
	 * MSK and EMSK.
	 */
	fr_sim_fips186_2prf(fk, keys->master_key);

	/* split up the result */
	p = fk;
	memcpy(keys->k_encr, p, 16);				/* 128 bits for encryption */
	p += 16;

	memcpy(keys->k_aut,  p, EAP_SIM_AUTH_SIZE);		/* 128 bits for auth */
	p += EAP_SIM_AUTH_SIZE;
	keys->k_aut_len = EAP_SIM_AUTH_SIZE;

	memcpy(keys->msk,    p, 64);				/* 64 bytes for Master Session Key */
	p += 64;

	memcpy(keys->emsk,   p, 64);				/* 64 bytes for Extended Master Session Key */

	return 0;
}

/** RFC4187 Key derivation function
 *
 * @note expects keys to contain a SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_crypto_kdf_0_umts(fr_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[384];
	uint8_t		*p;
	uint8_t		blen;
	size_t		need;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_UMTS)) return - 1;

	need = keys->identity_len + sizeof(keys->umts.vector.ik) + sizeof(keys->umts.vector.ck);
	if (need > sizeof(buf)) {
		fr_strerror_printf("Identity too long. PRF input is %zu bytes, input buffer is %zu bytes",
				   need, sizeof(buf));
		return -1;
	}

	p = buf;
	memcpy(p, keys->identity, keys->identity_len);
	p = p + keys->identity_len;

	memcpy(p, keys->umts.vector.ik, sizeof(keys->umts.vector.ik));
	p = p + sizeof(keys->umts.vector.ik);

	memcpy(p, keys->umts.vector.ck, sizeof(keys->umts.vector.ck));
	p = p + sizeof(keys->umts.vector.ck);

	blen = p - buf;

	/* do the master key first */
	fr_sha1_init(&context);
	fr_sha1_update(&context, buf, blen);
	fr_sha1_final(keys->master_key, &context);

	/*
   	 * now use the PRF to expand it, generated k_aut, k_encr,
	 * MSK and EMSK.
	 */
	fr_sim_fips186_2prf(fk, keys->master_key);

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

/** EAP-AKA Prime CK Prime IK Prime derivation function
 *
 * @note expects keys to contain a SIM_VECTOR_UMTS.
 *
 *	CK' || IK' = HMAC-SHA-256(Key, S)
 *	S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
 *	Key = CK || IK
 *	FC = 0x20
 *	P0 = access network identity (3GPP TS 24.302)
 *	L0 = length of acceess network identity (2 octets, big endian)
 *	P1 = SQN xor AK (if AK is not used, AK is treaded as 000..0
 *	L1 = 0x00 0x06
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_crypto_derive_ck_ik_prime(fr_sim_keys_t *keys)
{
	uint8_t		digest[sizeof(keys->ik_prime) + sizeof(keys->ck_prime)];
	unsigned int	len = sizeof(digest);

	uint8_t		k[sizeof(keys->umts.vector.ik) + sizeof(keys->umts.vector.ck)];

	uint8_t		s[384];
	uint8_t		*p = s;

	uint64_t	sqn_be = htonll(keys->sqn);
	uint16_t	l0, l1;
	size_t		s_len;
	HMAC_CTX	*hmac;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_UMTS)) return -1;

	s_len = sizeof(uint8_t) + keys->network_len + sizeof(l0) + SIM_SQN_AK_LEN + sizeof(l1);
	if (s_len > sizeof(s)) {
		fr_strerror_printf("Network too long. PRF input is %zu bytes, input buffer is %zu bytes",
				   s_len, sizeof(s));
		return -1;
	}

	/*
	 *	FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
	 */
	*p++ = 0x20;
	memcpy(p, keys->network, keys->network_len);
	p += keys->network_len;

	l0 = htons((uint16_t)keys->network_len);
	memcpy(p, &l0, sizeof(l0));
	p += sizeof(l0);

	memcpy(p, ((uint8_t *)&sqn_be) + 2, SIM_SQN_AK_LEN);
	p += SIM_SQN_AK_LEN;

	l1 = htons(SIM_SQN_AK_LEN);
	memcpy(p, &l1, sizeof(l1));

	/*
	 *	CK || IK
	 */
	p = k;
	memcpy(p, keys->umts.vector.ck, sizeof(keys->umts.vector.ck));
	p += sizeof(keys->umts.vector.ck);
	memcpy(p, keys->umts.vector.ik, sizeof(keys->umts.vector.ik));

	MEM(hmac = HMAC_CTX_new());
	if (HMAC_Init_ex(hmac, k, sizeof(k), EVP_sha256(), NULL) != 1) {
	error:
		tls_strerror_printf(true, "HMAC failure");
		HMAC_CTX_free(hmac);
		return -1;
	}
	if (HMAC_Update(hmac, s, s_len) != 1) goto error;
	if (HMAC_Final(hmac, digest, &len) != 1) goto error;

	memcpy(keys->ck_prime, digest, sizeof(keys->ck_prime));
	memcpy(keys->ik_prime, digest + sizeof(keys->ck_prime), sizeof(keys->ik_prime));

	HMAC_CTX_free(hmac);

	return 0;
}

static int fr_sim_crypto_aka_prime_prf(uint8_t *out, size_t outlen,
				       uint8_t const *key, size_t key_len, uint8_t const *in, size_t in_len)
{
	uint8_t		*p = out, *end = p + outlen;
	uint8_t		c = 0;
	uint8_t		digest[SHA256_DIGEST_LENGTH];
	HMAC_CTX	*hmac;

	MEM(hmac = HMAC_CTX_new());
	if (HMAC_Init_ex(hmac, key, key_len, EVP_sha256(), NULL) != 1) {
	error:
		tls_strerror_printf(true, "HMAC failure");
		HMAC_CTX_free(hmac);
		return -1;
	}

	while (p < end) {
		unsigned int len = sizeof(digest);
		size_t copy;

		c++;

		if (HMAC_Init_ex(hmac, NULL, 0, EVP_sha256(), NULL) != 1) goto error;
		if ((p != out) && HMAC_Update(hmac, digest, sizeof(digest)) != 1) goto error;	/* Ingest last round */
		if (HMAC_Update(hmac, in, in_len) != 1) goto error;				/* Ingest s */
		if (HMAC_Update(hmac, &c, sizeof(c)) != 1) goto error;				/* Ingest round number */
		if (HMAC_Final(hmac, digest, &len) != 1) goto error;				/* Output T(i) */

		copy = p - end;
		if (copy > SHA256_DIGEST_LENGTH) copy = SHA256_DIGEST_LENGTH;

		memcpy(p, digest, copy);
		p += copy;
	}
	HMAC_CTX_free(hmac);

	return 0;
}

/** EAP-AKA Prime Key derivation function
 *
 * @note expects keys to contain a SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_sim_crypto_kdf_1_umts(fr_sim_keys_t *keys)
{
	uint8_t k[sizeof(keys->ck_prime) + sizeof(keys->ik_prime)];
	uint8_t s[384];
	uint8_t *p = s;

	uint8_t	mk[1664];
	size_t	s_len;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_UMTS)) return -1;

#define KDF_1_S_STATIC	"EAP-AKA'"

	/*
	 *	build s, a concatenation of EAP-AKA' and Identity
	 */
	s_len = (sizeof(KDF_1_S_STATIC) - 1) + keys->identity_len;
	if (s_len > sizeof(s)) {
		fr_strerror_printf("Identity too long. PRF input is %zu bytes, input buffer is %zu bytes",
				   s_len, sizeof(s));
		return -1;
	}

	memcpy(p, KDF_1_S_STATIC, sizeof(KDF_1_S_STATIC) - 1);
	p += sizeof(KDF_1_S_STATIC) - 1;

	memcpy(p, keys->identity, keys->identity_len);

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
	if (fr_sim_crypto_aka_prime_prf(mk, sizeof(mk), k, sizeof(k), s, s_len) < 0) return -1;

	/*
	 *	Split the PRF output into separate keys
	 */
	p = mk;
	memcpy(keys->k_encr, p, 16);    			/* 128 bits for encryption    */
	p += 16;

	memcpy(keys->k_aut,  p, EAP_AKA_PRIME_AUTH_SIZE);	/* 256 bits for auth */
	p += EAP_AKA_PRIME_AUTH_SIZE;
	keys->k_aut_len = EAP_AKA_PRIME_AUTH_SIZE;

	memcpy(keys->k_re, p, 32);				/* 256 bits for reauthentication key */
	p += 32;

	memcpy(keys->msk, p, 64);				/* 64 bytes for Master Session Key */
	p += 64;

	memcpy(keys->emsk, p, 64);				/* 64 bytes for Extended Master Session Key */

	return 0;
}

/** Dump the current state of all keys associated with the EAP SIM session
 *
 * @param[in] request	The current request.
 * @param[in] keys	SIM keys associated with the session.
 */
void fr_sim_crypto_keys_log(REQUEST *request, fr_sim_keys_t *keys)
{
	RDEBUG3("Cryptographic inputs");

	RINDENT();
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->identity, keys->identity_len,
			"Identity     :");
	switch (keys->vector_type) {
	case SIM_VECTOR_GSM:
	{
		unsigned int i;

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->gsm.nonce_mt, sizeof(keys->gsm.nonce_mt),
				"nonce_mt     :");

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->gsm.version_list, keys->gsm.version_list_len,
				"version_list :");

		for (i = 0; i < keys->gsm.num_vectors; i++) {
			RHEXDUMP_INLINE(L_DBG_LVL_3, keys->gsm.vector[i].rand, SIM_VECTOR_GSM_RAND_SIZE,
					"[%i] RAND    :", i);
			RHEXDUMP_INLINE(L_DBG_LVL_3, keys->gsm.vector[i].sres, SIM_VECTOR_GSM_SRES_SIZE,
					"[%i] SRES    :", i);
			RHEXDUMP_INLINE(L_DBG_LVL_3, keys->gsm.vector[i].kc, SIM_VECTOR_GSM_KC_SIZE,
					"[%i] KC      :", i);
		}
	}
		break;

	case SIM_VECTOR_UMTS:
		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->umts.vector.autn, SIM_VECTOR_UMTS_AUTN_SIZE,
				"AUTN         :");

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->umts.vector.ck, SIM_VECTOR_UMTS_CK_SIZE,
				"CK           :");

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->umts.vector.ik, SIM_VECTOR_UMTS_IK_SIZE,
				"IK           :");

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->umts.vector.rand, SIM_VECTOR_UMTS_RAND_SIZE,
				"RAND         :");

		RHEXDUMP_INLINE(L_DBG_LVL_3, keys->umts.vector.xres, keys->umts.vector.xres_len,
				"XRES         :");
		break;

	case SIM_VECTOR_NONE:
		break;
	}
	REXDENT();

	RDEBUG3("Derived keys");
	RINDENT();
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->master_key, sizeof(keys->master_key),
			"mk           :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->k_aut, keys->k_aut_len,
			"k_aut        :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->k_encr, sizeof(keys->k_encr),
			"k_encr       :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->k_re, sizeof(keys->k_re),
			"k_re         :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->msk, sizeof(keys->msk),
			"msk          :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->emsk, sizeof(keys->emsk),
			"emsk         :");
	REXDENT();
}


#ifdef TESTING_SIM_CRYPTO
/*
 *  cc crypto.c fips186prf.c -g3 -Wall -DHAVE_DLFCN_H -DTESTING_SIM_CRYPTO -DWITH_TLS -I../../../../ -I../../../ -I ../base/ -I /usr/local/opt/openssl/include/ -include ../include/build.h -L /usr/local/opt/openssl/lib/ -l ssl -l crypto -l talloc -L ../../../../../build/lib/local/.libs/ -lfreeradius-server -lfreeradius-tls -lfreeradius-util -o test_sim_crypto && ./test_sim_crypto
 */
#include <stddef.h>
#include <stdbool.h>
#include <freeradius-devel/cutest.h>

main_config_t main_config;

static fr_sim_keys_t const rfc5448_vector0_in = {
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
	.vector_type = SIM_VECTOR_UMTS
};

static fr_sim_keys_t const rfc5448_vector0_out = {
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
	.k_re	= { 0xcf, 0x83, 0xaa, 0x8b, 0xc7, 0xe0, 0xac, 0xed,
		    0x89, 0x2a, 0xcc, 0x98, 0xe7, 0x6a, 0x9b, 0x20,
		    0x95, 0xb5, 0x58, 0xc7, 0x79, 0x5c, 0x70, 0x94,
		    0x71, 0x5c, 0xb3, 0x39, 0x3a, 0xa7, 0xd1, 0x7a },
	.msk	= { 0x67, 0xc4, 0x2d, 0x9a, 0xa5, 0x6c, 0x1b, 0x79,
		    0xe2, 0x95, 0xe3, 0x45, 0x9f, 0xc3, 0xd1, 0x87,
		    0xd4, 0x2b, 0xe0, 0xbf, 0x81, 0x8d, 0x30, 0x70,
		    0xe3, 0x62, 0xc5, 0xe9, 0x67, 0xa4, 0xd5, 0x44,
		    0xe8, 0xec, 0xfe, 0x19, 0x35, 0x8a, 0xb3, 0x03,
		    0x9a, 0xff, 0x03, 0xb7, 0xc9, 0x30, 0x58, 0x8c,
		    0x05, 0x5b, 0xab, 0xee, 0x58, 0xa0, 0x26, 0x50,
		    0xb0, 0x67, 0xec, 0x4e, 0x93, 0x47, 0xc7, 0x5a },
	.emsk	= { 0xf8, 0x61, 0x70, 0x3c, 0xd7, 0x75, 0x59, 0x0e,
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
	fr_sim_keys_t	keys;
	int		ret;

/*
	fr_log_fp = stdout;
	fr_debug_lvl = 4;
*/

	memcpy(&keys, &rfc5448_vector0_in, sizeof(keys));

	memcpy(keys.ck_prime, rfc5448_vector0_out.ck_prime, sizeof(keys.ck_prime));
	memcpy(keys.ik_prime, rfc5448_vector0_out.ik_prime, sizeof(keys.ik_prime));

	ret = fr_sim_crypto_kdf_1_umts(&keys);
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

	fr_sim_keys_t	keys;
	int		ret;
	fr_log_fp = stdout;


	fr_log_fp = stdout;
	fr_debug_lvl = 4;

	memcpy(&keys, &rfc5448_vector0_in, sizeof(keys));
	ret = fr_sim_crypto_derive_ck_ik_prime(&keys);
	TEST_CHECK(ret == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.ck_prime, keys.ck_prime, sizeof(keys.ck_prime)) == 0);
	TEST_CHECK(memcmp(&rfc5448_vector0_out.ik_prime, keys.ik_prime, sizeof(keys.ik_prime)) == 0);
}

TEST_LIST = {
	/*
	 *	Initialisation
	 */
	{ "test_eap_aka_kdf_1_umts",	test_eap_aka_kdf_1_umts },
/*	{ "test_eap_aka_derive_ck_ik",	test_eap_aka_derive_ck_ik },  Fails for unknown reason	*/

	{ NULL }
};
#endif

