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

/*
 * calculate the MAC for the EAP message, given the key.
 * The "extra" will be appended to the EAP message and included in the
 * HMAC.
 *
 */
int fr_sim_crypto_mac_verify(TALLOC_CTX *ctx, fr_dict_attr_t const *root,
			     VALUE_PAIR *rvps,
			     uint8_t key[EAP_SIM_AUTH_SIZE],
			     uint8_t *extra, int extra_len, uint8_t calc_mac[20])
{
	int			ret;
	eap_packet_raw_t	*e;
	uint8_t			*buffer;
	int			elen, len;
	VALUE_PAIR		*mac;
	fr_dict_attr_t const	*da;

	da = fr_dict_attr_child_by_num(root, FR_EAP_SIM_MAC);
	if (!da) {
		fr_strerror_printf("Missing definition for EAP-SIM-MAC");
		return -1;
	}

	mac = fr_pair_find_by_da(rvps, da, TAG_ANY);
	if (!mac || mac->vp_length != 18) {
		/* can't check a packet with no AT_MAC attribute */
		return 0;
	}

	/* get original copy of EAP message, note that it was sanitized
	 * to have a valid length, which we depend upon.
	 */
	e = eap_vp2packet(ctx, rvps);
	if (!e) return 0;

	/* make copy big enough for everything */
	elen = (e->length[0] * 256) + e->length[1];
	len = elen + extra_len;

	buffer = talloc_array(ctx, uint8_t, len);
	if (!buffer) {
		talloc_free(e);
		return 0;
	}

	memcpy(buffer, e, elen);
	memcpy(buffer + elen, extra, extra_len);

	/*
	 * now look for the AT_MAC attribute in the copy of the buffer
	 * and make sure that the checksum is zero.
	 *
	 */
	{
		uint8_t *attr;

		/* first attribute is 8 bytes into the EAP packet.
		 * 4 bytes for EAP, 1 for type, 1 for subtype, 2 reserved.
		 */
		attr = buffer + 8;
		while (attr < (buffer + elen)) {
			if (attr[0] == FR_EAP_SIM_MAC) {
				/* zero the data portion, after making sure
				 * the size is >=5. Maybe future versions.
				 * will use more bytes, so be liberal.
				 */
				if (attr[1] < 5) {
					ret = 0;
					goto done;
				}
				memset(&attr[4], 0, (attr[1]-1)*4);
			}
			/* advance the pointer */
			attr += attr[1]*4;
		}
	}

	/* now, HMAC-SHA1 it with the key. */
	fr_hmac_sha1(calc_mac, buffer, len, key, 16);

	ret = memcmp(&mac->vp_strvalue[2], calc_mac, 16) == 0 ? 1 : 0;
 done:
	talloc_free(e);
	talloc_free(buffer);
	return(ret);
}


/** Append AT_MAC to the end a packet.
 *
 * Run SHA1 digest over a fake EAP header, the entire SIM packet and any extra HMAC data,
 * writing out the complete AT_HMAC and digest to out.
 *
 * @note out must point to (buff) end - 20.  It's easier to write AT_MAC last.
 *
 * @param[out] out		Where to write the digest.
 * @param[in] eap_packet	to extract header values from.
 * @param[in] key		to use to sign the packet.
 * @param[in] key_len		Length of the key.
 * @param[in] hmac_extra	data to concatenate with the packet when calculating the HMAC
 *				(may be NULL).
 * @param[in] hmac_extra_len	Length of hmac_extra.
 * @return
 *	- <= 0 on failure.
 *	- > 0 the number of bytes written to out.
 */
ssize_t fr_sim_crypto_sign_packet(uint8_t out[16], eap_packet_t *eap_packet,
				  uint8_t const *key, size_t const key_len,
				  uint8_t const *hmac_extra, size_t const hmac_extra_len)
{
	EVP_MD_CTX		*md_ctx = NULL;
	EVP_MD const		*md = EVP_get_digestbyname("SHA1");
	EVP_PKEY		*pkey;

	uint8_t			digest[SHA1_DIGEST_LENGTH];
	size_t			digest_len = 0;

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
		tls_strerror_printf(true, "Failed digesting EAP header");
		goto error;
	}

	/*
	 *	Digest most of the packet, except the bit at
	 *	the end we're leaving for the HMAC.
	 */
	FR_PROTO_HEX_DUMP("hmac input sim_body", eap_packet->type.data, eap_packet->type.length);
	if (EVP_DigestSignUpdate(md_ctx, eap_packet->type.data, eap_packet->type.length) != 1) {
		tls_strerror_printf(true, "Failed digesting body");
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
 */
void fr_sim_crypto_kdf_0_gsm(fr_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[256];
	uint8_t		*p;
	uint8_t		blen;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_GSM)) return;

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
	memcpy(keys->k_encr, fk + 00, 16);    /* 128 bits for encryption    */
	memcpy(keys->k_aut,  fk + 16, EAP_SIM_AUTH_SIZE); /* 128 bits for auth */
	memcpy(keys->msk,    fk + 32, 64);  /* 64 bytes for Master Session Key */
	memcpy(keys->emsk,   fk + 96, 64);  /* 64- extended Master Session Key */
}

/** RFC4187 Key derivation function
 *
 * @note expects keys to contain a SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 */
void fr_sim_crypto_kdf_0_umts(fr_sim_keys_t *keys)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[256];
	uint8_t		*p;
	uint8_t		blen;

	if (!fr_cond_assert(keys->vector_type == SIM_VECTOR_UMTS)) return;

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
	memcpy(keys->k_encr, fk + 00, 16);    /* 128 bits for encryption    */
	memcpy(keys->k_aut,  fk + 16, EAP_SIM_AUTH_SIZE); /*128 bits for auth */
	memcpy(keys->msk,    fk + 32, 64);  /* 64 bytes for Master Session Key */
	memcpy(keys->emsk,   fk + 96, 64);  /* 64 - extended Master Session Key */
}

#if 0
/** RFC5448 Key derivation function
 *
 * @note expects keys to contain a SIM_VECTOR_UMTS.
 *
 * @param[in,out] keys		Contains the authentication vectors and the buffers
 *				to store the result of the derivation.
 */
void fr_sim_crypto_kdf_1_umts(UNUSED fr_sim_keys_t *keys)
{
	return;
}
#endif

/** Dump the current state of all keys associated with the EAP SIM session
 *
 * @param[in] request	The current request.
 * @param[in] keys	SIM keys associated with the session.
 */
void fr_sim_crypto_keys_log(REQUEST *request, fr_sim_keys_t *keys)
{
	RDEBUG3("Key data from AuC/static vectors");

	RINDENT();
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->identity, keys->identity_len,
			"identity     :");
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
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->k_aut, sizeof(keys->k_aut),
			"k_aut        :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->k_encr, sizeof(keys->k_encr),
			"k_encr       :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->msk, sizeof(keys->msk),
			"msk          :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, keys->emsk, sizeof(keys->emsk),
			"emsk         :");
	REXDENT();
}
