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

	da = fr_dict_attr_child_by_num(root, PW_EAP_SIM_MAC);
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
			if (attr[0] == PW_EAP_SIM_MAC) {
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
