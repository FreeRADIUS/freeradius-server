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

/*
 * calculate the MAC for the EAP message, given the key.
 * The "extra" will be appended to the EAP message and included in the
 * HMAC.
 *
 */
int fr_sim_crypto_mac_verify(TALLOC_CTX *ctx, VALUE_PAIR *rvps, uint8_t key[EAP_SIM_AUTH_SIZE],
			     uint8_t *extra, int extra_len, uint8_t calc_mac[20])
{
	int ret;
	eap_packet_raw_t *e;
	uint8_t *buffer;
	int elen,len;
	VALUE_PAIR *mac;

	mac = fr_pair_find_by_num(rvps, 0, PW_EAP_SIM_MAC, TAG_ANY);

	if(!mac || mac->vp_length != 18) {
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
			if (attr[0] == (PW_EAP_SIM_MAC - PW_EAP_SIM_BASE)) {
				/* zero the data portion, after making sure
				 * the size is >=5. Maybe future versions.
				 * will use more bytes, so be liberal.
				 */
				if(attr[1] < 5) {
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

/** Use the fips186_2prf to derive the various EAP SIM keys
 *
 */
void fr_sim_crypto_keys_derive(fr_sim_keys_t *ek)
{
	fr_sha1_ctx	context;
	uint8_t		fk[160];
	uint8_t		buf[256];
	uint8_t		*p;
	uint8_t		blen;

	p = buf;
	memcpy(p, ek->identity, ek->identity_len);
	p = p + ek->identity_len;

	memcpy(p, ek->vector[0].kc, EAP_SIM_KC_SIZE);
	p = p+EAP_SIM_KC_SIZE;

	memcpy(p, ek->vector[1].kc, EAP_SIM_KC_SIZE);
	p = p + EAP_SIM_KC_SIZE;

	memcpy(p, ek->vector[2].kc, EAP_SIM_KC_SIZE);
	p = p + EAP_SIM_KC_SIZE;

	memcpy(p, ek->nonce_mt, sizeof(ek->nonce_mt));
	p = p + sizeof(ek->nonce_mt);

	memcpy(p, ek->version_list, ek->version_list_len);
	p = p+ek->version_list_len;

	memcpy(p, ek->version_select, sizeof(ek->version_select));
	p = p + sizeof(ek->version_select);

	/* *p++ = ek->version_select[1]; */

	blen = p - buf;

	/* do the master key first */
	fr_sha1_init(&context);
	fr_sha1_update(&context, buf, blen);
	fr_sha1_final(ek->master_key, &context);

	/*
	 * now use the PRF to expand it, generated k_aut, k_encr,
	 * MSK and EMSK.
	 */
	fr_sim_fips186_2prf(fk, ek->master_key);

	/* split up the result */
	memcpy(ek->k_encr, fk +  0, 16);    /* 128 bits for encryption    */
	memcpy(ek->k_aut,  fk + 16, EAP_SIM_AUTH_SIZE); /*128 bits for auth */
	memcpy(ek->msk,    fk + 32, 64);  /* 64 bytes for Master Session Key */
	memcpy(ek->emsk,   fk + 96, 64);  /* 64- extended Master Session Key */
}

/** Dump the current state of all keys associated with the EAP SIM session
 *
 * @param[in] request	The current request.
 * @param[in] ek	EAP SIM keys associated with the session.
 */
void fr_sim_crypto_keys_log(REQUEST *request, fr_sim_keys_t *ek)
{
	unsigned int i;

	RDEBUG3("Key data from client");
	RINDENT();

	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->identity, ek->identity_len, "identity:");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->nonce_mt, sizeof(ek->nonce_mt), "nonce_mt:");

	for (i = 0; i < ek->num_vectors; i++) {
		RHEXDUMP_INLINE(L_DBG_LVL_3, ek->vector[i].rand, sizeof(ek->vector[i].rand),
				"[%i] rand :", i);
		RHEXDUMP_INLINE(L_DBG_LVL_3, ek->vector[i].sres, sizeof(ek->vector[i].sres),
				"[%i] sres :", i);
		RHEXDUMP_INLINE(L_DBG_LVL_3, ek->vector[i].kc, sizeof(ek->vector[i].kc),
				"[%i] kc   :", i);
	}

	RHEXDUMP(L_DBG_LVL_3, ek->version_list, ek->version_list_len, "version_list:");

	RDEBUG3("Key data to client");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->master_key, sizeof(ek->master_key),
			"mk      :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->k_aut, sizeof(ek->k_aut),
			"k_aut  :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->k_encr,sizeof(ek->k_encr),
			"k_encr :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->msk, sizeof(ek->msk),
			"msk     :");
	RHEXDUMP_INLINE(L_DBG_LVL_3, ek->emsk, sizeof(ek->emsk),
			"emsk    :");
}
