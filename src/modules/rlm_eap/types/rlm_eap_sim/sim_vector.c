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
 * $Id$
 * @file rlm_eap_sim/sim_vector.c
 * @brief Retrieve or derive vectors for EAP-SIM.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "../../eap.h"
#include "eap_types.h"
#include "eap_sim.h"
#include "comp128.h"

#include <freeradius-devel/rad_assert.h>

static int sim_vector_from_ki(eap_session_t *eap_session, VALUE_PAIR *vps, int idx, eap_sim_session_t *eap_sim_session)
{
	REQUEST	*request = eap_session->request;
	VALUE_PAIR *vp, *version;
	int i;

	/*
	 *	Generate a new RAND value, and derive Kc and SRES from Ki
	 */
	vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_KI, TAG_ANY);
	if (!vp) {
		RDEBUG3("No &control:EAP-SIM-KI found, not generating triplets locally");
		return 1;
	}

	/*
	 *	Check to see if have a Ki for the IMSI, this allows us to generate the rest
	 *	of the triplets.
	 */
	version = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_ALGO_VERSION, TAG_ANY);
	if (!version) {
		RDEBUG3("No &control:EAP-SIM-ALGO-VERSION found, not generating triplets locally");
		return 1;
	}

	for (i = 0; i < EAP_SIM_RAND_SIZE; i++) {
		eap_sim_session->keys.rand[idx][i] = fr_rand();
	}

	switch (version->vp_integer) {
	case 1:
		comp128v1(eap_sim_session->keys.sres[idx],
			  eap_sim_session->keys.kc[idx], vp->vp_octets,
			  eap_sim_session->keys.rand[idx]);
		break;

	case 2:
		comp128v23(eap_sim_session->keys.sres[idx],
			   eap_sim_session->keys.kc[idx],
			   vp->vp_octets,
			   eap_sim_session->keys.rand[idx], true);
		break;

	case 3:
		comp128v23(eap_sim_session->keys.sres[idx],
			   eap_sim_session->keys.kc[idx],
			   vp->vp_octets,
			   eap_sim_session->keys.rand[idx], false);
		break;

	case 4:
		REDEBUG("Milenage not supported (feel free to implement it)");
		return 1;

	default:
		REDEBUG("Unknown/unsupported algorithm Comp128-%i", version->vp_integer);
		return -1;
	}
	return 0;
}

static int sim_vector_from_gsm(eap_session_t *eap_session,
			       VALUE_PAIR *vps, int idx, eap_sim_session_t *eap_sim_session)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*rand = NULL, *sres = NULL, *kc = NULL;
	vp_cursor_t	cursor;
	int		i;

	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (rand = fr_cursor_next_by_num(&cursor, 0, PW_EAP_SIM_RAND, TAG_ANY));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:EAP-SIM-Rand[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (rand->vp_length != EAP_SIM_RAND_SIZE) {
		REDEBUG("&control:EAP-SIM-Rand[%i] is not " STRINGIFY(EAP_SIM_RAND_SIZE) " bytes, got %zu bytes",
			idx, rand->vp_length);
		return -1;
	}

	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (sres = fr_cursor_next_by_num(&cursor, 0, PW_EAP_SIM_SRES, TAG_ANY)); i++);
	if (!sres) {
		RDEBUG3("No &control:EAP-SIM-SRES[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (sres->vp_length != EAP_SIM_SRES_SIZE) {
		REDEBUG("&control:EAP-SIM-SRES[%i] is not " STRINGIFY(EAP_SIM_SRES_SIZE) " bytes, got %zu bytes",
			idx, sres->vp_length);
		return -1;
	}

	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (kc = fr_cursor_next_by_num(&cursor, 0, PW_EAP_SIM_KC, TAG_ANY)); i++);
	if (!kc) {
		RDEBUG3("No &control:EAP-SIM-KC[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (kc->vp_length != EAP_SIM_KC_SIZE) {
		REDEBUG("&control:EAP-SIM-KC[%i] is not " STRINGIFY(EAP_SIM_KC_SIZE) " bytes, got %zu bytes",
			idx, kc->vp_length);
		return -1;
	}

	memcpy(eap_sim_session->keys.rand[idx], rand->vp_octets, EAP_SIM_RAND_SIZE);
	memcpy(eap_sim_session->keys.sres[idx], sres->vp_octets, EAP_SIM_SRES_SIZE);
	memcpy(eap_sim_session->keys.kc[idx], kc->vp_strvalue, EAP_SIM_KC_SIZE);

	return 0;
}

/** Derive triplets from quintuplets
 *
 * c1: RAND[gsm] = RAND
 * c2: SRES[gsm] = (XRES*[0]...XRES*[31]) ⊕ (XRES*[32]...XRES*[63]) ⊕
 *		   (XRES*[64]...XRES*[95]) ⊕ (XRES*[96]...XRES*[127)
 * c3:   Kc[gsm] = (CK[0]...CK[63]) ⊕ (CK[64]...CK[127]) ⊕
 *		   (IK[0]...IK[63]) ⊕ (IK[64]...IK[127)
 */
static int sim_vector_from_umts(eap_session_t *eap_session,
				VALUE_PAIR *vps, int idx, eap_sim_session_t *eap_sim_session)
{
	REQUEST		*request = eap_session->request;
	vp_cursor_t	cursor;

	VALUE_PAIR	*rand = NULL, *xres = NULL, *ck = NULL, *ik = NULL;
	uint8_t		xres_buff[16];
	uint32_t const	*xres_ptr;
	uint64_t const	*ck_ptr;
	uint64_t const	*ik_ptr;

	int		i;

	/*
	 *	Fetch RAND
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps); (i <= idx) &&
	     (rand = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_RAND, TAG_ANY)); i++);
	if (!rand) {
		RDEBUG3("No &control:EAP-AKA-Rand[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	if (rand->vp_length != EAP_SIM_RAND_SIZE) {
		REDEBUG("&control:EAP-AKA-RAND[%i] incorrect length.  Expected " STRINGIFY(EAP_SIM_RAND_SIZE) " bytes, "
			"got %zu bytes", idx, rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (xres = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_XRES, TAG_ANY)); i++);
	if (!xres) {
		RDEBUG3("No &control:EAP-AKA-XRES[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	/*
	 *	Fetch CK
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (ck = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_CK, TAG_ANY)); i++);
	if (!ck) {
		RDEBUG3("No &control:EAP-AKA-CK[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	/*
	 *	Fetch IK
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps);
	     (i <= idx) && (ik = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_IK, TAG_ANY)); i++);
	if (!ik) {
		RDEBUG3("No &control:EAP-AKA-IK[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	memcpy(eap_sim_session->keys.rand[idx], rand->vp_octets, EAP_SIM_RAND_SIZE);	/* RAND is 128 bits in both */

	/*
	 *	Have to pad XRES out to 16 octets if it's shorter than that.
	 */
	if (xres->vp_length < 16) {
		memset(&xres_buff, 0, sizeof(xres_buff));
		memcpy(&xres_buff, &xres->vp_octets, xres->vp_length);
		xres_ptr = (uint32_t const *)&xres_buff[0];
	} else {
		xres_ptr = (uint32_t const *)xres->vp_octets;
	}

	/*
	 *	Fold XRES into itself in 32bit quantities using xor to
	 *	produce SRES.
	 */
	eap_sim_session->keys.sres_uint32[idx] = ((xres_ptr[0] ^ xres_ptr[1]) ^ xres_ptr[2]) ^ xres_ptr[3];

	/*
	 *	Fold CK and IK in 64bit quantities to produce Kc
	 */
	ck_ptr = (uint64_t const *)ck->vp_octets;
	ik_ptr = (uint64_t const *)ik->vp_octets;
	eap_sim_session->keys.kc_uint64[idx] = ((ck_ptr[0] ^ ck_ptr[1]) ^ ik_ptr[0]) ^ ik_ptr[1];

	return 0;
}

/** Retrieve GSM triplets from sets of attributes.
 *
 * Hunt for a source of SIM triplets
 *
 * @param eap_session		The current eap_session.
 * @param vps			List to hunt for triplets in.
 * @param idx			To write EAP-SIM triplets to.
 * @param eap_sim_session	EAP session state.
 * @param src			Forces triplets to be retrieved from a particular src
 *				and ensures if multiple triplets are being retrieved
 *				that they all come from the same src.
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
int sim_vector_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
			  int idx, eap_sim_session_t *eap_sim_session, eap_sim_vector_src_t *src)
{
	REQUEST		*request = eap_session->request;
	int		ret;

	rad_assert(idx >= 0 && idx < 3);

	switch (*src) {
	default:
	case EAP_SIM_VECTOR_SRC_KI:
		ret = sim_vector_from_ki(eap_session, vps, idx, eap_sim_session);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_KI;
			return 0;
		}
		if (ret < 0) return -1;
		if (*src != EAP_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case EAP_SIM_VECTOR_SRC_GSM:
		ret = sim_vector_from_gsm(eap_session, vps, idx, eap_sim_session);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_GSM;
			return 0;
		}
		if (ret < 0) return -1;
		if (*src != EAP_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case EAP_SIM_VECTOR_SRC_UMTS:
		ret = sim_vector_from_umts(eap_session, vps, idx, eap_sim_session);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_UMTS;
			return 0;
		}
		if (ret < 0) return -1;
		break;
	}

	if (RDEBUG_ENABLED2) {
		size_t	i;
		char	buffer[33];	/* 32 hexits (16 bytes) + 1 */
		char	*p;

		RDEBUG2("Acquired triplets for round %i", idx);

		RINDENT();
		p = buffer;
		for (i = 0; i < EAP_SIM_RAND_SIZE; i++) {
			p += sprintf(p, "%02x", eap_sim_session->keys.rand[idx][i]);
		}
		RDEBUG2("RAND : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAP_SIM_SRES_SIZE; i++) {
			p += sprintf(p, "%02x", eap_sim_session->keys.sres[idx][i]);
		}
		RDEBUG2("SRES : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAP_SIM_KC_SIZE; i++) {
			p += sprintf(p, "%02x", eap_sim_session->keys.kc[idx][i]);
		}
		RDEBUG2("Kc   : 0x%s", buffer);
		REXDENT();
	}

	return 0;
}
