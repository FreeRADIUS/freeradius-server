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
 * @file rlm_eap/lib/sim/vector.c
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
#include "sim_proto.h"
#include "comp128.h"
#include "milenage.h"

#include <freeradius-devel/rad_assert.h>

static int vector_gsm_from_ki(eap_session_t *eap_session, VALUE_PAIR *vps,
			      int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*ki, *version;
	int		i;

	/*
	 *	Generate a new RAND value, and derive Kc and SRES from Ki
	 */
	ki = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_KI, TAG_ANY);
	if (!ki) {
		RDEBUG3("No &control:SIM-Ki found, not generating triplets locally");
		return 1;
	} else if (ki->vp_length != SIM_MILENAGE_KI_SIZE) {
		REDEBUG("&control:SIM-Ki has incorrect length, expected 16 bytes got %zu bytes", ki->vp_length);
		return -1;
	}

	/*
	 *	Check to see if have a Ki for the IMSI, this allows us to generate the rest
	 *	of the triplets.
	 */
	version = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_ALGO_VERSION, TAG_ANY);
	if (!version) {
		RDEBUG3("No &control:SIM-Algo-Version found, not generating triplets locally");
		return 1;
	}

	for (i = 0; i < SIM_VECTOR_GSM_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->gsm.vector[idx].rand[i], &rand, sizeof(rand));
	}

	switch (version->vp_uint32) {
	case 1:
		comp128v1(keys->gsm.vector[idx].sres,
			  keys->gsm.vector[idx].kc,
			  ki->vp_octets,
			  keys->gsm.vector[idx].rand);
		break;

	case 2:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki->vp_octets,
			   keys->gsm.vector[idx].rand, true);
		break;

	case 3:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki->vp_octets,
			   keys->gsm.vector[idx].rand, false);
		break;

	case 4:
	{
		VALUE_PAIR *opc;

		opc = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_OPC, TAG_ANY);
		if (!opc) {
			RDEBUG3("No &control:SIM-OPc not generating triplets locally");
			return 1;
		}
		else if (opc->vp_length != SIM_MILENAGE_OPC_SIZE) {
			REDEBUG("&control:SIM-OPc has incorrect length, expected %u bytes got %zu bytes",
				SIM_MILENAGE_OPC_SIZE, opc->vp_length);
			return -1;
		}

		if (milenage_gsm_generate(keys->gsm.vector[idx].sres,
					  keys->gsm.vector[idx].kc,
					  opc->vp_octets,
					  ki->vp_octets,
					  keys->gsm.vector[idx].rand) < 0) {
			RPEDEBUG2("Failed deriving GSM triplet");
			return -1;
		}
	}
		return 1;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version->vp_uint32);
		return -1;
	}
	return 0;
}

static int vector_gsm_from_triplets(eap_session_t *eap_session, VALUE_PAIR *vps,
				    int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*rand = NULL, *sres = NULL, *kc = NULL;
	vp_cursor_t	cursor;
	int		i;

	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (kc = fr_pair_cursor_next_by_child_num(&cursor, dict_sim_root, FR_EAP_SIM_KC, TAG_ANY)); i++);
	if (!kc) {
		RDEBUG3("No &control:EAP-SIM-KC[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (kc->vp_length != SIM_VECTOR_GSM_KC_SIZE) {
		REDEBUG("&control:EAP-SIM-KC[%i] is not " STRINGIFY(SIM_VECTOR_GSM_KC_SIZE) " bytes, got %zu bytes",
			idx, kc->vp_length);
		return -1;
	}

	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (rand = fr_pair_cursor_next_by_child_num(&cursor, dict_sim_root, FR_EAP_SIM_RAND, TAG_ANY));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:EAP-SIM-Rand[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (rand->vp_length != SIM_VECTOR_GSM_RAND_SIZE) {
		REDEBUG("&control:EAP-SIM-Rand[%i] is not " STRINGIFY(SIM_RAND_SIZE) " bytes, got %zu bytes",
			idx, rand->vp_length);
		return -1;
	}

	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (sres = fr_pair_cursor_next_by_child_num(&cursor, dict_sim_root, FR_EAP_SIM_SRES, TAG_ANY)); i++);
	if (!sres) {
		RDEBUG3("No &control:EAP-SIM-SRES[%i] attribute found, not using GSM triplets", idx);
		return 1;
	}
	if (sres->vp_length != SIM_VECTOR_GSM_SRES_SIZE) {
		REDEBUG("&control:EAP-SIM-SRES[%i] is not " STRINGIFY(SIM_VECTOR_GSM_SRES_SIZE) " bytes, got %zu bytes",
			idx, sres->vp_length);
		return -1;
	}

	memcpy(keys->gsm.vector[idx].kc, kc->vp_strvalue, SIM_VECTOR_GSM_KC_SIZE);
	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, SIM_VECTOR_GSM_RAND_SIZE);
	memcpy(keys->gsm.vector[idx].sres, sres->vp_octets, SIM_VECTOR_GSM_SRES_SIZE);

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
static int vector_gsm_from_quintuplets(eap_session_t *eap_session, VALUE_PAIR *vps,
				       int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	vp_cursor_t	cursor;

	VALUE_PAIR	*ck = NULL, *ik = NULL, *rand = NULL, *xres = NULL;

	uint64_t const	*ck_ptr;
	uint64_t const	*ik_ptr;
	uint8_t		xres_buff[16];
	uint32_t const	*xres_ptr;

	int		i;

	/*
	 *	Fetch CK
	 */
	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (ck = fr_pair_cursor_next_by_child_num(&cursor, dict_aka_root, FR_EAP_AKA_CK, TAG_ANY)); i++);
	if (!ck) {
		RDEBUG3("No &control:EAP-AKA-CK[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	/*
	 *	Fetch IK
	 */
	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (ik = fr_pair_cursor_next_by_child_num(&cursor, dict_aka_root, FR_EAP_AKA_IK, TAG_ANY)); i++);
	if (!ik) {
		RDEBUG3("No &control:EAP-AKA-IK[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	/*
	 *	Fetch RAND
	 */
	for (i = 0, fr_pair_cursor_init(&cursor, &vps); (i <= idx) &&
	     (rand = fr_pair_cursor_next_by_child_num(&cursor, dict_aka_root, FR_EAP_AKA_RAND, TAG_ANY)); i++);
	if (!rand) {
		RDEBUG3("No &control:EAP-AKA-Rand[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	if (rand->vp_length != SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:EAP-AKA-RAND[%i] incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", idx, rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	for (i = 0, fr_pair_cursor_init(&cursor, &vps);
	     (i <= idx) && (xres = fr_pair_cursor_next_by_child_num(&cursor, dict_aka_root, FR_EAP_AKA_XRES, TAG_ANY)); i++);
	if (!xres) {
		RDEBUG3("No &control:EAP-AKA-XRES[%i] attribute found, not using quintuplet derivation", idx);
		return 1;
	}

	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, SIM_VECTOR_GSM_RAND_SIZE);

	/*
	 *	Fold CK and IK in 64bit quantities to produce Kc
	 */
	ck_ptr = (uint64_t const *)ck->vp_octets;
	ik_ptr = (uint64_t const *)ik->vp_octets;
	keys->gsm.vector[idx].kc_uint64 = ((ck_ptr[0] ^ ck_ptr[1]) ^ ik_ptr[0]) ^ ik_ptr[1];

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
	keys->gsm.vector[idx].sres_uint32 = ((xres_ptr[0] ^ xres_ptr[1]) ^ xres_ptr[2]) ^ xres_ptr[3];

	return 0;
}

/** Retrieve GSM triplets from sets of attributes.
 *
 * Hunt for a source of SIM triplets
 *
 * @param eap_session		The current eap_session.
 * @param vps			List to hunt for triplets in.
 * @param idx			To write EAP-SIM triplets to.
 * @param keys			EAP session keys.
 * @param src			Forces triplets to be retrieved from a particular src
 *				and ensures if multiple triplets are being retrieved
 *				that they all come from the same src.
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
int fr_sim_vector_gsm_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
				 int idx, fr_sim_keys_t *keys, fr_sim_vector_src_t *src)
{
	REQUEST		*request = eap_session->request;
	int		ret;

	rad_assert(idx >= 0 && idx < 3);
	rad_assert((keys->vector_type == SIM_VECTOR_NONE) || (keys->vector_type == SIM_VECTOR_GSM));

	switch (*src) {
	default:
	case SIM_VECTOR_SRC_KI:
		ret = vector_gsm_from_ki(eap_session, vps, idx, keys);
		if (ret == 0) {
			*src = SIM_VECTOR_SRC_KI;
			break;
		}
		if (ret < 0) return -1;
		if (*src != SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case SIM_VECTOR_SRC_TRIPLETS:
		ret = vector_gsm_from_triplets(eap_session, vps, idx, keys);
		if (ret == 0) {
			*src = SIM_VECTOR_SRC_TRIPLETS;
			break;
		}
		if (ret < 0) return -1;
		if (*src != SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case SIM_VECTOR_SRC_QUINTUPLETS:
		ret = vector_gsm_from_quintuplets(eap_session, vps, idx, keys);
		if (ret == 0) {
			*src = SIM_VECTOR_SRC_QUINTUPLETS;
			break;
		}
		if (ret < 0) return -1;
		break;
	}

	if (ret == 1) {
		RWDEBUG("Could not find or derive data for GSM vector[%i]", idx);
		return 1;
	}

	if (RDEBUG_ENABLED2) {
		RDEBUG2("GSM vector[%i]", idx);

		RINDENT();
		/*
		 *	Don't change colon indent, matches other messages later...
		 */
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->gsm.vector[idx].kc, SIM_VECTOR_GSM_KC_SIZE,
				"KC           :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->gsm.vector[idx].rand, SIM_VECTOR_GSM_RAND_SIZE,
				"RAND         :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->gsm.vector[idx].sres, SIM_VECTOR_GSM_SRES_SIZE,
				"SRES         :");
		REXDENT();
	}

	keys->vector_type = SIM_VECTOR_GSM;

	return 0;
}

static int vector_umts_from_ki(eap_session_t *eap_session, VALUE_PAIR *vps, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*ki, *opc, *amf, *sqn, *version_vp;
	uint8_t		amf_buff[SIM_MILENAGE_AMF_SIZE];
	uint8_t const	*amf_p;
	uint8_t		sqn_buff[SIM_MILENAGE_SQN_SIZE];
	uint8_t const	*sqn_p;
	uint32_t	version = 4;

	int		i;

	ki = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_KI, TAG_ANY);
	if (!ki) {
		RDEBUG3("No &control:SIM-Ki found, not generating triplets locally");
		return 1;
	} else if (ki->vp_length != SIM_MILENAGE_KI_SIZE) {
		REDEBUG("&control:SIM-Ki has incorrect length, expected %u bytes got %zu bytes",
			SIM_MILENAGE_KI_SIZE, ki->vp_length);
		return -1;
	}

	opc = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_OPC, TAG_ANY);
	if (!opc) {
		RDEBUG3("No &control:SIM-OPc not generating  quintuplets locally");
		return 1;
	} else if (opc->vp_length != SIM_MILENAGE_OPC_SIZE) {
		REDEBUG("&control:SIM-OPc has incorrect length, expected %u bytes got %zu bytes",
			SIM_MILENAGE_OPC_SIZE, opc->vp_length);
		return -1;
	}

	amf = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_AMF, TAG_ANY);
	if (!amf) {
		memset(&amf_buff, 0, sizeof(amf_buff));
		amf_p = amf_buff;
	} else if (amf->vp_length != SIM_MILENAGE_AMF_SIZE) {
		REDEBUG("&control:SIM-AMF has incorrect length, expected %u bytes got %zu bytes",
			SIM_MILENAGE_AMF_SIZE, amf->vp_length);
		return -1;
	} else {
		amf_p = amf->vp_octets;
	}

	sqn = fr_pair_find_by_child_num(vps, fr_dict_root(fr_dict_internal), FR_SIM_SQN, TAG_ANY);
	if (!sqn) {
		memset(&sqn_buff, 0, sizeof(sqn_buff));
		sqn_p = sqn_buff;
	} else if (sqn->vp_length != SIM_MILENAGE_SQN_SIZE) {
		REDEBUG("&control:SIM-SQN has incorrect length, expected %u bytes got %zu bytes",
			SIM_MILENAGE_SQN_SIZE, sqn->vp_length);
		return -1;
	} else {
		sqn_p = sqn->vp_octets;
	}

	/*
	 *	We default to milenage
	 */
	version_vp = fr_pair_find_by_num(vps, 0, FR_SIM_ALGO_VERSION, TAG_ANY);
	if (version_vp) version = version_vp->vp_uint32;

	for (i = 0; i < SIM_VECTOR_UMTS_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->umts.vector.rand[i], &rand, sizeof(rand));
	}

	switch (version) {
	case 4:
		if (milenage_umts_generate(keys->umts.vector.autn,
					   keys->umts.vector.ik, keys->umts.vector.ck, keys->umts.vector.xres,
					   opc->vp_octets, amf_p, ki->vp_octets,
					   sqn_p, keys->umts.vector.rand) < 0) {
			RPEDEBUG2("Failed deriving UMTS Quintuplet");
			return -1;
		}
		keys->umts.vector.xres_len = 8;
		return 1;

	case 1:
	case 2:
	case 3:
		REDEBUG("Only Milenage can be used to generate quintuplets");
		return -1;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version);
		return -1;
	}
	return 0;
}

/** Get one set of quintuplets from the request
 *
 */
static int vector_umts_from_quintuplets(eap_session_t *eap_session, VALUE_PAIR *vps, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;

	VALUE_PAIR	*rand = NULL, *xres = NULL, *ck = NULL, *ik = NULL, *autn = NULL;

	/*
	 *	Fetch AUTN
	 */
	autn = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_AUTN, TAG_ANY);
	if (!autn) {
		RDEBUG3("No &control:FR_EAP_AKA_AUTN attribute found, not using UMTS quintuplets");
		return 1;
	}

	if (autn->vp_length > SIM_VECTOR_UMTS_AUTN_SIZE) {
		REDEBUG("&control:EAP-AKA-AUTN incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_AUTN_SIZE) " bytes, got %zu bytes", autn->vp_length);
		return -1;
	}

	/*
	 *	Fetch CK
	 */
	ck = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_CK, TAG_ANY);
	if (!ck) {
		RDEBUG3("No &control:EAP-AKA-CK attribute found, not using UMTS quintuplets");
		return 1;
	}

	if (ck->vp_length > SIM_VECTOR_UMTS_CK_SIZE) {
		REDEBUG("&control:EAP-AKA-CK incorrect length.  Expected "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes", ck->vp_length);
		return -1;
	}

	/*
	 *	Fetch IK
	 */
	ik = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_IK, TAG_ANY);
	if (!ik) {
		RDEBUG3("No &control:EAP-AKA-IK attribute found, not using UMTS quintuplets");
		return 1;
	}

	if (ik->vp_length > SIM_VECTOR_UMTS_IK_SIZE) {
		REDEBUG("&control:EAP-AKA-IK incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_IK_SIZE) " bytes, got %zu bytes", ik->vp_length);
		return -1;
	}

	/*
	 *	Fetch RAND
	 */
	rand = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_RAND, TAG_ANY);
	if (!rand) {
		RDEBUG3("No &control:EAP-AKA-Rand attribute found, not using quintuplet derivation");
		return 1;
	}

	if (rand->vp_length != SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:EAP-AKA-RAND incorrect length.  Expected " STRINGIFY(SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	xres = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_XRES, TAG_ANY);
	if (!xres) {
		RDEBUG3("No &control:EAP-AKA-XRES attribute found, not using UMTS quintuplets");
		return 1;
	}

	if (xres->vp_length > SIM_VECTOR_UMTS_XRES_MAX_SIZE) {
		REDEBUG("&control:EAP-AKA-XRES incorrect length.  Expected < "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes", xres->vp_length);
		return -1;
	}

	memcpy(keys->umts.vector.autn, autn->vp_octets, SIM_VECTOR_UMTS_AUTN_SIZE);
	memcpy(keys->umts.vector.ck, ck->vp_octets, SIM_VECTOR_UMTS_CK_SIZE);
	memcpy(keys->umts.vector.ik, ik->vp_octets, SIM_VECTOR_UMTS_IK_SIZE);
	memcpy(keys->umts.vector.rand, rand->vp_octets, SIM_VECTOR_UMTS_RAND_SIZE);
	memcpy(keys->umts.vector.xres, xres->vp_octets, xres->vp_length);
	keys->umts.vector.xres_len = xres->vp_length;	/* xres is variable length */

	return 0;
}

/** Retrieve UMTS quintuplets from sets of attributes.
 *
 * Hunt for a source of UMTS quintuplets
 *
 * @param eap_session		The current eap_session.
 * @param vps			List to hunt for triplets in.
 * @param keys			UMTS keys.
 * @param src			Forces quintuplets to be retrieved from a particular src.
 *
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
int fr_sim_vector_umts_from_attrs(eap_session_t *eap_session, VALUE_PAIR *vps,
				  fr_sim_keys_t *keys, fr_sim_vector_src_t *src)
{
	REQUEST		*request = eap_session->request;
	int		ret;

	rad_assert((keys->vector_type == SIM_VECTOR_NONE) || (keys->vector_type == SIM_VECTOR_UMTS));

	switch (*src) {
	default:
	case SIM_VECTOR_SRC_KI:
		ret = vector_umts_from_ki(eap_session, vps, keys);
		if (ret == 0) {
			*src = SIM_VECTOR_SRC_KI;
			break;
		}
		if (ret < 0) return -1;
		if (*src != SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case SIM_VECTOR_SRC_QUINTUPLETS:
		ret = vector_umts_from_quintuplets(eap_session, vps, keys);
		if (ret == 0) {
			*src = SIM_VECTOR_SRC_QUINTUPLETS;
			break;;
		}
		if (ret < 0) return -1;
		break;
	}

	if (ret == 1) {
		RWDEBUG("Could not find or derive data for UMTS vector");
		return 1;
	}

	if (RDEBUG_ENABLED2) {
		RDEBUG2("UMTS vector");

		RINDENT();
		/*
		 *	Don't change colon indent, matches other messages later...
		 */
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->umts.vector.autn, SIM_VECTOR_UMTS_AUTN_SIZE,
				"AUTN         :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->umts.vector.ck, SIM_VECTOR_UMTS_CK_SIZE,
				"CK           :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->umts.vector.ik, SIM_VECTOR_UMTS_IK_SIZE,
				"IK           :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->umts.vector.rand, SIM_VECTOR_UMTS_RAND_SIZE,
				"RAND         :");
		RHEXDUMP_INLINE(L_DBG_LVL_2,
				keys->umts.vector.xres, keys->umts.vector.xres_len,
				"XRES         :");
		REXDENT();
	}

	keys->vector_type = SIM_VECTOR_UMTS;

	return 0;
}
