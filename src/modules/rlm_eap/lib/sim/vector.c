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
#include "sim_attrs.h"
#include "comp128.h"
#include "milenage.h"

#include <freeradius-devel/server/rad_assert.h>

static int vector_opc_from_op(REQUEST *request, uint8_t const **out, uint8_t opc_buff[MILENAGE_OPC_SIZE],
			      VALUE_PAIR *list, uint8_t const ki[MILENAGE_KI_SIZE])
{
	VALUE_PAIR	*opc_vp;
	VALUE_PAIR	*op_vp;

	opc_vp = fr_pair_find_by_da(list, attr_sim_opc, TAG_ANY);
	if (opc_vp) {
		if (opc_vp->vp_length != MILENAGE_OPC_SIZE) {
			REDEBUG("&control:%s has incorrect length, expected %u bytes got %zu bytes",
				attr_sim_opc->name, MILENAGE_OPC_SIZE, opc_vp->vp_length);
			return -1;
		}
		*out = opc_vp->vp_octets;
		return 0;
	}

	op_vp = fr_pair_find_by_da(list, attr_sim_op, TAG_ANY);
	if (op_vp) {
		if (op_vp->vp_length != MILENAGE_OP_SIZE) {
			REDEBUG("&control:%s has incorrect length, expected %u bytes got %zu bytes",
				attr_sim_op->name, MILENAGE_OP_SIZE, op_vp->vp_length);
			return -1;
		}
		if (milenage_opc_generate(opc_buff, op_vp->vp_octets, ki) < 0) {
			RPEDEBUG("Deriving OPc failed");
			return -1;
		}
		*out = opc_buff;
		return 0;
	}

	*out = NULL;
	return 1;
}

static int vector_gsm_from_ki(eap_session_t *eap_session, VALUE_PAIR *vps, int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*ki_vp, *version_vp;
	uint8_t		opc_buff[MILENAGE_OPC_SIZE];
	uint8_t	const	*opc_p;
	uint32_t	version;
	int		i;

	/*
	 *	Generate a new RAND value, and derive Kc and SRES from Ki
	 */
	ki_vp = fr_pair_find_by_da(vps, attr_sim_ki, TAG_ANY);
	if (!ki_vp) {
		RDEBUG3("No &control:%sfound, not generating triplets locally", attr_sim_ki->name);
		return 1;
	} else if (ki_vp->vp_length != MILENAGE_KI_SIZE) {
		REDEBUG("&control:%s has incorrect length, expected 16 bytes got %zu bytes",
			attr_sim_ki->name, ki_vp->vp_length);
		return -1;
	}

	/*
	 *	Check to see if have a Ki for the IMSI, this allows us to generate the rest
	 *	of the triplets.
	 */
	version_vp = fr_pair_find_by_da(vps, attr_sim_algo_version, TAG_ANY);
	if (!version_vp) {
		if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;
		version = opc_p ? 4 : 3;
	/*
	 *	Version we explicitly specified, see if we can find the prerequisite
	 *	attributes.
	 */
	} else {
		version = version_vp->vp_uint32;
		if (version == 4) {
			if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;
			if (!opc_p) {
				RPEDEBUG2("No &control:%s or &control:%s found, "
					  "can't run Milenage (COMP128-4)", attr_sim_op->name, attr_sim_opc->name);
				return -1;
			}
		}
	}

	for (i = 0; i < SIM_VECTOR_GSM_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->gsm.vector[idx].rand[i], &rand, sizeof(rand));
	}

	switch (version) {
	case 1:
		comp128v1(keys->gsm.vector[idx].sres,
			  keys->gsm.vector[idx].kc,
			  ki_vp->vp_octets,
			  keys->gsm.vector[idx].rand);
		break;

	case 2:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki_vp->vp_octets,
			   keys->gsm.vector[idx].rand, true);
		break;

	case 3:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki_vp->vp_octets,
			   keys->gsm.vector[idx].rand, false);
		break;

	case 4:
		if (milenage_gsm_generate(keys->gsm.vector[idx].sres,
					  keys->gsm.vector[idx].kc,
					  opc_p,
					  ki_vp->vp_octets,
					  keys->gsm.vector[idx].rand) < 0) {
			RPEDEBUG2("Failed deriving GSM triplet");
			return -1;
		}
		return 0;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version);
		return -1;
	}
	return 0;
}

static int vector_gsm_from_triplets(eap_session_t *eap_session, VALUE_PAIR *vps,
				    int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	VALUE_PAIR	*rand = NULL, *sres = NULL, *kc = NULL;
	fr_cursor_t	cursor;
	int		i;

	for (i = 0, (kc = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_sim_kc));
	     (i < idx) && (kc = fr_cursor_next(&cursor));
	     i++);
	if (!kc) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_sim_kc->name, idx);
		return 1;
	}
	if (kc->vp_length != SIM_VECTOR_GSM_KC_SIZE) {
		REDEBUG("&control:%s[%i] is not " STRINGIFY(SIM_VECTOR_GSM_KC_SIZE) " bytes, got %zu bytes",
			attr_eap_sim_kc->name, idx, kc->vp_length);
		return -1;
	}

	for (i = 0, (rand = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_sim_rand));
	     (i < idx) && (rand = fr_cursor_next(&cursor));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_sim_rand->name, idx);
		return 1;
	}
	if (rand->vp_length != SIM_VECTOR_GSM_RAND_SIZE) {
		REDEBUG("&control:EAP-SIM-Rand[%i] is not " STRINGIFY(SIM_RAND_SIZE) " bytes, got %zu bytes",
			idx, rand->vp_length);
		return -1;
	}

	for (i = 0, (sres = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_sim_sres));
	     (i < idx) && (sres = fr_cursor_next(&cursor));
	     i++);
	if (!sres) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_sim_sres->name, idx);
		return 1;
	}
	if (sres->vp_length != SIM_VECTOR_GSM_SRES_SIZE) {
		REDEBUG("&control:%s[%i] is not " STRINGIFY(SIM_VECTOR_GSM_SRES_SIZE) " bytes, got %zu bytes",
			attr_eap_sim_sres->name, idx, sres->vp_length);
		return -1;
	}

	memcpy(keys->gsm.vector[idx].kc, kc->vp_strvalue, SIM_VECTOR_GSM_KC_SIZE);
	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, SIM_VECTOR_GSM_RAND_SIZE);
	memcpy(keys->gsm.vector[idx].sres, sres->vp_octets, SIM_VECTOR_GSM_SRES_SIZE);

	return 0;
}

/** Derive triplets from quintuplets
 *
 */
static int vector_gsm_from_quintuplets(eap_session_t *eap_session, VALUE_PAIR *vps,
				       int idx, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;
	fr_cursor_t	cursor;

	VALUE_PAIR	*ck = NULL, *ik = NULL, *rand = NULL, *xres = NULL;

	int		i;

	/*
	 *	Fetch CK
	 */
	for (i = 0, (ck = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_ck));
	     (i < idx) && (ck = fr_cursor_next(&cursor));
	     i++);
	if (!ck) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_ck->name, idx);
		return 1;
	}

	/*
	 *	Fetch IK
	 */
	for (i = 0, (ik = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_ik));
	     (i < idx) && (ik = fr_cursor_next(&cursor));
	     i++);
	if (!ik) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_ik->name, idx);
		return 1;
	}

	/*
	 *	Fetch RAND
	 */
	for (i = 0, (rand = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_rand));
	     (i < idx) && (rand = fr_cursor_next(&cursor));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_rand->name, idx);
		return 1;
	}

	if (rand->vp_length != SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:%s[%i] incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", attr_eap_aka_rand->name, idx, rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	for (i = 0, (xres = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_xres));
	     (i < idx) && (xres = fr_cursor_next(&cursor));
	     i++);
	if (!xres) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_xres->name, idx);
		return 1;
	}

	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, SIM_VECTOR_GSM_RAND_SIZE);

	milenage_gsm_from_umts(keys->gsm.vector[idx].sres,
			       keys->gsm.vector[idx].kc,
			       ik->vp_octets,
			       ck->vp_octets,
			       xres->vp_octets);

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
	VALUE_PAIR	*ki_vp, *amf_vp, *sqn_vp, *version_vp;

	uint64_t	sqn;
	uint8_t		amf_buff[MILENAGE_AMF_SIZE] = { 0x00, 0x00 };
	uint8_t 	opc_buff[MILENAGE_OPC_SIZE];
	uint8_t	const	*opc_p;
	uint32_t	version = 4;
	int		i;

	ki_vp = fr_pair_find_by_da(vps, attr_sim_ki, TAG_ANY);
	if (!ki_vp) {
		RDEBUG3("No &control:%s found, not generating quintuplets locally", attr_sim_ki->name);
		return 1;
	} else if (ki_vp->vp_length != MILENAGE_KI_SIZE) {
		REDEBUG("&control:%s has incorrect length, expected %u bytes got %zu bytes",
			attr_sim_ki->name, MILENAGE_KI_SIZE, ki_vp->vp_length);
		return -1;
	}

	if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;

	amf_vp = fr_pair_find_by_da(vps, attr_sim_amf, TAG_ANY);
	if (amf_vp) {
		if (amf_vp->vp_length != sizeof(amf_buff)) {
			REDEBUG("&control:%s has incorrect length, expected %u bytes got %zu bytes",
				attr_sim_amf->name, MILENAGE_AMF_SIZE, amf_vp->vp_length);
			return -1;
		}
		memcpy(amf_buff, amf_vp->vp_octets, sizeof(amf_buff));
	}

	sqn_vp = fr_pair_find_by_da(vps, attr_sim_sqn, TAG_ANY);
	sqn = sqn_vp ? sqn_vp->vp_uint64 : 2;

	/*
	 *	We default to milenage
	 */
	version_vp = fr_pair_find_by_da(vps, attr_sim_algo_version, TAG_ANY);
	if (version_vp) version = version_vp->vp_uint32;

	for (i = 0; i < SIM_VECTOR_UMTS_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->umts.vector.rand[i], &rand, sizeof(rand));
	}

	switch (version) {
	case 4:
	{
		uint8_t sqn_buff[MILENAGE_SQN_SIZE];

		keys->sqn = sqn_vp ? sqn_vp->vp_uint64 : 0;
		uint48_to_buff(sqn_buff, keys->sqn);

		RDEBUG3("Milenage inputs");
		RINDENT();
		/*
		 *	Don't change colon indent, matches other messages later...
		 */
		RHEXDUMP_INLINE(L_DBG_LVL_3,
				ki_vp->vp_octets, MILENAGE_KI_SIZE,
				"Ki           :");
		RHEXDUMP_INLINE(L_DBG_LVL_3,
				opc_p, MILENAGE_OPC_SIZE,
				"OPc          :");
		RHEXDUMP_INLINE(L_DBG_LVL_3,
				sqn_buff, MILENAGE_SQN_SIZE,
				"SQN          :");
		RHEXDUMP_INLINE(L_DBG_LVL_3,
				amf_buff, MILENAGE_AMF_SIZE,
				"AMF          :");
		REXDENT();

		if (milenage_umts_generate(keys->umts.vector.autn,
					   keys->umts.vector.ik,
					   keys->umts.vector.ck,
					   keys->umts.vector.ak,
					   keys->umts.vector.xres,
					   opc_p,
					   amf_buff,
					   ki_vp->vp_octets,
					   sqn,
					   keys->umts.vector.rand) < 0) {
			RPEDEBUG2("Failed deriving UMTS Quintuplet");
			return -1;
		}

		keys->umts.vector.xres_len = 8;
	}
		return 0;

	case 1:
	case 2:
	case 3:
		REDEBUG("Only Milenage can be used to generate quintuplets");
		return -1;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version);
		return -1;
	}
}

/** Get one set of quintuplets from the request
 *
 */
static int vector_umts_from_quintuplets(eap_session_t *eap_session, VALUE_PAIR *vps, fr_sim_keys_t *keys)
{
	REQUEST		*request = eap_session->request;

	VALUE_PAIR	*rand_vp = NULL, *xres_vp = NULL, *ck_vp = NULL, *ik_vp = NULL;
	VALUE_PAIR	*autn_vp = NULL, *sqn_vp = NULL, *ak_vp = NULL;

	/*
	 *	Fetch AUTN
	 */
	autn_vp = fr_pair_find_by_da(vps, attr_eap_aka_autn, TAG_ANY);
	if (!autn_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_autn->name);
		return 1;
	}

	if (autn_vp->vp_length > SIM_VECTOR_UMTS_AUTN_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_AUTN_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_autn->name, autn_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch CK
	 */
	ck_vp = fr_pair_find_by_da(vps, attr_eap_aka_ck, TAG_ANY);
	if (!ck_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_ck->name);
		return 1;
	}

	if (ck_vp->vp_length > SIM_VECTOR_UMTS_CK_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_ck->name, ck_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch IK
	 */
	ik_vp = fr_pair_find_by_da(vps, attr_eap_aka_ik, TAG_ANY);
	if (!ik_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_ik->name);
		return 1;
	}

	if (ik_vp->vp_length > SIM_VECTOR_UMTS_IK_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(SIM_VECTOR_UMTS_IK_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_ik->name, ik_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch RAND
	 */
	rand_vp = fr_pair_find_by_da(vps, attr_eap_aka_rand, TAG_ANY);
	if (!rand_vp) {
		RDEBUG3("No &control:%s attribute found, not using quintuplet derivation", attr_eap_aka_rand->name);
		return 1;
	}

	if (rand_vp->vp_length != SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected " STRINGIFY(SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", attr_eap_aka_rand->name, rand_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	xres_vp = fr_pair_find_by_da(vps, attr_eap_aka_xres, TAG_ANY);
	if (!xres_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_xres->name);
		return 1;
	}

	if (xres_vp->vp_length > SIM_VECTOR_UMTS_XRES_MAX_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected < "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_xres->name, xres_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch (optional) AK
	 */
	ak_vp = fr_pair_find_by_da(vps, attr_eap_aka_ak, TAG_ANY);
	if (ak_vp && (ak_vp->vp_length != MILENAGE_AK_SIZE)) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(MILENAGE_AK_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_ak->name, ak_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch (optional) SQN
	 */
	sqn_vp = fr_pair_find_by_da(vps, attr_sim_sqn, TAG_ANY);
	if (sqn_vp && (sqn_vp->vp_length != MILENAGE_SQN_SIZE)) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(MILENAGE_AK_SIZE) " bytes, got %zu bytes",
			attr_sim_sqn->name, sqn_vp->vp_length);
		return -1;
	}

	/*
	 *	SQN = AUTN[0..5] ⊕ AK
	 *	AK = AK
	 */
	if (ak_vp && !sqn_vp) {
		keys->sqn = uint48_from_buff(autn_vp->vp_octets) ^ uint48_from_buff(ak_vp->vp_octets);
		memcpy(keys->umts.vector.ak, ak_vp->vp_octets, sizeof(keys->umts.vector.ak));
	/*
	 *	SQN = SQN
	 *	AK = AUTN[0..5] ⊕ SQN
	 */
	} else if (sqn_vp && !ak_vp) {
		keys->sqn = sqn_vp->vp_uint64;
		uint48_to_buff(keys->umts.vector.ak, uint48_from_buff(autn_vp->vp_octets) ^ sqn_vp->vp_uint64);
	/*
	 *	SQN = SQN
	 *	AK = AK
	 */
	} else if (sqn_vp && ak_vp) {
		keys->sqn = sqn_vp->vp_uint64;
		memcpy(keys->umts.vector.ak, ak_vp->vp_octets, sizeof(keys->umts.vector.ak));
	/*
	 *	SQN = AUTN[0..5]
	 *	AK = 0x000000000000
	 */
	} else {
		keys->sqn = uint48_from_buff(autn_vp->vp_octets);
		memset(keys->umts.vector.ak, 0, sizeof(keys->umts.vector.ak));
	}

	memcpy(keys->umts.vector.autn, autn_vp->vp_octets, SIM_VECTOR_UMTS_AUTN_SIZE);
	memcpy(keys->umts.vector.ck, ck_vp->vp_octets, SIM_VECTOR_UMTS_CK_SIZE);
	memcpy(keys->umts.vector.ik, ik_vp->vp_octets, SIM_VECTOR_UMTS_IK_SIZE);
	memcpy(keys->umts.vector.rand, rand_vp->vp_octets, SIM_VECTOR_UMTS_RAND_SIZE);
	memcpy(keys->umts.vector.xres, xres_vp->vp_octets, xres_vp->vp_length);
	keys->umts.vector.xres_len = xres_vp->vp_length;	/* xres is variable length */

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
