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
 * @file src/lib/eap_aka_sim/vector.c
 * @brief Retrieve or derive vectors for EAP-SIM.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/sim/common.h>
#include <freeradius-devel/sim/milenage.h>
#include <freeradius-devel/sim/ts_34_108.h>
#include <freeradius-devel/sim/comp128.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.sim.h>

#include "base.h"
#include "attrs.h"

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

static int vector_gsm_from_ki(REQUEST *request, VALUE_PAIR *vps, int idx, fr_aka_sim_keys_t *keys)
{
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
	 *	Check to see if we have a Ki for the IMSI, this allows us to generate the rest
	 *	of the triplets.
	 */
	version_vp = fr_pair_find_by_da(vps, attr_sim_algo_version, TAG_ANY);
	if (!version_vp) {
		if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;
		version = opc_p ? FR_SIM_ALGO_VERSION_VALUE_COMP128_4 : FR_SIM_ALGO_VERSION_VALUE_COMP128_3;
	/*
	 *	Version was explicitly specified, see if we can find the prerequisite
	 *	attributes.
	 */
	} else {
		version = version_vp->vp_uint32;
		if (version == FR_SIM_ALGO_VERSION_VALUE_COMP128_4) {
			if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;
			if (!opc_p) {
				RPEDEBUG2("No &control:%s or &control:%s found, "
					  "can't run Milenage (COMP128-4)", attr_sim_op->name, attr_sim_opc->name);
				return -1;
			}
		}
	}

	for (i = 0; i < AKA_SIM_VECTOR_GSM_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->gsm.vector[idx].rand[i], &rand, sizeof(rand));
	}

	switch (version) {
	case FR_SIM_ALGO_VERSION_VALUE_COMP128_1:
		comp128v1(keys->gsm.vector[idx].sres,
			  keys->gsm.vector[idx].kc,
			  ki_vp->vp_octets,
			  keys->gsm.vector[idx].rand);
		break;

	case FR_SIM_ALGO_VERSION_VALUE_COMP128_2:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki_vp->vp_octets,
			   keys->gsm.vector[idx].rand, true);
		break;

	case FR_SIM_ALGO_VERSION_VALUE_COMP128_3:
		comp128v23(keys->gsm.vector[idx].sres,
			   keys->gsm.vector[idx].kc,
			   ki_vp->vp_octets,
			   keys->gsm.vector[idx].rand, false);
		break;

	case FR_SIM_ALGO_VERSION_VALUE_COMP128_4:
		if (milenage_gsm_generate(keys->gsm.vector[idx].sres,
					  keys->gsm.vector[idx].kc,
					  opc_p,
					  ki_vp->vp_octets,
					  keys->gsm.vector[idx].rand) < 0) {
			RPEDEBUG2("Failed deriving GSM triplet");
			return -1;
		}
		break;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version);
		return -1;
	}

	/*
	 *	Store for completeness...
	 */
	memcpy(keys->auc.ki, ki_vp->vp_octets, sizeof(keys->auc.ki));
	memcpy(keys->auc.opc, opc_p, sizeof(keys->auc.opc));
	keys->vector_src = AKA_SIM_VECTOR_SRC_KI;

	return 0;
}

static int vector_gsm_from_triplets(REQUEST *request, VALUE_PAIR *vps,
				    int idx, fr_aka_sim_keys_t *keys)
{
	VALUE_PAIR	*rand = NULL, *sres = NULL, *kc = NULL;
	fr_cursor_t	cursor;
	int		i;

	for (i = 0, (kc = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_kc));
	     (i < idx) && (kc = fr_cursor_next(&cursor));
	     i++);
	if (!kc) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_aka_sim_kc->name, idx);
		return 1;
	}
	if (kc->vp_length != AKA_SIM_VECTOR_GSM_KC_SIZE) {
		REDEBUG("&control:%s[%i] is not " STRINGIFY(AKA_SIM_VECTOR_GSM_KC_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_kc->name, idx, kc->vp_length);
		return -1;
	}

	for (i = 0, (rand = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_rand));
	     (i < idx) && (rand = fr_cursor_next(&cursor));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_aka_sim_rand->name, idx);
		return 1;
	}
	if (rand->vp_length != AKA_SIM_VECTOR_GSM_RAND_SIZE) {
		REDEBUG("&control:EAP-SIM-Rand[%i] is not " STRINGIFY(SIM_RAND_SIZE) " bytes, got %zu bytes",
			idx, rand->vp_length);
		return -1;
	}

	for (i = 0, (sres = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_sres));
	     (i < idx) && (sres = fr_cursor_next(&cursor));
	     i++);
	if (!sres) {
		RDEBUG3("No &control:%s[%i] attribute found, not using GSM triplets",
			attr_eap_aka_sim_sres->name, idx);
		return 1;
	}
	if (sres->vp_length != AKA_SIM_VECTOR_GSM_SRES_SIZE) {
		REDEBUG("&control:%s[%i] is not " STRINGIFY(AKA_SIM_VECTOR_GSM_SRES_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_sres->name, idx, sres->vp_length);
		return -1;
	}

	memcpy(keys->gsm.vector[idx].kc, kc->vp_strvalue, AKA_SIM_VECTOR_GSM_KC_SIZE);
	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, AKA_SIM_VECTOR_GSM_RAND_SIZE);
	memcpy(keys->gsm.vector[idx].sres, sres->vp_octets, AKA_SIM_VECTOR_GSM_SRES_SIZE);
	keys->vector_src = AKA_SIM_VECTOR_SRC_TRIPLETS;

	return 0;
}

/** Derive triplets from quintuplets
 *
 */
static int vector_gsm_from_quintuplets(REQUEST *request, VALUE_PAIR *vps,
				       int idx, fr_aka_sim_keys_t *keys)
{
	fr_cursor_t	cursor;

	VALUE_PAIR	*ck = NULL, *ik = NULL, *rand = NULL, *xres = NULL;

	int		i;

	/*
	 *	Fetch CK
	 */
	for (i = 0, (ck = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_ck));
	     (i < idx) && (ck = fr_cursor_next(&cursor));
	     i++);
	if (!ck) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_sim_ck->name, idx);
		return 1;
	}

	/*
	 *	Fetch IK
	 */
	for (i = 0, (ik = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_ik));
	     (i < idx) && (ik = fr_cursor_next(&cursor));
	     i++);
	if (!ik) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_sim_ik->name, idx);
		return 1;
	}

	/*
	 *	Fetch RAND
	 */
	for (i = 0, (rand = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_rand));
	     (i < idx) && (rand = fr_cursor_next(&cursor));
	     i++);
	if (!rand) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_sim_rand->name, idx);
		return 1;
	}

	if (rand->vp_length != AKA_SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:%s[%i] incorrect length.  Expected "
			STRINGIFY(AKA_SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", attr_eap_aka_sim_rand->name, idx, rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	for (i = 0, (xres = fr_cursor_iter_by_da_init(&cursor, &vps, attr_eap_aka_sim_xres));
	     (i < idx) && (xres = fr_cursor_next(&cursor));
	     i++);
	if (!xres) {
		RDEBUG3("No &control:%s[%i] attribute found, not using quintuplet derivation",
			attr_eap_aka_sim_xres->name, idx);
		return 1;
	}

	memcpy(keys->gsm.vector[idx].rand, rand->vp_octets, AKA_SIM_VECTOR_GSM_RAND_SIZE);

	milenage_gsm_from_umts(keys->gsm.vector[idx].sres,
			       keys->gsm.vector[idx].kc,
			       ik->vp_octets,
			       ck->vp_octets,
			       xres->vp_octets);

	keys->vector_src = AKA_SIM_VECTOR_SRC_QUINTUPLETS;

	return 0;
}

/** Retrieve GSM triplets from sets of attributes.
 *
 * Hunt for a source of SIM triplets
 *
 * @param[in] request		The current subrequest.
 * @param[in] vps		List to hunt for triplets in.
 * @param[in] idx		To write EAP-SIM triplets to.
 * @param[in] keys		EAP session keys.
 * @param[in] src		Forces triplets to be retrieved from a particular src
 *				and ensures if multiple triplets are being retrieved
 *				that they all come from the same src.
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
int fr_aka_sim_vector_gsm_from_attrs(REQUEST *request, VALUE_PAIR *vps,
				     int idx, fr_aka_sim_keys_t *keys, fr_aka_sim_vector_src_t *src)
{
	int		ret;

	rad_assert(idx >= 0 && idx < 3);
	rad_assert((keys->vector_type == AKA_SIM_VECTOR_NONE) || (keys->vector_type == AKA_SIM_VECTOR_GSM));

	switch (*src) {
	default:
	case AKA_SIM_VECTOR_SRC_KI:
		ret = vector_gsm_from_ki(request, vps, idx, keys);
		if (ret == 0) {
			*src = AKA_SIM_VECTOR_SRC_KI;
			break;
		}
		if (ret < 0) return -1;
		if (*src != AKA_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case AKA_SIM_VECTOR_SRC_TRIPLETS:
		ret = vector_gsm_from_triplets(request, vps, idx, keys);
		if (ret == 0) {
			*src = AKA_SIM_VECTOR_SRC_TRIPLETS;
			break;
		}
		if (ret < 0) return -1;
		if (*src != AKA_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case AKA_SIM_VECTOR_SRC_QUINTUPLETS:
		ret = vector_gsm_from_quintuplets(request, vps, idx, keys);
		if (ret == 0) {
			*src = AKA_SIM_VECTOR_SRC_QUINTUPLETS;
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
		RHEXDUMP_INLINE2(keys->gsm.vector[idx].kc, AKA_SIM_VECTOR_GSM_KC_SIZE,
				 "KC           :");
		RHEXDUMP_INLINE2(keys->gsm.vector[idx].rand, AKA_SIM_VECTOR_GSM_RAND_SIZE,
				 "RAND         :");
		RHEXDUMP_INLINE2(keys->gsm.vector[idx].sres, AKA_SIM_VECTOR_GSM_SRES_SIZE,
				 "SRES         :");
		REXDENT();
	}

	keys->vector_type = AKA_SIM_VECTOR_GSM;

	return 0;
}

static int vector_umts_from_ki(REQUEST *request, VALUE_PAIR *vps, fr_aka_sim_keys_t *keys)
{
	VALUE_PAIR	*ki_vp, *amf_vp, *sqn_vp, *version_vp;

	size_t		ki_size, amf_size;
	uint32_t	version = FR_SIM_ALGO_VERSION_VALUE_MILENAGE;
	int		i;

	/*
	 *	Select the algorithm (default to Milenage)
	 */
	version_vp = fr_pair_find_by_da(vps, attr_sim_algo_version, TAG_ANY);
	if (version_vp) version = version_vp->vp_uint32;

	/*
	 *	Get expected input sizes
	 */
	switch (version) {
	case FR_SIM_ALGO_VERSION_VALUE_MILENAGE:
		ki_size = MILENAGE_KI_SIZE;
		amf_size = MILENAGE_AMF_SIZE;
		break;

	case FR_SIM_ALGO_VERSION_VALUE_TS_34_108_UMTS:
		ki_size = TS_34_108_KI_SIZE;
		amf_size = TS_34_108_AMF_SIZE;
		break;

	/*
	 *	GSM algos
	 */
	case FR_SIM_ALGO_VERSION_VALUE_COMP128_1:
	case FR_SIM_ALGO_VERSION_VALUE_COMP128_2:
	case FR_SIM_ALGO_VERSION_VALUE_COMP128_3:
	case FR_SIM_ALGO_VERSION_VALUE_COMP128_4:
		REDEBUG("COMP128-* algorithms cannot generate UMTS vectors");
		return -1;

	default:
		REDEBUG("Unknown/unsupported algorithm %i", version);
		return -1;
	}

	/*
	 *	Find the Ki VP and check its length
	 */
	ki_vp = fr_pair_find_by_da(vps, attr_sim_ki, TAG_ANY);
	if (!ki_vp) {
		RDEBUG3("No &control:%s found, not generating quintuplets locally", attr_sim_ki->name);
		return 1;
	} else if (ki_vp->vp_length != ki_size) {
		REDEBUG("&control:%s has incorrect length, expected %zu bytes got %zu bytes",
			attr_sim_ki->name, ki_size, ki_vp->vp_length);
		return -1;
	}

	/*
	 *	Find the Sequence Number VP or default to SQN = 2
	 */
	sqn_vp = fr_pair_find_by_da(vps, attr_sim_sqn, TAG_ANY);
	keys->sqn = sqn_vp ? sqn_vp->vp_uint64 : 2;	/* 2 is the lowest valid SQN on our side */

	/*
	 *	Check if we have an AMF value
	 */
	amf_vp = fr_pair_find_by_da(vps, attr_sim_amf, TAG_ANY);
	if (amf_vp) {
		if (amf_vp->vp_length != amf_size) {
			REDEBUG("&control:%s has incorrect length, expected %zu bytes got %zu bytes",
				attr_sim_amf->name, amf_size, amf_vp->vp_length);
			return -1;
		}
	}

	/*
	 *	Generate rand
	 */
	for (i = 0; i < AKA_SIM_VECTOR_UMTS_RAND_SIZE; i += sizeof(uint32_t)) {
		uint32_t rand = fr_rand();
		memcpy(&keys->umts.vector.rand[i], &rand, sizeof(rand));
	}

	switch (version) {
	case FR_SIM_ALGO_VERSION_VALUE_MILENAGE:
	{
		uint8_t		amf_buff[MILENAGE_AMF_SIZE] = { 0x00, 0x00 };
		uint8_t		sqn_buff[MILENAGE_SQN_SIZE];
		uint8_t 	opc_buff[MILENAGE_OPC_SIZE];
		uint8_t	const	*opc_p;

		if (vector_opc_from_op(request, &opc_p, opc_buff, vps, ki_vp->vp_octets) < 0) return -1;

		uint48_to_buff(sqn_buff, keys->sqn);
		if (amf_vp) memcpy(amf_buff, amf_vp->vp_octets, amf_size);

		RDEBUG3("Milenage inputs");
		RINDENT();
		/*
		 *	Don't change colon indent, matches other messages later...
		 */
		RHEXDUMP_INLINE3(ki_vp->vp_octets, ki_size,
				 "Ki           :");
		RHEXDUMP_INLINE3(opc_p, sizeof(opc_buff),
				 "OPc          :");
		RHEXDUMP_INLINE3(sqn_buff, sizeof(sqn_buff),
				 "SQN          :");
		RHEXDUMP_INLINE3(amf_buff, sizeof(amf_buff),
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
					   keys->sqn,
					   keys->umts.vector.rand) < 0) {
			RPEDEBUG2("Failed deriving UMTS Quintuplet");
			return -1;
		}
		keys->umts.vector.xres_len = MILENAGE_RES_SIZE;

		/*
		 *	Store the keys we used for possible AUTS
		 *	validation later.
		 */
		memcpy(keys->auc.ki, ki_vp->vp_octets, sizeof(keys->auc.ki));
		memcpy(keys->auc.opc, opc_p, sizeof(keys->auc.opc));
		keys->vector_src = AKA_SIM_VECTOR_SRC_KI;
	}
		return 0;

	/*
	 *	This is a dummy algorithm and should be used for testing
	 *	purposes only.  It offers no security and can be trivially
	 *	broken and the original Ki retrieved.
	 */
	case FR_SIM_ALGO_VERSION_VALUE_TS_34_108_UMTS:
	{
		uint8_t		amf_buff[TS_34_108_AMF_SIZE] = { 0x00, 0x00 };
		uint8_t		sqn_buff[TS_34_108_SQN_SIZE];

		uint48_to_buff(sqn_buff, keys->sqn);

		if (amf_vp) memcpy(amf_buff, amf_vp->vp_octets, amf_size);

		RDEBUG3("TS-34-108-UMTS inputs");
		RINDENT();
		/*
		 *	Don't change colon indent, matches other messages later...
		 */
		RHEXDUMP_INLINE3(
				ki_vp->vp_octets, ki_size,
				"Ki           :");
		RHEXDUMP_INLINE3(
				sqn_buff, sizeof(sqn_buff),
				"SQN          :");
		RHEXDUMP_INLINE3(
				amf_buff, sizeof(amf_buff),
				"AMF          :");
		REXDENT();

		if (ts_34_108_umts_generate(keys->umts.vector.autn,
					    keys->umts.vector.ik,
					    keys->umts.vector.ck,
					    keys->umts.vector.ak,
					    keys->umts.vector.xres,
					    amf_buff,
					    ki_vp->vp_octets,
					    keys->sqn,
					    keys->umts.vector.rand) < 0) {
			RPEDEBUG2("Failed deriving UMTS Quintuplet");
			return -1;
		}
		keys->umts.vector.xres_len = TS_34_108_RES_SIZE;

		/*
		 *	Store the keys we used for possible AUTS
		 *	validation later.
		 */
		memcpy(keys->auc.ki, ki_vp->vp_octets, sizeof(keys->auc.ki));
		keys->vector_src = AKA_SIM_VECTOR_SRC_KI;
	}
		return 0;

	default:
		rad_assert(0);
		return -1;
	}
}

/** Get one set of quintuplets from the request
 *
 */
static int vector_umts_from_quintuplets(REQUEST *request, VALUE_PAIR *vps, fr_aka_sim_keys_t *keys)
{
	VALUE_PAIR	*rand_vp = NULL, *xres_vp = NULL, *ck_vp = NULL, *ik_vp = NULL;
	VALUE_PAIR	*autn_vp = NULL, *sqn_vp = NULL, *ak_vp = NULL;

	/*
	 *	Fetch AUTN
	 */
	autn_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_autn, TAG_ANY);
	if (!autn_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_sim_autn->name);
		return 1;
	}

	if (autn_vp->vp_length > AKA_SIM_VECTOR_UMTS_AUTN_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(AKA_SIM_VECTOR_UMTS_AUTN_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_autn->name, autn_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch CK
	 */
	ck_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_ck, TAG_ANY);
	if (!ck_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_sim_ck->name);
		return 1;
	}

	if (ck_vp->vp_length > AKA_SIM_VECTOR_UMTS_CK_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_ck->name, ck_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch IK
	 */
	ik_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_ik, TAG_ANY);
	if (!ik_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_sim_ik->name);
		return 1;
	}

	if (ik_vp->vp_length > AKA_SIM_VECTOR_UMTS_IK_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(AKA_SIM_VECTOR_UMTS_IK_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_ik->name, ik_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch RAND
	 */
	rand_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_rand, TAG_ANY);
	if (!rand_vp) {
		RDEBUG3("No &control:%s attribute found, not using quintuplet derivation", attr_eap_aka_sim_rand->name);
		return 1;
	}

	if (rand_vp->vp_length != AKA_SIM_VECTOR_UMTS_RAND_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected " STRINGIFY(AKA_SIM_VECTOR_UMTS_RAND_SIZE) " bytes, "
			"got %zu bytes", attr_eap_aka_sim_rand->name, rand_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	xres_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_xres, TAG_ANY);
	if (!xres_vp) {
		RDEBUG3("No &control:%s attribute found, not using UMTS quintuplets", attr_eap_aka_sim_xres->name);
		return 1;
	}

	if (xres_vp->vp_length > AKA_SIM_VECTOR_UMTS_XRES_MAX_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected < "
			STRINGIFY(EAP_AKA_XRES_MAX_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_xres->name, xres_vp->vp_length);
		return -1;
	}

	/*
	 *	Fetch (optional) AK
	 */
	ak_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_ak, TAG_ANY);
	if (ak_vp && (ak_vp->vp_length != MILENAGE_AK_SIZE)) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(MILENAGE_AK_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_ak->name, ak_vp->vp_length);
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

	memcpy(keys->umts.vector.autn, autn_vp->vp_octets, AKA_SIM_VECTOR_UMTS_AUTN_SIZE);
	memcpy(keys->umts.vector.ck, ck_vp->vp_octets, AKA_SIM_VECTOR_UMTS_CK_SIZE);
	memcpy(keys->umts.vector.ik, ik_vp->vp_octets, AKA_SIM_VECTOR_UMTS_IK_SIZE);
	memcpy(keys->umts.vector.rand, rand_vp->vp_octets, AKA_SIM_VECTOR_UMTS_RAND_SIZE);
	memcpy(keys->umts.vector.xres, xres_vp->vp_octets, xres_vp->vp_length);
	keys->umts.vector.xres_len = xres_vp->vp_length;	/* xres is variable length */

	keys->vector_src = AKA_SIM_VECTOR_SRC_QUINTUPLETS;

	return 0;
}

/** Retrieve UMTS quintuplets from sets of attributes.
 *
 * Hunt for a source of UMTS quintuplets
 *
 * @param request		The current request.
 * @param vps			List to hunt for triplets in.
 * @param keys			UMTS keys.
 * @param src			Forces quintuplets to be retrieved from a particular src.
 *
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
int fr_aka_sim_vector_umts_from_attrs(REQUEST *request, VALUE_PAIR *vps,
				      fr_aka_sim_keys_t *keys, fr_aka_sim_vector_src_t *src)
{
	int		ret;

	rad_assert((keys->vector_type == AKA_SIM_VECTOR_NONE) || (keys->vector_type == AKA_SIM_VECTOR_UMTS));

	switch (*src) {
	default:
	case AKA_SIM_VECTOR_SRC_KI:
		ret = vector_umts_from_ki(request, vps, keys);
		if (ret == 0) {
			*src = AKA_SIM_VECTOR_SRC_KI;
			break;
		}
		if (ret < 0) return -1;
		if (*src != AKA_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case AKA_SIM_VECTOR_SRC_QUINTUPLETS:
		ret = vector_umts_from_quintuplets(request, vps, keys);
		if (ret == 0) {
			*src = AKA_SIM_VECTOR_SRC_QUINTUPLETS;
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
		RHEXDUMP_INLINE2(keys->umts.vector.autn, AKA_SIM_VECTOR_UMTS_AUTN_SIZE,
				 "AUTN         :");
		RHEXDUMP_INLINE2(keys->umts.vector.ck, AKA_SIM_VECTOR_UMTS_CK_SIZE,
				 "CK           :");
		RHEXDUMP_INLINE2(keys->umts.vector.ik, AKA_SIM_VECTOR_UMTS_IK_SIZE,
				 "IK           :");
		RHEXDUMP_INLINE2(keys->umts.vector.rand, AKA_SIM_VECTOR_UMTS_RAND_SIZE,
				 "RAND         :");
		RHEXDUMP_INLINE2(keys->umts.vector.xres, keys->umts.vector.xres_len,
				 "XRES         :");
		REXDENT();
	}

	keys->vector_type = AKA_SIM_VECTOR_UMTS;

	return 0;
}

/** Populate a fr_aka_sim_keys_t structure from attributes in the session-state list
 *
 * @param[in] request	The current request.
 * @param[in] vps	Session-state list
 * @param[in] keys	key structure to populate.
 * @return
 *	- 1 if we do not have sufficient data.
 *	- 0 on success.
 *	- -1 on validation failure.
 */
int fr_aka_sim_vector_gsm_umts_kdf_0_reauth_from_attrs(REQUEST *request, VALUE_PAIR *vps, fr_aka_sim_keys_t *keys)
{
	VALUE_PAIR *counter_vp;
	VALUE_PAIR *mk_vp;

	/*
	 *	This is the *old* counter value increment
	 *	by 1 to get the *new* counter value
	 */
	counter_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_counter, TAG_ANY);
	if (!counter_vp) {
		RDEBUG2("No &session-state:%s attribute found, can't calculate re-auth keys",
			attr_eap_aka_sim_counter->name);
		return 1;
	}
	counter_vp->vp_uint16++;

	mk_vp = fr_pair_find_by_da(vps, attr_session_data, TAG_ANY);
	if (!mk_vp) mk_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_mk, TAG_ANY);
	if (!mk_vp) {
		RDEBUG2("Neither &session-state:%s or &session-state:%s attributes found, "
			"can't calculate re-auth keys", attr_session_data->name, attr_eap_aka_sim_mk->name);
		return 1;
	}

	if (mk_vp->vp_length != AKA_SIM_MK_SIZE) {
		REDEBUG("&session-state:%s incorrect length.  Expected "
			STRINGIFY(AKA_SIM_MK_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_mk->name, mk_vp->vp_length);
		return -1;
	}

	fr_aka_sim_crypto_keys_init_kdf_0_reauth(keys, mk_vp->vp_octets, counter_vp->vp_uint16);

	keys->vector_type = AKA_SIM_VECTOR_UMTS_REAUTH_KDF_0_REAUTH;	/* Didn't come from a vector */
	keys->vector_src = AKA_SIM_VECTOR_SRC_REAUTH;

	return 0;
}

/** Populate a fr_aka_sim_keys_t structure from attributes in the session-state list
 *
 * @param[in] request	The current request.
 * @param[in] vps	Session-state list
 * @param[in] keys	key structure to populate.
 * @return
 *	- 1 if we do not have sufficient data.
 *	- 0 on success.
 *	- -1 on validation failure.
 */
int fr_aka_sim_vector_umts_kdf_1_reauth_from_attrs(REQUEST *request, VALUE_PAIR *vps, fr_aka_sim_keys_t *keys)
{
	VALUE_PAIR *counter_vp;
	VALUE_PAIR *k_re_vp;

	/*
	 *	This is the *old* counter value increment
	 *	by 1 to get the *new* counter value
	 */
	counter_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_counter, TAG_ANY);
	if (!counter_vp) {
		RDEBUG2("No &session-state:%s attribute found, can't calculate re-auth keys",
			attr_eap_aka_sim_counter->name);
		return 1;
	}
	counter_vp->vp_uint16++;

	k_re_vp = fr_pair_find_by_da(vps, attr_session_data, TAG_ANY);
	if (!k_re_vp) k_re_vp = fr_pair_find_by_da(vps, attr_eap_aka_sim_k_re, TAG_ANY);
	if (!k_re_vp) {
		RDEBUG2("Neither &session-state:%s or &session-sate:%s attributes found, "
			"can't calculate re-auth keys", attr_session_data->name, attr_eap_aka_sim_k_re->name);
		return 1;
	}

	if (k_re_vp->vp_length != AKA_SIM_K_RE_SIZE) {
		REDEBUG("&session-state:%s incorrect length.  Expected "
			STRINGIFY(AKA_SIM_K_RE_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_mk->name, k_re_vp->vp_length);
		return -1;
	}

	fr_aka_sim_crypto_keys_init_umts_kdf_1_reauth(keys, k_re_vp->vp_octets, counter_vp->vp_uint16);

	keys->vector_type = AKA_SIM_VECTOR_UMTS_REAUTH_KDF_1_REAUTH;	/* Didn't come from a vector */
	keys->vector_src = AKA_SIM_VECTOR_SRC_REAUTH;

	return 0;
}

/** Clear reauth data if reauthentication failed
 *
 * @param[in] keys	key structure to clear.
 */
void fr_aka_sim_vector_umts_reauth_clear(fr_aka_sim_keys_t *keys)
{
	memset(&keys->reauth, 0, sizeof(keys->reauth));
	keys->vector_src = 0;
	keys->vector_type = 0;
}

/** Perform milenage AUTS validation and resynchronisation
 *
 * @param[out] new_sqn	The new sequence number provided by the AUTS.
 * @param[in] request	The current request.
 * @param[in] auts_vp	The AUTS response.
 * @param[in] keys	UMTS keys.
 * @return
 *	- 1 if we do not have sufficient data (lacking ki).
 *	- 0 on success.
 *	- -1 on validation failure.
 */
int fr_aka_sim_umts_resync_from_attrs(uint64_t *new_sqn,
				      REQUEST *request, VALUE_PAIR *auts_vp, fr_aka_sim_keys_t *keys)
{
	if (keys->vector_src != AKA_SIM_VECTOR_SRC_KI) {
		RDEBUG2("Original vectors were not generated locally, cannot perform AUTS validation");
		return 1;
	}

	if (auts_vp->vp_length != MILENAGE_AUTS_SIZE) {
		REDEBUG("&control:%s incorrect length.  Expected "
			STRINGIFY(MILENAGE_AUTS_SIZE) " bytes, got %zu bytes",
			attr_eap_aka_sim_auts->name, auts_vp->vp_length);
		return -1;
	}

	if (milenage_auts(new_sqn, keys->auc.opc, keys->auc.ki, keys->umts.vector.rand, auts_vp->vp_octets) < 0) {
		REDEBUG("AUTS validation failed");
		return -1;
	}

	RDEBUG2("AUTS validation success, new SQN %"PRIu64, *new_sqn);

	return 0;
}
