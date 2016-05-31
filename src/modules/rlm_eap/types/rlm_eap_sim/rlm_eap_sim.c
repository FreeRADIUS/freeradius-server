/*
 * rlm_eap_sim.c    Handles that are called from eap for SIM
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * Version:     $Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2003  Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright 2003,2006  The FreeRADIUS server project
 *
 */

RCSID("$Id$")

#include <stdio.h>
#include <stdlib.h>

#include "../../eap.h"
#include "eap_types.h"
#include "eap_sim.h"
#include "comp128.h"

#include <freeradius-devel/rad_assert.h>

typedef struct eap_sim_server_state {
	eap_sim_server_states_t state;
	eap_sim_keys_t		keys;
	int  			sim_id;
} eap_sim_state_t;

typedef enum {
	EAP_SIM_VECTOR_SRC_AUTO,
	EAP_SIM_VECTOR_SRC_GSM,
	EAP_SIM_VECTOR_SRC_UMTS,
	EAP_SIM_VECTOR_SRC_KI
} eap_sim_vector_src_t;

/*
 *	build a reply to be sent.
 */
static int eap_sim_compose(eap_session_t *eap_session)
{
	/* we will set the ID on requests, since we have to HMAC it */
	eap_session->this_round->set_request_id = true;

	return eap_sim_encode(eap_session->request->reply,
				     eap_session->this_round->request);
}

static int eap_sim_send_state(eap_session_t *eap_session)
{
	VALUE_PAIR **vps, *newvp;
	uint16_t words[3];
	eap_sim_state_t *ess;
	RADIUS_PACKET *packet;
	uint8_t *p;

	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);

	/* these are the outgoing attributes */
	packet = eap_session->request->reply;
	vps = &packet->vps;
	rad_assert(vps != NULL);


	/*
	 *	Add appropriate TLVs for the EAP things we wish to send.
	 */

	/* the version list. We support only version 1. */
	words[0] = htons(sizeof(words[1]));
	words[1] = htons(EAP_SIM_VERSION);
	words[2] = 0;

	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_VERSION_LIST);
	fr_pair_value_memcpy(newvp, (uint8_t const *) words, sizeof(words));

	fr_pair_add(vps, newvp);

	/* set the EAP_ID - new value */
	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_ID);
	newvp->vp_integer = ess->sim_id++;
	fr_pair_replace(vps, newvp);

	/* record it in the ess */
	ess->keys.versionlistlen = 2;
	memcpy(ess->keys.versionlist, words + 1, ess->keys.versionlistlen);

	/* the ANY_ID attribute. We do not support re-auth or pseudonym */
	MEM(newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_FULLAUTH_ID_REQ));
	MEM(p = talloc_array(newvp, uint8_t, 2));
	p[0] = 0;
	p[1] = 1;
	fr_pair_value_memsteal(newvp, p);
	fr_pair_add(vps, newvp);

	/* the SUBTYPE, set to start. */
	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_SUBTYPE);
	newvp->vp_integer = EAPSIM_START;
	fr_pair_replace(vps, newvp);

	return 1;
}

static int eap_sim_vector_from_ki(eap_session_t *eap_session, VALUE_PAIR *vps, int idx, eap_sim_state_t *ess)
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

	for (i = 0; i < EAPSIM_RAND_SIZE; i++) {
		ess->keys.rand[idx][i] = fr_rand();
	}

	switch (version->vp_integer) {
	case 1:
		comp128v1(ess->keys.sres[idx], ess->keys.kc[idx], vp->vp_octets, ess->keys.rand[idx]);
		break;

	case 2:
		comp128v23(ess->keys.sres[idx], ess->keys.kc[idx], vp->vp_octets, ess->keys.rand[idx], true);
		break;

	case 3:
		comp128v23(ess->keys.sres[idx], ess->keys.kc[idx], vp->vp_octets, ess->keys.rand[idx], false);
		break;

	case 4:
		REDEBUG("Milenage not supported (feel free to implement it)");
		return 1;

	default:
		REDEBUG("Unknown/unsupported algorithm Comp128-%i", version->vp_integer);
	}

	if (RDEBUG_ENABLED2) {
		char buffer[33];	/* 32 hexits (16 bytes) + 1 */
		char *p;

		RDEBUG2("Generated following triplets for round %i:", idx);

		RINDENT();
		p = buffer;
		for (i = 0; i < EAPSIM_RAND_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.rand[idx][i]);
		}
		RDEBUG2("RAND : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAPSIM_SRES_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.sres[idx][i]);
		}
		RDEBUG2("SRES : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAPSIM_KC_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.kc[idx][i]);
		}
		RDEBUG2("Kc   : 0x%s", buffer);
		REXDENT();
	}
	return 0;
}

static int eap_sim_vector_from_gsm(eap_session_t *eap_session, VALUE_PAIR *vps, int idx, eap_sim_state_t *ess)
{
	REQUEST	*request = eap_session->request;
	VALUE_PAIR *vp;

	/*
	 *	Use known RAND, SRES, and Kc values, these may of been pulled in from an AuC,
	 *	or created by sending challenges to the SIM directly.
	 */
	vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_RAND1 + idx, TAG_ANY);
	if (!vp) {
		RDEBUG3("No &control:EAP-SIM-RAND attribute found, not using triplets");
		return 1;
	}

	if (vp->vp_length != EAPSIM_RAND_SIZE) {
		REDEBUG("&control:EAP-SIM-RAND%i is not " STRINGIFY(EAPSIM_RAND_SIZE) " bytes, got %zu bytes",
			idx + 1, vp->vp_length);
		return -1;
	}
	memcpy(ess->keys.rand[idx], vp->vp_octets, EAPSIM_RAND_SIZE);

	vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_SRES1 + idx, TAG_ANY);
	if (!vp) {
		RDEBUG3("No &control:EAP-SIM-SRES attribute found, not using triplets");
		return 1;
	}

	if (vp->vp_length != EAPSIM_SRES_SIZE) {
		REDEBUG("&control:EAP-SIM-SRES%i is not " STRINGIFY(EAPSIM_SRES_SIZE) " bytes, got %zu bytes",
			idx + 1, vp->vp_length);
		return -1;
	}
	memcpy(ess->keys.sres[idx], vp->vp_octets, EAPSIM_SRES_SIZE);

	vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_KC1 + idx, TAG_ANY);
	if (!vp) {
		RDEBUG3("No &control:EAP-SIM-KC attribute found, not using triplets");
		return 1;
	}

	if (vp->vp_length != EAPSIM_KC_SIZE) {
		REDEBUG("&control:EAP-SIM-Kc%i is not 8 bytes, got %zu bytes", idx + 1, vp->vp_length);
		return -1;
	}
	memcpy(ess->keys.kc[idx], vp->vp_octets, EAPSIM_KC_SIZE);
	if (vp->vp_length != EAPSIM_KC_SIZE) {
		REDEBUG("&control:EAP-SIM-Kc%i is not " STRINGIFY(EAPSIM_KC_SIZE) " bytes, got %zu bytes",
			idx + 1, vp->vp_length);
		return -1;
	}
	memcpy(ess->keys.kc[idx], vp->vp_strvalue, EAPSIM_KC_SIZE);

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
static int eap_sim_vector_from_umts(eap_session_t *eap_session, VALUE_PAIR *vps, int idx, eap_sim_state_t *ess)
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
	for (i = 0, fr_cursor_init(&cursor, &vps); i < idx; i++) {
		rand = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_RAND, TAG_ANY);
		if (!rand) break;
	}
	if (!rand) {
		RDEBUG3("No &control:EAP-AKA-Rand attribute found, not using quintuplet derivation");
		return 1;
	}

	if (rand->vp_length != EAPSIM_RAND_SIZE) {
		REDEBUG("&control:EAP-AKA-RAND incorrect length.  Expected " STRINGIFY(EAPSIM_RAND_SIZE) " bytes, "
			"got %zu bytes", rand->vp_length);
		return -1;
	}

	/*
	 *	Fetch XRES
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps); i < idx; i++) {
		xres = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_XRES, TAG_ANY);
		if (!xres) break;
	}
	if (!xres) {
		RDEBUG3("No &control:EAP-AKA-XRES attribute found, not using quintuplet derivation");
		return 1;
	}

	/*
	 *	Fetch CK
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps); i < idx; i++) {
		ck = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_CK, TAG_ANY);
		if (!ck) break;
	}
	if (!ck) {
		RDEBUG3("No &control:EAP-AKA-CK attribute found, not using quintuplet derivation");
		return 1;
	}

	/*
	 *	Fetch IK
	 */
	for (i = 0, fr_cursor_init(&cursor, &vps); i < idx; i++) {
		ik = fr_cursor_next_by_num(&cursor, 0, PW_EAP_AKA_IK, TAG_ANY);
		if (!ik) break;
	}
	if (!ik) {
		RDEBUG3("No &control:EAP-AKA-IK attribute found, not using quintuplet derivation");
		return 1;
	}

	memcpy(ess->keys.rand[idx], rand->vp_octets, EAPSIM_RAND_SIZE);	/* RAND is 128 bits in both */

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
	 *	Fold xres into itself in 32bit quantities using xor to
	 *	produce sres.
	 */
	ess->keys.sres_uint32[idx] = ((xres_ptr[0] ^ xres_ptr[1]) ^ xres_ptr[2]) ^ xres_ptr[3];

	/*
	 *	Fold CK and IK in 64bit quantities to produce Kc
	 */
	ck_ptr = (uint64_t const *)ck->vp_octets;
	ik_ptr = (uint64_t const *)ik->vp_octets;
	ess->keys.kc_uint64[idx] = ((ck_ptr[0] ^ ck_ptr[1]) ^ ik_ptr[0]) ^ ik_ptr[1];

	if (RDEBUG_ENABLED2) {
		char buffer[33];	/* 32 hexits (16 bytes) + 1 */
		char *p;

		RDEBUG2("Derived following triplets from UMTS for round %i:", idx);

		RINDENT();
		p = buffer;
		for (i = 0; i < EAPSIM_RAND_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.rand[idx][i]);
		}
		RDEBUG2("RAND : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAPSIM_SRES_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.sres[idx][i]);
		}
		RDEBUG2("SRES : 0x%s", buffer);

		p = buffer;
		for (i = 0; i < EAPSIM_KC_SIZE; i++) {
			p += sprintf(p, "%02x", ess->keys.kc[idx][i]);
		}
		RDEBUG2("Kc   : 0x%s", buffer);
		REXDENT();
	}

	return 0;
}

/** Retrieve GSM triplets from various locations
 *
 * Hunt for a source of SIM triplets
 *
 * @param eap_session	The current eap_session.
 * @param vps		List to hunt for triplets in.
 * @param idx		To write EAP-SIM triplets to.
 * @param ess		EAP session state.
 * @param src		Forces triplets to be retrieved from a particular src
 *			and ensures if multiple triplets are being retrieved
 *			that they all come from the same src.
 * @return
 *	- 1	Vector could not be retrieved from the specified src.
 *	- 0	Vector was retrieved OK and written to the specified index.
 *	- -1	Error retrieving vector from the specified src.
 */
static int eap_sim_get_challenge(eap_session_t *eap_session, VALUE_PAIR *vps,
				 int idx, eap_sim_state_t *ess, eap_sim_vector_src_t *src)
{

	int ret;

	rad_assert(idx >= 0 && idx < 3);

	switch (*src) {
	default:
	case EAP_SIM_VECTOR_SRC_KI:
		ret = eap_sim_vector_from_ki(eap_session, vps, idx, ess);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_KI;
			return 0;
		}
		if (ret < 0) return -1;
		if (*src != EAP_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case EAP_SIM_VECTOR_SRC_GSM:
		ret = eap_sim_vector_from_gsm(eap_session, vps, idx, ess);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_GSM;
			return 0;
		}
		if (ret < 0) return -1;
		if (*src != EAP_SIM_VECTOR_SRC_AUTO) return 1;
		/* FALL-THROUGH */

	case EAP_SIM_VECTOR_SRC_UMTS:
		ret = eap_sim_vector_from_umts(eap_session, vps, idx, ess);
		if (ret == 0) {
			*src = EAP_SIM_VECTOR_SRC_UMTS;
			return 0;
		}
		if (ret < 0) return -1;
		return 1;
	}
}

/** Send the challenge itself
 *
 * Challenges will come from one of three places eventually:
 *
 * 1  from attributes like PW_EAP_SIM_RANDx
 *	    (these might be retrieved from a database)
 *
 * 2  from internally implemented SIM authenticators
 *	    (a simple one based upon XOR will be provided)
 *
 * 3  from some kind of SS7 interface.
 *
 * For now, they only come from attributes.
 * It might be that the best way to do 2/3 will be with a different
 * module to generate/calculate things.
 *
 */
static int eap_sim_send_challenge(eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;
	eap_sim_state_t *ess;
	VALUE_PAIR **invps, **outvps, *newvp;
	RADIUS_PACKET *packet;
	uint8_t *p, *rand;

	ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);
	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	/*
	 *	Invps is the data from the client but this is for non-protocol data here.
	 *	We should already have consumed any client originated data.
	 */
	invps = &eap_session->request->packet->vps;

	/*
	 *	Outvps is the data to the client
	 */
	packet = eap_session->request->reply;
	outvps = &packet->vps;

	if (RDEBUG_ENABLED2) {
		RDEBUG2("EAP-SIM decoded packet");
		rdebug_pair_list(L_DBG_LVL_2, request, *invps, NULL);
	}

	/*
	 *	Okay, we got the challenges! Put them into an attribute.
	 */
	MEM(newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_RAND));
	MEM(p = rand = talloc_array(newvp, uint8_t, 2 + (EAPSIM_RAND_SIZE * 3)));
	memset(p, 0, 2); /* clear reserved bytes */
	p += 2;
	memcpy(p, ess->keys.rand[0], EAPSIM_RAND_SIZE);
	p += EAPSIM_RAND_SIZE;
	memcpy(p, ess->keys.rand[1], EAPSIM_RAND_SIZE);
	p += EAPSIM_RAND_SIZE;
	memcpy(p, ess->keys.rand[2], EAPSIM_RAND_SIZE);
	fr_pair_value_memsteal(newvp, rand);
	fr_pair_add(outvps, newvp);

	/*
	 *	Set the EAP_ID - new value
	 */
	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_ID);
	newvp->vp_integer = ess->sim_id++;
	fr_pair_replace(outvps, newvp);

	/*
	 *	Make a copy of the identity
	 */
	ess->keys.identitylen = strlen(eap_session->identity);
	memcpy(ess->keys.identity, eap_session->identity, ess->keys.identitylen);

	/*
	 *	Use the SIM identity, if available
	 */
	newvp = fr_pair_find_by_num(*invps, 0, PW_EAP_SIM_IDENTITY, TAG_ANY);
	if (newvp && newvp->vp_length > 2) {
		uint16_t len;

		memcpy(&len, newvp->vp_octets, sizeof(uint16_t));
		len = ntohs(len);
		if (len <= newvp->vp_length - 2 && len <= FR_MAX_STRING_LEN) {
			ess->keys.identitylen = len;
			memcpy(ess->keys.identity, newvp->vp_octets + 2, ess->keys.identitylen);
		}
	}

	/*
	 *	All set, calculate keys!
	 */
	eap_sim_calculate_keys(&ess->keys);

#ifdef EAP_SIM_DEBUG_PRF
	eap_sim_dump_mk(&ess->keys);
#endif

	/*
	 *	Need to include an AT_MAC attribute so that it will get
	 *	calculated. The NONCE_MT and the MAC are both 16 bytes, so
	 *	We store the NONCE_MT in the MAC for the encoder, which
	 *	will pull it out before it does the operation.
	 */
	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_MAC);
	fr_pair_value_memcpy(newvp, ess->keys.nonce_mt, 16);
	fr_pair_replace(outvps, newvp);

	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_KEY);
	fr_pair_value_memcpy(newvp, ess->keys.K_aut, 16);
	fr_pair_replace(outvps, newvp);

	/* the SUBTYPE, set to challenge. */
	newvp = fr_pair_afrom_num(packet, 0, PW_EAP_SIM_SUBTYPE);
	newvp->vp_integer = EAPSIM_CHALLENGE;
	fr_pair_replace(outvps, newvp);

	return 1;
}

#ifndef EAPTLS_MPPE_KEY_LEN
#define EAPTLS_MPPE_KEY_LEN     32
#endif

/*
 * this code sends the success message.
 *
 * the only work to be done is the add the appropriate SEND/RECV
 * radius attributes derived from the MSK.
 *
 */
static int eap_sim_send_success(eap_session_t *eap_session)
{
	unsigned char *p;
	eap_sim_state_t *ess;
	VALUE_PAIR *vp;
	RADIUS_PACKET *packet;

	/* outvps is the data to the client. */
	packet = eap_session->request->reply;
	ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);

	/* set the EAP_ID - new value */
	vp = fr_pair_afrom_num(packet, 0, PW_EAP_ID);
	vp->vp_integer = ess->sim_id++;
	fr_pair_replace(&eap_session->request->reply->vps, vp);

	p = ess->keys.msk;
	eap_add_reply(eap_session->request, "MS-MPPE-Recv-Key", p, EAPTLS_MPPE_KEY_LEN);
	p += EAPTLS_MPPE_KEY_LEN;
	eap_add_reply(eap_session->request, "MS-MPPE-Send-Key", p, EAPTLS_MPPE_KEY_LEN);

	return 1;
}


/** Run the server state machine
 *
 */
static void eap_sim_state_enter(eap_session_t *eap_session,
				eap_sim_state_t *ess,
				enum eap_sim_server_states newstate)
{
	switch (newstate) {
	/*
	 * 	Send the EAP-SIM Start message, listing the versions that we support.
	 */
	case EAPSIM_SERVER_START:
		eap_sim_send_state(eap_session);
		break;
	/*
	 *	Send the EAP-SIM Challenge message.
	 */
	case EAPSIM_SERVER_CHALLENGE:
		eap_sim_send_challenge(eap_session);
		break;

	/*
	 * 	Send the EAP Success message
	 */
	case EAPSIM_SERVER_SUCCESS:
		eap_sim_send_success(eap_session);
		eap_session->this_round->request->code = PW_EAP_SUCCESS;
		break;
	/*
	 *	Nothing to do for this transition.
	 */
	default:
		break;
	}

	ess->state = newstate;

	/* build the target packet */
	eap_sim_compose(eap_session);
}


static int CC_HINT(nonnull) mod_process(void *instance, eap_session_t *eap_session);

/*
 *	Initiate the EAP-SIM session by starting the state machine
 *      and initiating the state.
 */
static int mod_session_init(UNUSED void *instance, eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;
	eap_sim_state_t *ess;
	time_t n;
	eap_sim_vector_src_t src = EAP_SIM_VECTOR_SRC_AUTO;

	ess = talloc_zero(eap_session, eap_sim_state_t);
	if (!ess) {
		RDEBUG2("No space for EAP-SIM state");
		return 0;
	}

	eap_session->opaque = ess;

	/*
	 *	Save the keying material, because it could change on a subsequent retrieval.
	 */
	if ((eap_sim_get_challenge(eap_session, request->control, 0, ess, &src) != 0) ||
	    (eap_sim_get_challenge(eap_session, request->control, 1, ess, &src) < 0) ||
	    (eap_sim_get_challenge(eap_session, request->control, 2, ess, &src) < 0)) {
	    	REDEBUG("Failed retrieving SIM triplets");
		return 0;
	}

	/*
	 *	This value doesn't have be strong, but it is good if it is different now and then.
	 */
	time(&n);
	ess->sim_id = (n & 0xff);

	eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_START);

	eap_session->process = mod_process;

	return 1;
}


/** Process an EAP-Sim/Response/Start
 *
 * Verify that client chose a version, and provided a NONCE_MT,
 * and if so, then change states to challenge, and send the new
 * challenge, else, resend the Request/Start.
 */
static int process_eap_sim_start(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST *request = eap_session->request;
	VALUE_PAIR *nonce_vp, *selectedversion_vp;
	eap_sim_state_t *ess;
	uint16_t simversion;
	ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);

	nonce_vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_NONCE_MT, TAG_ANY);
	selectedversion_vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_SELECTED_VERSION, TAG_ANY);
	if (!nonce_vp || !selectedversion_vp) {
		RDEBUG2("Client did not select a version and send a NONCE");
		eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_START);

		return 1;
	}

	/*
	 *	Okay, good got stuff that we need. Check the version we found.
	 */
	if (selectedversion_vp->vp_length < 2) {
		REDEBUG("EAP-SIM version field is too short");
		return 0;
	}
	memcpy(&simversion, selectedversion_vp->vp_strvalue, sizeof(simversion));
	simversion = ntohs(simversion);
	if (simversion != EAP_SIM_VERSION) {
		REDEBUG("EAP-SIM version %i is unknown", simversion);
		return 0;
	}

	/*
	 *	Record it for later keying
	 */
	memcpy(ess->keys.versionselect, selectedversion_vp->vp_strvalue, sizeof(ess->keys.versionselect));

	/*
	 *	Double check the nonce size.
	 */
	if(nonce_vp->vp_length != 18) {
		REDEBUG("EAP-SIM nonce_mt must be 16 bytes (+2 bytes padding), not %zu", nonce_vp->vp_length);
		return 0;
	}
	memcpy(ess->keys.nonce_mt, nonce_vp->vp_strvalue + 2, 16);

	/*
	 *	Everything looks good, change states
	 */
	eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_CHALLENGE);

	return 1;
}


/** Process an EAP-Sim/Response/Challenge
 *
 * Verify that MAC that we received matches what we would have
 * calculated from the packet with the SRESx appended.
 *
 */
static int process_eap_sim_challenge(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST *request = eap_session->request;
	eap_sim_state_t *ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);

	uint8_t srescat[EAPSIM_SRES_SIZE * 3];
	uint8_t *p = srescat;

	uint8_t calcmac[EAPSIM_CALCMAC_SIZE];

	memcpy(p, ess->keys.sres[0], EAPSIM_SRES_SIZE);
	p += EAPSIM_SRES_SIZE;
	memcpy(p, ess->keys.sres[1], EAPSIM_SRES_SIZE);
	p += EAPSIM_SRES_SIZE;
	memcpy(p, ess->keys.sres[2], EAPSIM_SRES_SIZE);

	/*
	 *	Verify the MAC, now that we have all the keys
	 */
	if (eap_sim_check_mac(eap_session, vps, ess->keys.K_aut, srescat, sizeof(srescat), calcmac)) {
		RDEBUG2("MAC check succeed");
	} else {
		int i, j;
		char macline[20*3];
		char *m = macline;

		for (i = 0, j = 0; i < EAPSIM_CALCMAC_SIZE; i++) {
			if (j == 4) {
				*m++ = '_';
				j=0;
			}
			j++;

			sprintf(m, "%02x", calcmac[i]);
			m = m + strlen(m);
		}
		REDEBUG("Calculated MAC (%s) did not match", macline);
		return 0;
	}

	/* everything looks good, change states */
	eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_SUCCESS);
	return 1;
}


/** Authenticate a previously sent challenge
 *
 */
static int mod_process(UNUSED void *arg, eap_session_t *eap_session)
{
	REQUEST *request = eap_session->request;
	eap_sim_state_t *ess = talloc_get_type_abort(eap_session->opaque, eap_sim_state_t);

	VALUE_PAIR *vp, *vps;

	enum eap_sim_subtype subtype;

	int success;

	/*
	 *	VPS is the data from the client
	 */
	vps = eap_session->request->packet->vps;

	success = eap_sim_decode(eap_session->request->packet,
					  eap_session->this_round->response->type.data,
					  eap_session->this_round->response->type.length);

	if (!success) return 0;

	/*
	 *	See what kind of message we have gotten
	 */
	vp = fr_pair_find_by_num(vps, 0, PW_EAP_SIM_SUBTYPE, TAG_ANY);
	if (!vp) {
		REDEBUG2("No subtype attribute was created, message dropped");
		return 0;
	}
	subtype = vp->vp_integer;

	/*
	 *	Client error supersedes anything else.
	 */
	if (subtype == EAPSIM_CLIENT_ERROR) {
		REDEBUG("Client encountered an error");
		return 0;
	}

	switch (ess->state) {
	case EAPSIM_SERVER_START:
		switch (subtype) {
		/*
		 *	Pretty much anything else here is illegal, so we will retransmit the request.
		 */
		default:
			eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_START);
			return 1;
		/*
		 * 	A response to our EAP-Sim/Request/Start!
		 */
		case EAPSIM_START:
			return process_eap_sim_start(eap_session, vps);
		}

	case EAPSIM_SERVER_CHALLENGE:
		switch (subtype) {
		/*
		 *	Pretty much anything else here is illegal, so we will retransmit the request.
		 */
		default:
			eap_sim_state_enter(eap_session, ess, EAPSIM_SERVER_CHALLENGE);
			return 1;
		/*
		 *	A response to our EAP-Sim/Request/Challenge!
		 */
		case EAPSIM_CHALLENGE:
			return process_eap_sim_challenge(eap_session, vps);
		}

	default:
		rad_assert(0 == 1);
	}

	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_module_t rlm_eap_sim;
rlm_eap_module_t rlm_eap_sim = {
	.name		= "eap_sim",
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process,		/* Process next round of EAP method */
};
