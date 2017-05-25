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
 * @file rlm_eap_aka.c
 * @brief Implements the AKA part of EAP-AKA
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SARL <sales@networkradius.com>
 */
RCSID("$Id$")

#include "../../eap.h"
#include "eap_types.h"
#include "eap_aka.h"
#include "sim_proto.h"

#include <freeradius-devel/rad_assert.h>

#ifndef EAP_TLS_MPPE_KEY_LEN
#  define EAP_TLS_MPPE_KEY_LEN     32
#endif

fr_dict_attr_t const *dict_aka_root;

static rlm_rcode_t mod_process(UNUSED void *arg, eap_session_t *eap_session);

/*
 *	build a reply to be sent.
 */
static int eap_aka_compose(eap_session_t *eap_session)
{
	/* we will set the ID on requests, since we have to HMAC it */
	eap_session->this_round->set_request_id = true;

	return fr_sim_encode(eap_session->request, dict_aka_root, FR_EAP_AKA,
			     eap_session->request->reply->vps, eap_session->this_round->request,
			     NULL, 0);
}

/** Send the challenge itself
 *
 * Challenges will come from one of three places eventually:
 *
 * 1  from attributes like FR_EAP_SIM_RANDx
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
 */
static int eap_aka_send_challenge(eap_session_t *eap_session)
{
	static uint8_t		hmac_zero[16] = { 0x00 };

	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session;
	VALUE_PAIR		**to_client, *vp;
	RADIUS_PACKET		*packet;
	uint8_t			*p, *rand;

	eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	/*
	 *	to_client is the data to the client
	 */
	packet = eap_session->request->reply;
	to_client = &packet->vps;

	/*
	 *	Okay, we got the challenge! Put it into an attribute.
	 */
	MEM(vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_RAND));
	MEM(p = rand = talloc_array(vp, uint8_t, 2 + SIM_VECTOR_UMTS_RAND_SIZE));
	memset(p, 0, 2); /* clear reserved bytes */
	memcpy(p + 2, eap_aka_session->keys.umts.vector.rand, SIM_VECTOR_UMTS_RAND_SIZE);
	fr_pair_value_memsteal(vp, rand);
	fr_pair_add(to_client, vp);

	/*
	 *	Send the AUTN value to the client, so it can authenticate
	 *	whoever has knowledge of the Ki.
	 */
	MEM(vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_AUTN));
	MEM(p = talloc_array(vp, uint8_t, 2 + SIM_VECTOR_UMTS_AUTN_SIZE));
	memset(p, 0, 2); /* clear reserved bytes */
	memcpy(p + 2, eap_aka_session->keys.umts.vector.autn, SIM_VECTOR_UMTS_AUTN_SIZE);
	fr_pair_value_memsteal(vp, p);
	fr_pair_add(to_client, vp);

	/*
	 *	Set the EAP_ID - new value
	 */
	vp = fr_pair_afrom_child_num(packet, fr_dict_root(fr_dict_internal), FR_EAP_ID);
	vp->vp_uint32 = eap_aka_session->aka_id++;
	fr_pair_replace(to_client, vp);

	/*
	 *	Grab the outer identity and add it to the keying material
	 */
	if (eap_aka_session->keys.identity) talloc_free(eap_aka_session->keys.identity);

	eap_aka_session->keys.identity_len = strlen(eap_session->identity);
	MEM(eap_aka_session->keys.identity = talloc_array(eap_aka_session, uint8_t,
							  eap_aka_session->keys.identity_len));
	memcpy(eap_aka_session->keys.identity, eap_session->identity,
	       eap_aka_session->keys.identity_len);

	/*
	 *	All set, calculate keys!
	 */
	fr_sim_crypto_kdf_0_umts(&eap_aka_session->keys);

	if (RDEBUG_ENABLED3) fr_sim_crypto_keys_log(request, &eap_aka_session->keys);

	/*
	 *	need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_MAC);
	fr_pair_value_memcpy(vp, hmac_zero, sizeof(hmac_zero));
	fr_pair_replace(to_client, vp);

	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_KEY);
	fr_pair_value_memcpy(vp, eap_aka_session->keys.k_aut, 16);
	fr_pair_replace(to_client, vp);

	/* the SUBTYPE, set to challenge. */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_SUBTYPE);
	vp->vp_uint32 = FR_EAP_AKA_SUBTYPE_VALUE_AKA_CHALLENGE;
	fr_pair_replace(to_client, vp);

	return 1;
}

/** Send a success message
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * attributes derived from the MSK.
 */
static void eap_aka_send_success(eap_session_t *eap_session)
{
	uint8_t			*p;
	eap_aka_session_t	*eap_aka_session;
	VALUE_PAIR		*vp;
	RADIUS_PACKET		*packet;

	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	/* to_client is the data to the client. */
	packet = eap_session->request->reply;
	eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	/* set the EAP_ID - new value */
	vp = fr_pair_afrom_child_num(packet, fr_dict_root(fr_dict_internal), FR_EAP_ID);
	vp->vp_uint32 = eap_aka_session->aka_id++;
	fr_pair_replace(&eap_session->request->reply->vps, vp);

	p = eap_aka_session->keys.msk;
	eap_add_reply(eap_session->request, "MS-MPPE-Recv-Key", p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(eap_session->request, "MS-MPPE-Send-Key", p, EAP_TLS_MPPE_KEY_LEN);
}

/** Run the server state machine
 *
 */
static void eap_aka_state_enter(eap_session_t *eap_session,
				eap_aka_session_t *eap_aka_session,
				eap_aka_server_state_t new_state)
{
	switch (new_state) {
	/*
	 *	Send the EAP-AKA Challenge message.
	 */
	case EAP_AKA_SERVER_CHALLENGE:
		eap_aka_send_challenge(eap_session);
		eap_aka_compose(eap_session);
		break;

	/*
	 *	Send the EAP Success message
	 */
	case EAP_AKA_SERVER_SUCCESS:
		eap_aka_send_success(eap_session);
		return;

	/*
	 *	Nothing to do for this transition.
	 */
	default:
		eap_aka_compose(eap_session);
		break;
	}

	eap_aka_session->state = new_state;

}

/**  Process an EAP-AKA/Response/Challenge
 *
 * Verify that MAC, and RES match what we expect.
 */
static int process_eap_aka_challenge(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	uint8_t			calc_mac[SIM_CALC_MAC_SIZE];
	VALUE_PAIR		*vp;

	/*
	 *	Verify the MAC, now that we have all the keys
	 */
	if (fr_sim_crypto_mac_verify(eap_session, dict_aka_root, vps,
				     eap_aka_session->keys.k_aut,
				     NULL, 0, calc_mac)) {
		RDEBUG2("MAC check succeed");
	} else {
		int i, j;
		char macline[20 * 3];
		char *m = macline;

		for (i = 0, j = 0; i < SIM_CALC_MAC_SIZE; i++) {
			if (j == 4) {
				*m++ = '_';
				j = 0;
			}
			j++;

			sprintf(m, "%02x", calc_mac[i]);
			m = m + strlen(m);
		}
		REDEBUG("Calculated MAC (%s) did not match", macline);
		return -1;
	}

	vp = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_RES, TAG_ANY);
	if (!vp) {
		REDEBUG("Missing EAP-AKA-RES from challenge response");
		return -1;
	}

	if ((vp->vp_length - 2) != eap_aka_session->keys.umts.vector.xres_len) {
		REDEBUG("EAP-AKA-RES length (%zu) does not match XRES length (%zu)",
			(vp->vp_length - 2), eap_aka_session->keys.umts.vector.xres_len);
		return -1;
	}

  	if (memcmp(&vp->vp_octets[2], eap_aka_session->keys.umts.vector.xres, vp->vp_length - 2)) {
    		REDEBUG("EAP-AKA-RES from client does match XRES");
		RHEXDUMP_INLINE(L_DBG_LVL_2, &vp->vp_octets[2], vp->vp_length, "RES  :");
		RHEXDUMP_INLINE(L_DBG_LVL_2, eap_aka_session->keys.umts.vector.xres,
				eap_aka_session->keys.umts.vector.xres_len, "XRES :");
		return -1;
	}

	RDEBUG2("EAP-AKA-RES matches XRES");

	/* everything looks good, change states */
	eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_SUCCESS);

	return 0;
}

/** Authenticate a previously sent challenge
 *
 */
static rlm_rcode_t mod_process(UNUSED void *arg, eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	fr_sim_decode_ctx_t	ctx;
	VALUE_PAIR		*vp, *vps;
	vp_cursor_t		cursor;

	eap_aka_subtype_t	subtype;

	int			ret;

	/* vps is the data from the client */
	vps = request->packet->vps;

	fr_pair_cursor_init(&cursor, &request->packet->vps);

	ctx.keys = &(eap_aka_session->keys);
	ret = fr_sim_decode(eap_session->request,
			    &cursor, dict_aka_root,
			    eap_session->this_round->response->type.data,
			    eap_session->this_round->response->type.length,
			    &ctx);
	if (ret < 0) return RLM_MODULE_INVALID;

	vp = fr_pair_cursor_next(&cursor);
	if (vp && RDEBUG_ENABLED2) {
		RDEBUG2("EAP-AKA decoded attributes");
		rdebug_pair_list(L_DBG_LVL_2, request, vp, NULL);
	}

	MEM(vp = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_SUBTYPE, TAG_ANY));
	subtype = vp->vp_uint32;

	switch (eap_aka_session->state) {
	case EAP_AKA_SERVER_CHALLENGE:
		switch(subtype) {
		default:
			eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_CHALLENGE);
			return RLM_MODULE_HANDLED;

		case EAP_AKA_SYNCHRONIZATION_FAILURE:
			REDEBUG("EAP-AKA Peer synchronization failure");
			return RLM_MODULE_REJECT;

		case EAP_AKA_AUTHENTICATION_REJECT:
			REDEBUG("EAP-AKA Peer Rejected AT_AUTN");
			return RLM_MODULE_REJECT;

		case EAP_AKA_CLIENT_ERROR:
		{
			char buff[20];

			vp = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_CLIENT_ERROR_CODE, TAG_ANY);
			if (!vp) {
				REDEBUG("EAP-AKA Peer rejected AKA-Challenge with client-error message but "
					"has not supplied a client error code");
			} else {
				REDEBUG("Client rejected AKA-Challenge with error: %s (%i)",
					fr_pair_value_enum(vp, &buff[0]), vp->vp_uint16);
			}
			return RLM_MODULE_REJECT;
		}

		case EAP_AKA_CHALLENGE:
			return process_eap_aka_challenge(eap_session, vps) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_HANDLED;
		}

	default:
		REDEBUG("Illegal-unknown state reached");
		return RLM_MODULE_FAIL;
	}
}

/** Initiate the EAP-SIM session by starting the state machine
 *
 */
static rlm_rcode_t mod_session_init(UNUSED void *instance, eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session;
	time_t			n;
	fr_sim_vector_src_t	src = SIM_VECTOR_SRC_AUTO;

	MEM(eap_aka_session = talloc_zero(eap_session, eap_aka_session_t));

	eap_session->opaque = eap_aka_session;

	/*
	 *	Save the keying material, because it could change on a subsequent retrieval.
	 */
	RDEBUG2("New EAP-AKA session.  Acquiring AKA vectors");
	if (fr_sim_vector_umts_from_attrs(eap_session, request->control, &eap_aka_session->keys, &src) < 0) {
	    	REDEBUG("Failed retrieving AKA vectors");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	This value doesn't have be strong, but it is good if it is different now and then.
	 */
	time(&n);
	eap_aka_session->aka_id = (n & 0xff);

	eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_CHALLENGE);

	eap_session->process = mod_process;

	return RLM_MODULE_OK;
}

static int mod_load(void)
{
	dict_aka_root = fr_dict_attr_child_by_num(fr_dict_root(fr_dict_internal), FR_EAP_AKA_ROOT);
	if (!dict_aka_root) {
		ERROR("Missing EAP-AKA-Root attribute");
		return -1;
	}
	if (fr_sim_global_init() < 0) return -1;
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_aka;
rlm_eap_submodule_t rlm_eap_aka = {
	.name		= "eap_aka",
	.magic		= RLM_MODULE_INIT,
	.load		= mod_load,
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process,		/* Process next round of EAP method */
};
