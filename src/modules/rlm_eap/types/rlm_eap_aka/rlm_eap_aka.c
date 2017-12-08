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

static rlm_rcode_t mod_process(UNUSED void *arg, eap_session_t *eap_session);

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, rlm_eap_aka_t, virtual_server) },
	CONF_PARSER_TERMINATOR
};

/*
 *	build a reply to be sent.
 */
static int eap_aka_compose(eap_session_t *eap_session)
{
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	/* we will set the ID on requests, since we have to HMAC it */
	eap_session->this_round->set_request_id = true;

	return fr_sim_encode(eap_session->request, dict_aka_root, FR_EAP_AKA,
			     eap_session->request->reply->vps, eap_session->this_round->request,
			     &eap_aka_session->keys);
}

/** Send an EAP-AKA identity request to the supplicant
 *
 * There are three types of user identities that can be implemented
 * - Permanent identities such as 0123456789098765@myoperator.com
 *   Permanent identities can be identified by the leading zero followed by
 *   by 15 digits (the IMSI number).
 * - Ephemeral identities (pseudonyms).  These are identities assigned for
 *   identity privacy so the user can't be tracked.  These can identities
 *   can either be generated as per the 3GPP 'Security aspects of non-3GPP accesses'
 *   document section 14, where a set of up to 16 encryption keys are used
 *   to reversibly encrypt the IMSI. Alternatively the pseudonym can be completely
 *   randomised and stored in a datastore.
 * - A fast resumption ID which resolves to data used for fast resumption.
 *
 * In order to perform full authentication the original IMSI is required for
 * forwarding to the HLR. In the case where we can't match/decrypt the pseudonym,
 * or can't perform fast resumption, we need to request the full identity from
 * the supplicant.
 *
 * @param[in] eap_session	to continue.
 * @param[in] id_req_type	what type of identity we need returned.
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
static int eap_aka_send_identity_request(eap_session_t *eap_session, int id_req_type)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	VALUE_PAIR		*vp;
	RADIUS_PACKET		*packet;
	fr_cursor_t		cursor;

	packet = request->reply;
	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *	Set the subtype to identity request
	 */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_SUBTYPE);
	vp->vp_uint32 = FR_EAP_AKA_SUBTYPE_VALUE_AKA_IDENTITY;
	fr_cursor_append(&cursor, vp);

	/*
	 *	Set the EAP_ID
	 */
	vp = fr_pair_afrom_child_num(packet, fr_dict_root(fr_dict_internal), FR_EAP_ID);
	vp->vp_uint32 = eap_aka_session->aka_id++;
	fr_cursor_append(&cursor, vp);

	/*
	 *	Select the right type of identity request attribute
	 */
	switch (id_req_type) {
	case SIM_ANY_ID:
		vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_ANY_ID_REQ);
		break;

	case SIM_PERMANENT_ID_REQ:
		vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_PERMANENT_ID_REQ);
		break;

	case SIM_FULLAUTH_ID_REQ:
		vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_FULLAUTH_ID_REQ);
		break;

	default:
		rad_assert(0);
	}
	vp->vp_bool = true;
	fr_cursor_append(&cursor, vp);

	return 0;
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
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	VALUE_PAIR		**to_client, *vp;
	RADIUS_PACKET		*packet;

	rad_assert(request);
	rad_assert(request->reply);

	/*
	 *	to_client is the data to the client
	 */
	packet = eap_session->request->reply;
	to_client = &packet->vps;

	/*
	 *	Okay, we got the challenge! Put it into an attribute.
	 */
	MEM(vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_RAND));
	fr_pair_value_memcpy(vp, eap_aka_session->keys.umts.vector.rand, SIM_VECTOR_UMTS_RAND_SIZE);
	fr_pair_add(to_client, vp);

	/*
	 *	Send the AUTN value to the client, so it can authenticate
	 *	whoever has knowledge of the Ki.
	 */
	MEM(vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_AUTN));
	fr_pair_value_memcpy(vp, eap_aka_session->keys.umts.vector.autn, SIM_VECTOR_UMTS_AUTN_SIZE);
	fr_pair_add(to_client, vp);

	/*
	 *	Set the EAP_ID - new value
	 */
	vp = fr_pair_afrom_child_num(packet, fr_dict_root(fr_dict_internal), FR_EAP_ID);
	vp->vp_uint32 = eap_aka_session->aka_id++;
	fr_pair_replace(to_client, vp);

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
	 *	Send an EAP-AKA Identity request
	 */
	case EAP_AKA_SERVER_IDENTITY:
		eap_aka_send_identity_request(eap_session, SIM_PERMANENT_ID_REQ);
		eap_aka_compose(eap_session);
		break;

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
				     (eap_packet_raw_t *)eap_session->this_round->response->packet,
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

	if (vp->vp_length != eap_aka_session->keys.umts.vector.xres_len) {
		REDEBUG("EAP-AKA-RES length (%zu) does not match XRES length (%zu)",
			vp->vp_length, eap_aka_session->keys.umts.vector.xres_len);
		return -1;
	}

  	if (memcmp(vp->vp_octets, eap_aka_session->keys.umts.vector.xres, vp->vp_length)) {
    		REDEBUG("EAP-AKA-RES from client does match XRES");
		RHEXDUMP_INLINE(L_DBG_LVL_2, vp->vp_octets, vp->vp_length, "RES  :");
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

	fr_sim_decode_ctx_t	ctx = {
					.keys = &eap_aka_session->keys,
					.root = dict_aka_root
				};
	VALUE_PAIR		*vp, *vps;
	vp_cursor_t		cursor;

	eap_aka_subtype_t	subtype;

	int			ret;

	/* vps is the data from the client */
	vps = request->packet->vps;

	fr_pair_cursor_init(&cursor, &request->packet->vps);

	ret = fr_sim_decode(eap_session->request,
			    &cursor,
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
	case EAP_AKA_SERVER_IDENTITY:
		break;

	case EAP_AKA_SERVER_CHALLENGE:
		switch (subtype) {
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
					fr_pair_value_enum(vp, buff), vp->vp_uint16);
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

	return RLM_MODULE_OK;
}

/** Initiate the EAP-SIM session by starting the state machine
 *
 */
static rlm_rcode_t mod_session_init(UNUSED void *instance, eap_session_t *eap_session)
{
	REQUEST				*request = eap_session->request;
	eap_aka_session_t		*eap_aka_session;
	time_t				n;
	fr_sim_vector_src_t		src = SIM_VECTOR_SRC_AUTO;
	fr_sim_id_type_t		type;
	fr_sim_method_hint_t		method;

	MEM(eap_aka_session = talloc_zero(eap_session, eap_aka_session_t));

	eap_session->opaque = eap_aka_session;

	/*
	 *	Save the keying material, because it could
	 *	change on a subsequent retrieval.
	 */
	RDEBUG2("New EAP-AKA session.  Acquiring AKA vectors");
	if (fr_sim_vector_umts_from_attrs(eap_session, request->control, &eap_aka_session->keys, &src) < 0) {
	    	REDEBUG("Failed retrieving AKA vectors");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	This value doesn't have be strong, but it is
	 *	good if it is different now and then.
	 */
	time(&n);
	eap_aka_session->aka_id = (n & 0xff);
	eap_session->process = mod_process;

	/*
	 *	Process the identity that we received in the
	 *	EAP-Identity-Response and use it to determine
	 *	the initial request we send to the Supplicant.
	 */
	if (fr_sim_id_type(&type, &method,
			   eap_session->identity, talloc_array_length(eap_session->identity) - 1) < 0) {
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_IDENTITY);
		return RLM_MODULE_OK;
	}

	if (method != SIM_METHOD_HINT_AKA) WARN("EAP-Identity-Response hints that EAP-SIM "
						"should be started, but we're attempting EAP-AKA");

	/*
	 *	Figure out what type of identity we have
	 *	and use it to determine the initial
	 *	request we send.
	 */
	switch (type) {
	/*
	 *	Permanent ID means we can just send the challenge
	 */
	case SIM_ID_TYPE_PERMANENT:
		eap_aka_session->keys.identity_len = talloc_array_length(eap_session->identity) - 1;
		MEM(eap_aka_session->keys.identity = talloc_memdup(eap_aka_session, eap_session->identity,
								   eap_aka_session->keys.identity_len));
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_CHALLENGE);
		return RLM_MODULE_OK;

	/*
	 *	These types need to be transformed into something
	 *	usable before we can do anything.
	 */
	case SIM_ID_TYPE_PSEUDONYM:
	case SIM_ID_TYPE_FASTAUTH:
	case SIM_ID_TYPE_UNKNOWN:
		ERROR("Not yet implemented");
		return RLM_MODULE_FAIL;
	}

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
	sim_xlat_register();

	return 0;
}

static void mod_unload(void)
{
	sim_xlat_unregister();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_aka;
rlm_eap_submodule_t rlm_eap_aka = {
	.name		= "eap_aka",
	.magic		= RLM_MODULE_INIT,

	.inst_size	= sizeof(rlm_eap_aka_t),
	.config		= submodule_config,

	.load		= mod_load,
	.unload		= mod_unload,
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.process	= mod_process,		/* Process next round of EAP method */
};
