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

FR_NAME_NUMBER const aka_state_table[] = {
	{ "START",		EAP_AKA_SERVER_START		},
	{ "IDENTITY",		EAP_AKA_SERVER_IDENTITY		},
	{ "CHALLENGE",		EAP_AKA_SERVER_CHALLENGE	},
	{ "SUCCESS",		EAP_AKA_SERVER_SUCCESS		},
	{ "GENERAL-FAILURE",	EAP_AKA_SERVER_GENERAL_FAILURE	},
	{ NULL }
};

static rlm_rcode_t mod_process(UNUSED void *arg, eap_session_t *eap_session);

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("request_identity", FR_TYPE_BOOL, rlm_eap_aka_t, request_identity ) },
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, rlm_eap_aka_t, virtual_server) },
	CONF_PARSER_TERMINATOR
};

static int eap_aka_compose(eap_session_t *eap_session)
{
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	vp_cursor_t		cursor;
	vp_cursor_t		to_encode;
	VALUE_PAIR		*head = NULL, *vp;
	REQUEST			*request = eap_session->request;
	ssize_t			ret;

	fr_pair_cursor_init(&cursor, &eap_session->request->reply->vps);
	fr_pair_cursor_init(&to_encode, &head);

	while ((fr_pair_cursor_next_by_ancestor(&cursor, dict_sim_root, TAG_ANY))) {
		vp = fr_pair_cursor_remove(&cursor);
		fr_pair_cursor_append(&to_encode, vp);
	}

	RDEBUG2("Encoding EAP-AKA attributes");
	rdebug_pair_list(L_DBG_LVL_2, request, head, NULL);

	eap_session->this_round->request->id = eap_aka_session->aka_id++ & 0xff;
	eap_session->this_round->set_request_id = true;

	ret = fr_sim_encode(eap_session->request, dict_aka_root, FR_EAP_AKA,
			    head, eap_session->this_round->request,
			    &eap_aka_session->keys);
	fr_pair_cursor_first(&to_encode);
	fr_pair_cursor_free(&to_encode);

	if (ret < 0) {
		RPEDEBUG("Failed encoding EAP-AKA data");
		return -1;
	}
	return 0;
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
 * @return
 *	- 0 on success.
 *	- <0 on failure.
 */
static int eap_aka_send_identity_request(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	VALUE_PAIR		*vp;
	RADIUS_PACKET		*packet;
	fr_cursor_t		cursor;

	RDEBUG2("Sending AKA-Identity (%s)", fr_int2str(sim_id_request_table, eap_aka_session->id_req, "<INVALID>"));

	packet = request->reply;
	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *	Set the subtype to identity request
	 */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_SUBTYPE);
	vp->vp_uint32 = FR_EAP_AKA_SUBTYPE_VALUE_AKA_IDENTITY;
	fr_cursor_append(&cursor, vp);

	/*
	 *	Select the right type of identity request attribute
	 */
	switch (eap_aka_session->id_req) {
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
	fr_sim_vector_src_t	src = SIM_VECTOR_SRC_AUTO;

	rad_assert(request);
	rad_assert(request->reply);

	RDEBUG2("Acquiring UMTS vector(s)");
	if (fr_sim_vector_umts_from_attrs(eap_session, request->control, &eap_aka_session->keys, &src) < 0) {
	    	REDEBUG("Failed retrieving UMTS vectors");
		return RLM_MODULE_FAIL;
	}

	RDEBUG2("Sending AKA-Challenge");

	/*
	 *	to_client is the data to the client
	 */
	packet = eap_session->request->reply;
	to_client = &packet->vps;

	/*
	 *	Set the subtype to challenge
	 */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_SUBTYPE);
	vp->vp_uint32 = FR_EAP_AKA_SUBTYPE_VALUE_AKA_CHALLENGE;
	fr_pair_replace(to_client, vp);

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

	return 1;
}

/** Send a success message
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * attributes derived from the MSK.
 */
static void eap_aka_send_success(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	uint8_t			*p;
	eap_aka_session_t	*eap_aka_session;
	RADIUS_PACKET		*packet;

	RDEBUG2("Sending Success");

	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	/* to_client is the data to the client. */
	packet = eap_session->request->reply;
	eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	p = eap_aka_session->keys.msk;
	eap_add_reply(eap_session->request, "MS-MPPE-Recv-Key", p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(eap_session->request, "MS-MPPE-Send-Key", p, EAP_TLS_MPPE_KEY_LEN);
}

/** Send a success message
 *
 */
static void eap_aka_send_general_failure(eap_session_t *eap_session)
{
	REQUEST		*request = eap_session->request;
	RADIUS_PACKET	*packet = eap_session->request->reply;
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;

	RDEBUG2("Sending AKA-Notification (General-Failure)");

	fr_cursor_init(&cursor, &packet->vps);

	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to notification
	 */
	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_SUBTYPE);
	vp->vp_uint32 = FR_EAP_AKA_SUBTYPE_VALUE_AKA_NOTIFICATION;
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_child_num(packet, dict_aka_root, FR_EAP_AKA_NOTIFICATION);
	vp->vp_uint32 = FR_EAP_AKA_NOTIFICATION_VALUE_GENERAL_FAILURE;
	fr_cursor_append(&cursor, vp);
}

static void eap_aka_send_failure(eap_session_t *eap_session)
{
	eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
}

/** Run the server state machine
 *
 */
static void eap_aka_state_enter(eap_session_t *eap_session,
				eap_aka_session_t *eap_aka_session,
				eap_aka_server_state_t new_state)
{
	REQUEST	*request = eap_session->request;

	if (new_state != eap_aka_session->state) {
		RDEBUG2("Changed state %s -> %s",
			fr_int2str(aka_state_table, eap_aka_session->state, "<unknown>"),
			fr_int2str(aka_state_table, new_state, "<unknown>"));
		eap_aka_session->state = new_state;
	} else {
		RDEBUG2("Reentering state %s",
			fr_int2str(aka_state_table, eap_aka_session->state, "<unknown>"));
	}

	switch (new_state) {
	/*
	 *	Send an EAP-AKA Identity request
	 */
	case EAP_AKA_SERVER_IDENTITY:
		eap_aka_send_identity_request(eap_session);
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
	 *	Send a general failure notification
	 */
	case EAP_AKA_SERVER_GENERAL_FAILURE:
		eap_aka_send_general_failure(eap_session);
		eap_aka_compose(eap_session);
		return;

	/*
	 *	Nothing to do for this transition.
	 */
	default:
		eap_aka_compose(eap_session);
		break;
	}
}

static int process_eap_aka_identity(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);
	VALUE_PAIR		*id;
	fr_sim_id_type_t	type = SIM_ID_TYPE_UNKNOWN;
	fr_sim_method_hint_t	method = SIM_METHOD_HINT_UNKNOWN;

	/*
	 *	See if we got an AT_IDENTITY
	 */
	id = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_IDENTITY, TAG_ANY);
	if (id && fr_sim_id_type(&type, &method,
				 eap_session->identity, talloc_array_length(eap_session->identity) - 1) < 0) {
		RDEBUG2("Failed parsing identity: %s", fr_strerror());
	}

	/*
	 *	Negotiate the next permissive form
	 *	if identity, or fail.
	 */
	switch (eap_aka_session->id_req) {
	case SIM_ANY_ID:
		eap_aka_session->id_req = SIM_FULLAUTH_ID_REQ;
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_IDENTITY);
		break;

	case SIM_FULLAUTH_ID_REQ:
		eap_aka_session->id_req = SIM_PERMANENT_ID_REQ;
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_IDENTITY);
		break;

	case SIM_PERMANENT_ID_REQ:
		REDEBUG2("Failed to negotiate a usable identity");
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_GENERAL_FAILURE);
		break;
	}

	return 0;
}

/**  Process an EAP-AKA/Response/Challenge
 *
 * Verify that MAC, and RES match what we expect.
 */
static int process_eap_aka_challenge(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST			*request = eap_session->request;
	eap_aka_session_t	*eap_aka_session = talloc_get_type_abort(eap_session->opaque, eap_aka_session_t);

	uint8_t			calc_mac[SIM_MAC_HASH_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*vp = NULL, *mac;

	mac = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_RES, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
		return -1;
	}
	if (mac->vp_length != SIM_MAC_HASH_SIZE) {
		REDEBUG("AT_MAC incorrect length, expected %u bytes got %zu bytes",
			SIM_MAC_HASH_SIZE, mac->vp_length);
		return -1;
	}

	slen = fr_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true,
					 eap_aka_session->keys.k_aut, sizeof(eap_aka_session->keys.k_aut),
					 NULL, 0);
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		return -1;
	}

	if (slen == 0) {
		REDEBUG("Missing AT_MAC attribute in packet buffer");
		return -1;
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("MAC check succeed");
	} else {
		REDEBUG("MAC checked failed");
		RHEXDUMP_INLINE(L_DBG_LVL_2, mac->vp_octets, SIM_MAC_HASH_SIZE, "Received");
		RHEXDUMP_INLINE(L_DBG_LVL_2, calc_mac, SIM_MAC_HASH_SIZE, "Expected");
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
	fr_pair_cursor_last(&cursor);

	ret = fr_sim_decode(eap_session->request,
			    &cursor,
			    eap_session->this_round->response->type.data,
			    eap_session->this_round->response->type.length,
			    &ctx);
	if (ret < 0) {
		RPEDEBUG2("Failed decoding EAP-AKA attributes");
		return RLM_MODULE_INVALID;
	}

	vp = fr_pair_cursor_current(&cursor);
	if (vp && RDEBUG_ENABLED2) {
		RDEBUG2("EAP-AKA decoded attributes");
		rdebug_pair_list(L_DBG_LVL_2, request, vp, NULL);
	}

	MEM(vp = fr_pair_find_by_child_num(vps, dict_aka_root, FR_EAP_AKA_SUBTYPE, TAG_ANY));
	subtype = vp->vp_uint32;

	switch (eap_aka_session->state) {
	case EAP_AKA_SERVER_IDENTITY:
		switch (subtype) {
		case EAP_AKA_IDENTITY:
			return process_eap_aka_identity(eap_session, vps) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_HANDLED;

		}

		break;

	case EAP_AKA_SERVER_CHALLENGE:
		switch (subtype) {
		default:
			eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_CHALLENGE);
			return RLM_MODULE_HANDLED;

		case EAP_AKA_SYNCHRONIZATION_FAILURE:
			REDEBUG("EAP-AKA Peer synchronization failure");
		failure:
			eap_aka_send_failure(eap_session);
			return RLM_MODULE_REJECT;

		case EAP_AKA_AUTHENTICATION_REJECT:
			REDEBUG("EAP-AKA Peer Rejected AUTN");
			goto failure;

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
			goto failure;
		}

		case EAP_AKA_CHALLENGE:
			return process_eap_aka_challenge(eap_session, vps) < 0 ? RLM_MODULE_FAIL : RLM_MODULE_HANDLED;
		}

	case EAP_AKA_SERVER_GENERAL_FAILURE:
		if (subtype == EAP_AKA_NOTIFICATION) {
			RDEBUG2("AKA-Notification ACKed, sending EAP-Failure");
		} else {
			REDEBUG2("Invalid response to AKA-Notification, sending EAP-Failure");
		}
		goto failure;

	default:
		REDEBUG("Illegal-unknown state reached");
		goto failure;
	}

	return RLM_MODULE_OK;
}

/** Initiate the EAP-SIM session by starting the state machine
 *
 */
static rlm_rcode_t mod_session_init(void *instance, eap_session_t *eap_session)
{
	REQUEST				*request = eap_session->request;
	eap_aka_session_t		*eap_aka_session;
	rlm_eap_aka_t			*inst = instance;
	fr_sim_id_type_t		type;
	fr_sim_method_hint_t		method;

	MEM(eap_aka_session = talloc_zero(eap_session, eap_aka_session_t));

	eap_session->opaque = eap_aka_session;

	/*
	 *	Save the keying material, because it could
	 *	change on a subsequent retrieval.
	 */
	RDEBUG2("New EAP-AKA session");

	/*
	 *	This value doesn't have be strong, but it is
	 *	good if it is different now and then.
	 */
	eap_aka_session->aka_id = (fr_rand() & 0xff);
	eap_session->process = mod_process;

	/*
	 *	Process the identity that we received in the
	 *	EAP-Identity-Response and use it to determine
	 *	the initial request we send to the Supplicant.
	 */
	if (fr_sim_id_type(&type, &method,
			   eap_session->identity, talloc_array_length(eap_session->identity) - 1) < 0) {
		RDEBUG2("Failed parsing identity, continuing anyway: %s", fr_strerror());
	}

	if (method == SIM_METHOD_HINT_SIM) WARN("EAP-Identity-Response hints that EAP-SIM "
						"should be started, but we're attempting EAP-AKA");

	/*
	 *	Admin wants us to always request an identity
	 *	initially.  The RFC says this is also the
	 *	better way to operate, as the supplicant
	 *	can 'decorate' the identity in the identity
	 *	response.
	 */
	if (inst->request_identity) {
	request_id:
		/*
		 *	We always start by requesting
		 *	any ID initially as we can
		 *	always negotiate down.
		 */
		eap_aka_session->id_req = SIM_ANY_ID;
		eap_aka_state_enter(eap_session, eap_aka_session, EAP_AKA_SERVER_IDENTITY);
		return RLM_MODULE_OK;
	}
	/*
	 *	Figure out what type of identity we have
	 *	and use it to determine the initial
	 *	request we send.
	 */
	switch (type) {
	/*
	 *	If there's no valid tag on the identity
	 *	then it's probably been decorated by the
	 *	supplicant.
	 *
	 *	Request the unmolested identity
	 */
	case SIM_ID_TYPE_UNKNOWN:
		goto request_id;

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

		return RLM_MODULE_OK;
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
