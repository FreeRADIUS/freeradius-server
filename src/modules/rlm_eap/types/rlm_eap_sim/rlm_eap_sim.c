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
 * @file rlm_eap_sim.c
 * @brief Implements the SIM part of EAP-SIM
 *
 * The development of the EAP/SIM support was funded by Internet Foundation
 * Austria (http://www.nic.at/ipa).
 *
 * @copyright 2003 Michael Richardson (mcr@sandelman.ottawa.on.ca)
 * @copyright 2003-2016 The FreeRADIUS server project
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/eap/base.h>
#include <freeradius-devel/eap/types.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/sim/base.h>

#include <freeradius-devel/protocol/eap/sim/rfc4187.h>

#include "eap_sim.h"

#ifndef EAP_TLS_MPPE_KEY_LEN
#  define EAP_TLS_MPPE_KEY_LEN     32
#endif

static fr_table_num_ordered_t const sim_state_table[] = {
	{ "START",				EAP_SIM_SERVER_START				},
	{ "CHALLENGE",				EAP_SIM_SERVER_CHALLENGE			},
	{ "REAUTHENTICATE",			EAP_SIM_SERVER_REAUTHENTICATE			},
	{ "SUCCESS-NOTIFICATION",		EAP_SIM_SERVER_SUCCESS_NOTIFICATION 		},
	{ "SUCCESS",				EAP_SIM_SERVER_SUCCESS				},
	{ "FAILURE-NOTIFICATION",		EAP_SIM_SERVER_FAILURE_NOTIFICATION		},
	{ "FAILURE",				EAP_SIM_SERVER_FAILURE				},
};
static size_t sim_state_table_len = NUM_ELEMENTS(sim_state_table);

static CONF_PARSER submodule_config[] = {
	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, rlm_eap_sim_t, virtual_server) },
	{ FR_CONF_OFFSET("protected_success", FR_TYPE_BOOL, rlm_eap_sim_t, protected_success ), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;
static fr_dict_t *dict_eap_sim;

extern fr_dict_autoload_t rlm_eap_sim_dict[];
fr_dict_autoload_t rlm_eap_sim_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_eap_sim, .proto = "eap-sim", .base_dir = "eap/sim" },
	{ NULL }
};

static fr_dict_attr_t const *attr_eap_sim_mk;
static fr_dict_attr_t const *attr_eap_sim_subtype;

static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

static fr_dict_attr_t const *attr_eap_sim_any_id_req;
static fr_dict_attr_t const *attr_eap_sim_client_error_code;
static fr_dict_attr_t const *attr_eap_sim_counter;
static fr_dict_attr_t const *attr_eap_sim_encr_data;
static fr_dict_attr_t const *attr_eap_sim_fullauth_id_req;
static fr_dict_attr_t const *attr_eap_sim_identity;
static fr_dict_attr_t const *attr_eap_sim_mac;
static fr_dict_attr_t const *attr_eap_sim_nonce_mt;
static fr_dict_attr_t const *attr_eap_sim_nonce_s;
static fr_dict_attr_t const *attr_eap_sim_notification;
static fr_dict_attr_t const *attr_eap_sim_permanent_id_req;
static fr_dict_attr_t const *attr_eap_sim_rand;
static fr_dict_attr_t const *attr_eap_sim_result_ind;
static fr_dict_attr_t const *attr_eap_sim_selected_version;
static fr_dict_attr_t const *attr_eap_sim_version_list;

extern fr_dict_attr_autoload_t rlm_eap_sim_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_sim_dict_attr[] = {
	{ .out = &attr_eap_sim_mk, .name = "EAP-SIM-MK", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },

	{ .out = &attr_ms_mppe_send_key, .name = "MS-MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "MS-MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },

	{ .out = &attr_eap_sim_any_id_req, .name = "EAP-SIM-Any-ID-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_client_error_code, .name = "EAP-SIM-Client-Error-Code", .type = FR_TYPE_UINT16, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_counter, .name = "EAP-SIM-Counter", .type = FR_TYPE_UINT16, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_encr_data, .name = "EAP-SIM-Encr-Data", .type = FR_TYPE_TLV, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_fullauth_id_req, .name = "EAP-SIM-Fullauth-ID-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_identity, .name = "EAP-SIM-Identity", .type = FR_TYPE_STRING, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_mac, .name = "EAP-SIM-MAC", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_nonce_mt, .name = "EAP-SIM-Nonce-MT", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_nonce_s, .name = "EAP-SIM-Nonce-S", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_notification, .name = "EAP-SIM-Notification", .type = FR_TYPE_UINT16, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_permanent_id_req, .name = "EAP-SIM-Permanent-ID-Req", .type = FR_TYPE_BOOL, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_rand, .name = "EAP-SIM-RAND", .type = FR_TYPE_OCTETS, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_result_ind, .name = "EAP-SIM-Result-Ind", .type = FR_TYPE_BOOL, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_selected_version, .name = "EAP-SIM-Selected-Version", .type = FR_TYPE_UINT16, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_subtype, .name = "EAP-SIM-Subtype", .type = FR_TYPE_UINT32, .dict = &dict_eap_sim },
	{ .out = &attr_eap_sim_version_list, .name = "EAP-SIM-Version-List", .type = FR_TYPE_UINT16, .dict = &dict_eap_sim },
	{ NULL }
};

/*
 *	build a reply to be sent.
 */
static int eap_sim_compose(eap_session_t *eap_session, uint8_t const *hmac_extra, size_t hmac_extra_len)
{
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);
	fr_cursor_t		cursor;
	fr_cursor_t		to_encode;
	VALUE_PAIR		*head = NULL, *vp;
	REQUEST			*request = eap_session->request;
	fr_sim_encode_ctx_t	encoder_ctx = {
					.root = fr_dict_root(dict_eap_sim),
					.keys = &eap_sim_session->keys,

					.iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
						0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					.iv_included = false,

					.hmac_md = EVP_sha1(),
					.eap_packet = eap_session->this_round->request,
					.hmac_extra = hmac_extra,
					.hmac_extra_len = hmac_extra_len
				};

	ssize_t			ret;

	/* we will set the ID on requests, since we have to HMAC it */
	eap_session->this_round->set_request_id = true;

	fr_cursor_init(&cursor, &eap_session->request->reply->vps);
	fr_cursor_init(&to_encode, &head);

	while ((vp = fr_cursor_current(&cursor))) {
		if (!fr_dict_parent_common(fr_dict_root(dict_eap_sim), vp->da, true)) {
			fr_cursor_next(&cursor);
			continue;
		}
		vp = fr_cursor_remove(&cursor);

		/*
		 *	Silently discard encrypted attributes until
		 *	the peer should have k_encr.  These can be
		 *	added by policy, and seem to cause
		 *	wpa_supplicant to fail if sent before the challenge.
		 */
		if (!eap_sim_session->allow_encrypted && fr_dict_parent_common(attr_eap_sim_encr_data, vp->da, true)) {
			RWDEBUG("Silently discarding &reply:%s: Encrypted attributes not allowed in this round",
				vp->da->name);
			talloc_free(vp);
			continue;
		}

		fr_cursor_append(&to_encode, vp);
	}

	RDEBUG2("Encoding EAP-SIM attributes");
	log_request_pair_list(L_DBG_LVL_2, request, head, NULL);

	eap_session->this_round->request->type.num = FR_EAP_METHOD_SIM;
	eap_session->this_round->request->id = eap_sim_session->sim_id++ & 0xff;
	eap_session->this_round->set_request_id = true;

	ret = fr_sim_encode(eap_session->request, head, &encoder_ctx);
	fr_cursor_head(&to_encode);
	fr_cursor_free_list(&to_encode);

	if (ret < 0) {
		RPEDEBUG("Failed encoding EAP-SIM data");
		return -1;
	}
	return 0;
}

static int eap_sim_send_start(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	VALUE_PAIR		**vps, *vp;
	uint16_t		version;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);
	RADIUS_PACKET		*packet;

	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	RDEBUG2("Sending SIM-State");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;
	eap_sim_session->allow_encrypted = false;	/* In case this is after failed fast-resumption */

	/* these are the outgoing attributes */
	packet = eap_session->request->reply;
	vps = &packet->vps;
	rad_assert(vps != NULL);

	/*
	 *	Add appropriate TLVs for the EAP things we wish to send.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_version_list);
	vp->vp_uint16 = EAP_SIM_VERSION;
	fr_pair_add(vps, vp);

	/* record it in the ess */
	version = htons(EAP_SIM_VERSION);
	memcpy(eap_sim_session->keys.gsm.version_list, &version, sizeof(version));
	eap_sim_session->keys.gsm.version_list_len = 2;

	/*
	 *	Select the right type of identity request attribute
	 */
	switch (eap_sim_session->id_req) {
	case SIM_ANY_ID_REQ:
		vp = fr_pair_afrom_da(packet, attr_eap_sim_any_id_req);
		break;

	case SIM_PERMANENT_ID_REQ:
		vp = fr_pair_afrom_da(packet, attr_eap_sim_permanent_id_req);
		break;

	case SIM_FULLAUTH_ID_REQ:
		vp = fr_pair_afrom_da(packet, attr_eap_sim_fullauth_id_req);
		break;

	default:
		rad_assert(0);
	}
	vp->vp_bool = true;
	fr_pair_replace(vps, vp);

	/* the SUBTYPE, set to start. */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_subtype);
	vp->vp_uint16 = EAP_SIM_START;
	fr_pair_replace(vps, vp);

	/*
	 *	Encode the packet
	 */
	if (eap_sim_compose(eap_session, NULL, 0) < 0) {
		fr_pair_list_free(&packet->vps);
		return -1;
	}

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
static int eap_sim_send_challenge(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);
	VALUE_PAIR		**to_peer, *vp;
	RADIUS_PACKET		*packet;
	fr_sim_vector_src_t	src = SIM_VECTOR_SRC_AUTO;

	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	RDEBUG2("Acquiring GSM vector(s)");
	if ((fr_sim_vector_gsm_from_attrs(eap_session, request->control, 0, &eap_sim_session->keys, &src) != 0) ||
	    (fr_sim_vector_gsm_from_attrs(eap_session, request->control, 1, &eap_sim_session->keys, &src) != 0) ||
	    (fr_sim_vector_gsm_from_attrs(eap_session, request->control, 2, &eap_sim_session->keys, &src) != 0)) {
	    	REDEBUG("Failed retrieving SIM vectors");
		return RLM_MODULE_FAIL;
	}

	/*
	 *	All set, calculate keys!
	 */
	fr_sim_crypto_kdf_0_gsm(&eap_sim_session->keys);
	if (RDEBUG_ENABLED3) fr_sim_crypto_keys_log(request, &eap_sim_session->keys);

	RDEBUG2("Sending SIM-Challenge");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	to_peer is the data to the client
	 */
	packet = eap_session->request->reply;
	to_peer = &packet->vps;

	/*
	 *	Okay, we got the challenges! Put them into attributes.
	 */
	MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_rand));
	fr_pair_value_memcpy(vp, eap_sim_session->keys.gsm.vector[0].rand, SIM_VECTOR_GSM_RAND_SIZE, false);
	fr_pair_add(to_peer, vp);

	MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_rand));
	fr_pair_value_memcpy(vp, eap_sim_session->keys.gsm.vector[1].rand, SIM_VECTOR_GSM_RAND_SIZE, false);
	fr_pair_add(to_peer, vp);

	MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_rand));
	fr_pair_value_memcpy(vp, eap_sim_session->keys.gsm.vector[2].rand, SIM_VECTOR_GSM_RAND_SIZE, false);
	fr_pair_add(to_peer, vp);

	/*
	 *	Set subtype to challenge.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_subtype);
	vp->vp_uint16 = EAP_SIM_CHALLENGE;
	fr_pair_replace(to_peer, vp);

	/*
	 *	Indicate we'd like to use protected success messages
	 */
	if (eap_sim_session->send_result_ind) {
		MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_result_ind));
		vp->vp_bool = true;
		fr_pair_replace(to_peer, vp);
	}

	/*
	 *	Need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_mac);
	fr_pair_replace(to_peer, vp);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_sim_session->allow_encrypted = true;

	/*
	 *	Encode the packet
	 */
	if (eap_sim_compose(eap_session,
			    eap_sim_session->keys.gsm.nonce_mt, sizeof(eap_sim_session->keys.gsm.nonce_mt)) < 0) {
		fr_pair_list_free(&packet->vps);
		return -1;
	}

	return 0;
}

/** Send NONCE_S and re-key
 *
 */
static int eap_sim_send_reauthentication(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);
	VALUE_PAIR		**to_peer, *vp, *mk, *counter;
	RADIUS_PACKET		*packet;

	rad_assert(eap_session->request != NULL);
	rad_assert(eap_session->request->reply);

	/*
	 *	to_peer is the data to the client
	 */
	packet = eap_session->request->reply;
	to_peer = &packet->vps;

	/*
	 *	If any of the session resumption inputs (on our side)
	 *	are missing or malformed, return an error code
	 *	and the state machine will jump to the start state.
	 */
	mk = fr_pair_find_by_da(request->control, attr_eap_sim_mk, TAG_ANY);
	if (!mk) {
		RWDEBUG2("Missing &control:EAP-SIM-MK, skipping session resumption");
		return -1;
	}
	if (mk->vp_length != SIM_MK_SIZE) {
		RWDEBUG("&control:EAP-SIM-MK has incorrect length, expected %u bytes got %zu bytes",
			SIM_MK_SIZE, mk->vp_length);
		return -1;
	}
	counter = fr_pair_find_by_da(request->control, attr_eap_sim_counter, TAG_ANY);
	if (!counter) {
		RWDEBUG2("Missing &control:EAP-SIM-Counter, skipping session resumption");
		return -1;
	}

	/*
	 *	All set, calculate keys!
	 */
	fr_sim_crypto_keys_init_reauth(&eap_sim_session->keys, mk->vp_octets, counter->vp_uint16);
	fr_sim_crypto_kdf_0_reauth(&eap_sim_session->keys);
	if (RDEBUG_ENABLED3) fr_sim_crypto_keys_log(request, &eap_sim_session->keys);

	RDEBUG2("Sending SIM-Reauthentication");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set subtype to challenge.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_subtype);
	vp->vp_uint16 = EAP_SIM_REAUTH;
	fr_pair_replace(to_peer, vp);

	/*
	 *	Add nonce_s
	 */
	MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_nonce_s));
	fr_pair_value_memcpy(vp, eap_sim_session->keys.reauth.nonce_s,
			     sizeof(eap_sim_session->keys.reauth.nonce_s), false);
	fr_pair_replace(to_peer, vp);

	/*
	 *	Indicate we'd like to use protected success messages
	 */
	if (eap_sim_session->send_result_ind) {
		MEM(vp = fr_pair_afrom_da(packet, attr_eap_sim_result_ind));
		vp->vp_bool = true;
		fr_pair_replace(to_peer, vp);
	}

	/*
	 *	Need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_mac);
	fr_pair_replace(to_peer, vp);

	/*
	 *	We've sent the challenge so the peer should now be able
	 *	to accept encrypted attributes.
	 */
	eap_sim_session->allow_encrypted = true;

	/*
	 *	Encode the packet
	 */
	if (eap_sim_compose(eap_session, NULL, 0) < 0) {
		fr_pair_list_free(&packet->vps);
		return -1;
	}

	return 0;
}

/** Send a success notification
 *
 */
static int eap_sim_send_eap_success_notification(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	RADIUS_PACKET		*packet = eap_session->request->reply;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);
	fr_cursor_t		cursor;
	VALUE_PAIR		*vp;

	RDEBUG2("Sending SIM-Notification (Success)");
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	if (!fr_cond_assert(eap_sim_session->challenge_success)) return -1;

	fr_cursor_init(&cursor, &packet->vps);

	/*
	 *	Set the subtype to notification
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_subtype);
	vp->vp_uint16 = FR_EAP_SIM_SUBTYPE_VALUE_SIM_NOTIFICATION;
	fr_cursor_append(&cursor, vp);

	vp = fr_pair_afrom_da(packet, attr_eap_sim_notification);
	vp->vp_uint16 = FR_EAP_SIM_NOTIFICATION_VALUE_SUCCESS;
	fr_cursor_append(&cursor, vp);

	/*
	 *	Need to include an AT_MAC attribute so that it will get
	 *	calculated.
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_mac);
	fr_pair_replace(&packet->vps, vp);

	/*
	 *	Encode the packet
	 */
	if (eap_sim_compose(eap_session, NULL, 0) < 0) {
		fr_pair_list_free(&packet->vps);
		return -1;
	}

	return 0;
}

/** Send a success message
 *
 * The only work to be done is the add the appropriate SEND/RECV
 * radius attributes derived from the MSK.
 */
static int eap_sim_send_eap_success(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	uint8_t			*p;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	RDEBUG2("Sending SIM-Success");
	eap_session->this_round->request->code = FR_EAP_CODE_SUCCESS;
	eap_session->finished = true;

	p = eap_sim_session->keys.msk;
	eap_add_reply(eap_session->request, attr_ms_mppe_recv_key, p, EAP_TLS_MPPE_KEY_LEN);
	p += EAP_TLS_MPPE_KEY_LEN;
	eap_add_reply(eap_session->request, attr_ms_mppe_send_key, p, EAP_TLS_MPPE_KEY_LEN);

	return 0;
}

/** Send a failure message
 *
 */
static int eap_sim_send_eap_failure_notification(eap_session_t *eap_session)
{
	REQUEST			*request = eap_session->request;
	RADIUS_PACKET		*packet = eap_session->request->reply;
	fr_cursor_t		cursor;
	VALUE_PAIR		*vp;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	fr_cursor_init(&cursor, &packet->vps);

	vp = fr_pair_find_by_da(packet->vps, attr_eap_sim_notification, TAG_ANY);
	if (!vp) {
		vp = fr_pair_afrom_da(packet, attr_eap_sim_notification);
		vp->vp_uint16 = FR_EAP_SIM_NOTIFICATION_VALUE_GENERAL_FAILURE;
		fr_cursor_append(&cursor, vp);
	}

	/*
	 *	Change the failure notification depending where
	 *	we are in the state machine.
	 */
	if (eap_sim_session->challenge_success) {
		vp->vp_uint16 &= ~0x4000;	/* Unset phase bit */
	} else {
		vp->vp_uint16 |= 0x4000;	/* Set phase bit */
	}
	vp->vp_uint16 &= ~0x8000;               /* In both cases success bit should be low */

	RDEBUG2("Sending SIM-Notification (%pV)", &vp->data);
	eap_session->this_round->request->code = FR_EAP_CODE_REQUEST;

	/*
	 *	Set the subtype to notification
	 */
	vp = fr_pair_afrom_da(packet, attr_eap_sim_subtype);
	vp->vp_uint16 = FR_EAP_SIM_SUBTYPE_VALUE_SIM_NOTIFICATION;
	fr_cursor_append(&cursor, vp);

	/*
	 *	If we're after the challenge phase
	 *	then we need to include a MAC to
	 *	protect notifications.
	 */
	if (eap_sim_session->challenge_success) {
		vp = fr_pair_afrom_da(packet, attr_eap_sim_mac);
		fr_pair_replace(&packet->vps, vp);
	}

	/*
	 *	Encode the packet
	 */
	if (eap_sim_compose(eap_session, NULL, 0) < 0) {
		fr_pair_list_free(&packet->vps);
		return -1;
	}

	return 0;
}

static int eap_sim_send_eap_failure(eap_session_t *eap_session)
{
	REQUEST		*request = eap_session->request;

	RDEBUG2("Sending EAP-Failure");

	eap_session->this_round->request->code = FR_EAP_CODE_FAILURE;
	eap_session->finished = true;

	return 0;
}

/** Run the server state machine
 *
 */
static void eap_sim_state_enter(eap_session_t *eap_session, eap_sim_server_state_t new_state)
{
	REQUEST			*request = eap_session->request;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	if (new_state != eap_sim_session->state) {
		RDEBUG2("Changed state %s -> %s",
			fr_table_str_by_value(sim_state_table, eap_sim_session->state, "<unknown>"),
			fr_table_str_by_value(sim_state_table, new_state, "<unknown>"));
		eap_sim_session->state = new_state;
	} else {
		RDEBUG2("Reentering state %s",
			fr_table_str_by_value(sim_state_table, eap_sim_session->state, "<unknown>"));
	}

	switch (new_state) {
	/*
	 *	Send our version list
	 */
	case EAP_SIM_SERVER_START:
	start:
		if (eap_sim_send_start(eap_session) < 0) {
		notify_failure:
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
			return;
		}
		break;

	/*
	 *	Send the EAP-SIM Challenge message.
	 */
	case EAP_SIM_SERVER_CHALLENGE:
		if (eap_sim_send_challenge(eap_session) < 0) goto notify_failure;
		break;

	case EAP_SIM_SERVER_REAUTHENTICATE:
		if (eap_sim_send_reauthentication(eap_session) < 0) goto start;
		break;

	/*
	 *	Sent a protected success notification
	 */
	case EAP_SIM_SERVER_SUCCESS_NOTIFICATION:
		if (eap_sim_send_eap_success_notification(eap_session) < 0) goto notify_failure;
		break;

	/*
	 *	Send the EAP Success message (we're done)
	 */
	case EAP_SIM_SERVER_SUCCESS:
		if (eap_sim_send_eap_success(eap_session) < 0) goto notify_failure;
		return;

	/*
	 *	Send a general failure notification
	 */
	case EAP_SIM_SERVER_FAILURE_NOTIFICATION:
		if (eap_sim_send_eap_failure_notification(eap_session) < 0) {	/* Fallback to EAP-Failure */
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE);
		}
		return;

	/*
	 *	Send an EAP-Failure (we're done)
	 */
	case EAP_SIM_SERVER_FAILURE:
		eap_sim_send_eap_failure(eap_session);
		return;

	default:
		rad_assert(0);	/* Invalid transition */
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
		return;
	}
}

/** Process an EAP-Sim/Response/Start
 *
 * Verify that client chose a version, and provided a NONCE_MT,
 * and if so, then change states to challenge, and send the new
 * challenge, else, resend the Request/Start.
 */
static int process_eap_sim_start(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST			*request = eap_session->request;
	VALUE_PAIR		*nonce_vp, *selected_version_vp;
	eap_sim_session_t	*eap_sim_session;
	uint16_t		eap_sim_version;
	VALUE_PAIR		*id;
	fr_sim_id_type_t	type = SIM_ID_TYPE_UNKNOWN;
	fr_sim_method_hint_t	method = SIM_METHOD_HINT_UNKNOWN;

	eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	/*
	 *	For fullauth We require both the NONCE_MT
	 *	and SELECTED_VERSION from the peer, else
	 *	the packet is invalid.
	 */
	nonce_vp = fr_pair_find_by_da(vps, attr_eap_sim_nonce_mt, TAG_ANY);
	selected_version_vp = fr_pair_find_by_da(vps, attr_eap_sim_selected_version, TAG_ANY);
	if (!nonce_vp || !selected_version_vp) {
		REDEBUG2("Client did not select a version and send a NONCE");
		return -1;
	}

	eap_sim_version = selected_version_vp->vp_uint16;
	if (eap_sim_version != EAP_SIM_VERSION) {
		REDEBUG2("EAP-SIM-Version %i is unknown", eap_sim_version);
		return -1;
	}

	/*
	 *	Record it for later keying
	 */
	eap_sim_version = htons(eap_sim_version);
	memcpy(eap_sim_session->keys.gsm.version_select,
	       &eap_sim_version, sizeof(eap_sim_session->keys.gsm.version_select));

	/*
	 *	Double check the nonce size.
	 */
	if (nonce_vp->vp_length != 16) {
		REDEBUG("EAP-SIM nonce_mt must be 16 bytes, not %zu bytes", nonce_vp->vp_length);
		return -1;
	}
	memcpy(eap_sim_session->keys.gsm.nonce_mt, nonce_vp->vp_octets, 16);

	/*
	 *	See if we got an AT_IDENTITY
	 */
	id = fr_pair_find_by_da(vps, attr_eap_sim_identity, TAG_ANY);
	if (id) {
	 	if (fr_sim_id_type(&type, &method,
				   eap_session->identity, talloc_array_length(eap_session->identity) - 1) < 0) {
			RPWDEBUG2("Failed parsing identity");
		}

		/*
		 *	Update cryptographic identity
		 */
		talloc_const_free(eap_sim_session->keys.identity);
		eap_sim_session->keys.identity_len = id->vp_length;
		MEM(eap_sim_session->keys.identity = talloc_memdup(eap_sim_session, id->vp_strvalue, id->vp_length));
	}

	/*
	 *	@TODO Run a virtual server to see if we can use the
	 *	identity we just acquired, or whether we need to
	 *	negotiate the next permissive ID.
	 */

	/*
	 *	Negotiate the next permissive form
	 *	if identity, or fail.
	 */
	switch (eap_sim_session->id_req) {
	case SIM_ANY_ID_REQ:
		eap_sim_session->id_req = SIM_FULLAUTH_ID_REQ;
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_START);
		break;

	case SIM_FULLAUTH_ID_REQ:
		eap_sim_session->id_req = SIM_PERMANENT_ID_REQ;
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_START);
		break;

	case SIM_NO_ID_REQ:
	case SIM_PERMANENT_ID_REQ:
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_CHALLENGE);
//		REDEBUG2("Failed to negotiate a usable identity");
//		eap_sim_state_enter(eap_session, eap_sim_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
		break;
	}

	return 0;
}


/** Process an EAP-Sim/Response/Challenge
 *
 * Verify that MAC that we received matches what we would have
 * calculated from the packet with the SRESx appended.
 */
static int process_eap_sim_challenge(eap_session_t *eap_session, VALUE_PAIR *vps)
{
	REQUEST			*request = eap_session->request;
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	uint8_t			sres_cat[SIM_VECTOR_GSM_SRES_SIZE * 3];
	uint8_t			*p = sres_cat;

	uint8_t			calc_mac[SIM_MAC_DIGEST_SIZE];
	ssize_t			slen;
	VALUE_PAIR		*mac;

	memcpy(p, eap_sim_session->keys.gsm.vector[0].sres, SIM_VECTOR_GSM_SRES_SIZE);
	p += SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_sim_session->keys.gsm.vector[1].sres, SIM_VECTOR_GSM_SRES_SIZE);
	p += SIM_VECTOR_GSM_SRES_SIZE;
	memcpy(p, eap_sim_session->keys.gsm.vector[2].sres, SIM_VECTOR_GSM_SRES_SIZE);

	mac = fr_pair_find_by_da(vps, attr_eap_sim_mac, TAG_ANY);
	if (!mac) {
		REDEBUG("Missing AT_MAC attribute");
		return -1;
	}
	if (mac->vp_length != SIM_MAC_DIGEST_SIZE) {
		REDEBUG("EAP-SIM-MAC has incorrect length, expected %u bytes got %zu bytes",
			SIM_MAC_DIGEST_SIZE, mac->vp_length);
		return -1;
	}

	slen = fr_sim_crypto_sign_packet(calc_mac, eap_session->this_round->response, true, EVP_sha1(),
					 eap_sim_session->keys.k_aut, eap_sim_session->keys.k_aut_len,
					 sres_cat, sizeof(sres_cat));
	if (slen < 0) {
		RPEDEBUG("Failed calculating MAC");
		return -1;
	} else if (slen == 0) {
		REDEBUG("Missing EAP-SIM-MAC attribute in packet buffer");
		return -1;
	}

	if (memcmp(mac->vp_octets, calc_mac, sizeof(calc_mac)) == 0) {
		RDEBUG2("EAP-SIM-MAC matches calculated MAC");
	} else {
		REDEBUG("EAP-SIM-MAC does not match calculated MAC");
		RHEXDUMP_INLINE2(mac->vp_octets, SIM_MAC_DIGEST_SIZE, "Received");
		RHEXDUMP_INLINE2(calc_mac, SIM_MAC_DIGEST_SIZE, "Expected");
		return -1;
	}

	eap_sim_session->challenge_success = true;

	/*
	 *	If the peer wants a Success notification, then
	 *	send a success notification, otherwise send a
	 *	normal EAP-Success.
	 */
	if (fr_pair_find_by_da(vps, attr_eap_sim_result_ind, TAG_ANY)) {
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_SUCCESS_NOTIFICATION);
		return 1;
	}

	eap_sim_state_enter(eap_session, EAP_SIM_SERVER_SUCCESS);
	return 0;
}


/** Authenticate a previously sent challenge
 *
 */
static rlm_rcode_t mod_process(UNUSED void *instance, UNUSED void *thread, REQUEST *request)
{
	eap_session_t		*eap_session = eap_session_get(request);
	eap_sim_session_t	*eap_sim_session = talloc_get_type_abort(eap_session->opaque, eap_sim_session_t);

	fr_sim_decode_ctx_t	ctx = { .keys = &eap_sim_session->keys };
	VALUE_PAIR		*subtype_vp, *from_peer, *vp;
	fr_cursor_t		cursor;

	eap_sim_subtype_t	subtype;

	int			ret;

	/*
	 *	VPS is the data from the client
	 */
	from_peer = eap_session->request->packet->vps;

	fr_cursor_init(&cursor, &request->packet->vps);
	fr_cursor_tail(&cursor);

	ret = fr_sim_decode(eap_session->request,
			    &cursor,
			    dict_eap_sim,
			    eap_session->this_round->response->type.data,
			    eap_session->this_round->response->type.length,
			    &ctx);
	/*
	 *	RFC 4186 says we *MUST* notify, not just
	 *	send an EAP-Failure in this case where
	 *	we cannot decode an EAP-AKA packet.
	 */
	if (ret < 0) {
		RPEDEBUG2("Failed decoding EAP-SIM attributes");
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
		return RLM_MODULE_HANDLED;	/* We need to process more packets */
	}

	vp = fr_cursor_current(&cursor);
	if (vp && RDEBUG_ENABLED2) {
		RDEBUG2("Decoded EAP-SIM attributes");
		log_request_pair_list(L_DBG_LVL_2, request, vp, NULL);
	}

	subtype_vp = fr_pair_find_by_da(from_peer, attr_eap_sim_subtype, TAG_ANY);
	if (!subtype_vp) {
		REDEBUG("Missing EAP-SIM-Subtype");
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
		return RLM_MODULE_HANDLED;				/* We need to process more packets */
	}
	subtype = subtype_vp->vp_uint16;

	switch (eap_sim_session->state) {
	/*
	 *	Response to our advertised versions and request for an ID
	 *	This is very similar to Identity negotiation in EAP-AKA[']
	 */
	case EAP_SIM_SERVER_START:
		switch (subtype) {
		case EAP_SIM_START:
			if (process_eap_sim_start(eap_session, from_peer) == 0) return RLM_MODULE_HANDLED;
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
			return RLM_MODULE_HANDLED;	/* We need to process more packets */

		/*
		 *	Case 1 where we're allowed to send an EAP-Failure
		 *
		 *	This can happen in the case of a conservative
		 *	peer, where it refuses to provide the permanent
		 *	identity.
		 */
		case EAP_SIM_CLIENT_ERROR:
		{
			char buff[20];

			vp = fr_pair_find_by_da(from_peer, attr_eap_sim_client_error_code, TAG_ANY);
			if (!vp) {
				REDEBUG("EAP-SIM Peer rejected SIM-Start (%s) with client-error message but "
					"has not supplied a client error code",
					fr_table_str_by_value(sim_id_request_table, eap_sim_session->id_req, "<INVALID>"));
			} else {
				REDEBUG("Client rejected SIM-Start (%s) with error: %s (%i)",
					fr_table_str_by_value(sim_id_request_table, eap_sim_session->id_req, "<INVALID>"),
					fr_pair_value_enum(vp, buff), vp->vp_uint16);
			}
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE);
			return RLM_MODULE_REJECT;
		}

		case EAP_SIM_NOTIFICATION:
		notification:
		{
			char buff[20];

			vp = fr_pair_afrom_da(from_peer, attr_eap_sim_notification);
			if (!vp) {
				REDEBUG2("Received SIM-Notification with no notification code");
				eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
				return RLM_MODULE_HANDLED;			/* We need to process more packets */
			}

			/*
			 *	Case 2 where we're allowed to send an EAP-Failure
			 */
			if (!(vp->vp_uint16 & 0x8000)) {
				REDEBUG2("SIM-Notification %s (%i) indicates failure", fr_pair_value_enum(vp, buff),
					 vp->vp_uint16);
				eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE);
				return RLM_MODULE_REJECT;
			}

			/*
			 *	...if it's not a failure, then re-enter the
			 *	current state.
			 */
			REDEBUG2("Got SIM-Notification %s (%i)", fr_pair_value_enum(vp, buff), vp->vp_uint16);
			eap_sim_state_enter(eap_session, eap_sim_session->state);
			return RLM_MODULE_HANDLED;

		default:
		unexpected_subtype:
			/*
			 *	RFC 4186 says we *MUST* notify, not just
			 *	send an EAP-Failure in this case.
			 */
			REDEBUG("Unexpected subtype %pV", &subtype_vp->data);
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
			return RLM_MODULE_HANDLED;				/* We need to process more packets */
		}
		}

	/*
	 *	Process the response to our previous challenge.
	 */
	case EAP_SIM_SERVER_CHALLENGE:
		switch (subtype) {
		/*
		 *	A response to our EAP-Sim/Request/Challenge!
		 */
		case EAP_SIM_CHALLENGE:
			switch (process_eap_sim_challenge(eap_session, from_peer)) {
			case 1:
				return RLM_MODULE_HANDLED;

			case 0:
				return RLM_MODULE_OK;

			case -1:
				eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
				return RLM_MODULE_HANDLED;			/* We need to process more packets */
			}

		case EAP_SIM_CLIENT_ERROR:
		{
			char buff[20];

			vp = fr_pair_find_by_da(from_peer, attr_eap_sim_client_error_code, TAG_ANY);
			if (!vp) {
				REDEBUG("EAP-SIM Peer rejected SIM-Challenge with client-error message but "
					"has not supplied a client error code");
			} else {
				REDEBUG("Client rejected SIM-Challenge with error: %s (%i)",
					fr_pair_value_enum(vp, buff), vp->vp_uint16);
			}
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE);
			return RLM_MODULE_REJECT;
		}

		case EAP_SIM_NOTIFICATION:
			goto notification;

		default:
			goto unexpected_subtype;
		}

	/*
	 *	Peer acked our failure
	 */
	case EAP_SIM_SERVER_FAILURE_NOTIFICATION:
		switch (subtype) {
		case EAP_SIM_NOTIFICATION:
			RDEBUG2("SIM-Notification ACKed, sending EAP-Failure");
			eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE);
			return RLM_MODULE_REJECT;

		default:
			goto unexpected_subtype;
		}

	/*
	 *	Something bad happened...
	 */
	default:
		rad_assert(0);
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_FAILURE_NOTIFICATION);
		return RLM_MODULE_HANDLED;				/* We need to process more packets */
	}
}

/*
 *	Initiate the EAP-SIM session by starting the state machine
 *      and initiating the state.
 */
static rlm_rcode_t mod_session_init(void *instance, UNUSED void *thread, REQUEST *request)
{
	rlm_eap_sim_t			*inst = talloc_get_type_abort(instance, rlm_eap_sim_t);
	eap_session_t			*eap_session = eap_session_get(request);
	eap_sim_session_t		*eap_sim_session;

	fr_sim_id_type_t		type;
	fr_sim_method_hint_t		method;

	MEM(eap_sim_session = talloc_zero(eap_session, eap_sim_session_t));

	eap_session->opaque = eap_sim_session;

	/*
	 *	Set default configuration, we may allow these
	 *	to be toggled by attributes later.
	 */
	eap_sim_session->send_result_ind = inst->protected_success;
	eap_sim_session->id_req = SIM_ANY_ID_REQ;	/* Set the default */

	/*
	 *	This value doesn't have be strong, but it is
	 *	good if it is different now and then.
	 */
	eap_sim_session->sim_id = (fr_rand() & 0xff);

	/*
	 *	Save the keying material, because it could change on a subsequent retrieval.
	 */
	RDEBUG2("New EAP-SIM session");

	/*
	 *	Process the identity that we received in the
	 *	EAP-Identity-Response and use it to determine
	 *	the initial request we send to the Supplicant.
	 */
	if (fr_sim_id_type(&type, &method,
			   eap_session->identity, talloc_array_length(eap_session->identity) - 1) < 0) {
		RPWDEBUG2("Failed parsing identity, continuing anyway");
	}

	switch (method) {
	default:
		RWDEBUG("EAP-Identity-Response hints that EAP-%s should be started, but we're attempting EAP-SIM",
			fr_table_str_by_value(sim_id_method_hint_table, method, "<INVALID>"));
		break;

	case SIM_METHOD_HINT_SIM:
	case SIM_METHOD_HINT_UNKNOWN:
		break;
	}
	eap_session->process = mod_process;

	/*
	 *	Figure out what type of identity we have
	 *	and use it to determine the initial
	 *	request we send.
	 */
	switch (type) {
	/*
	 *	These types need to be transformed into something
	 *	usable before we can do anything.
	 */
	case SIM_ID_TYPE_UNKNOWN:
	case SIM_ID_TYPE_PSEUDONYM:
	case SIM_ID_TYPE_FASTAUTH:
	/*
	 *	Permanent ID means we can just send the challenge
	 */
	case SIM_ID_TYPE_PERMANENT:
		eap_sim_session->keys.identity_len = talloc_array_length(eap_session->identity) - 1;
		MEM(eap_sim_session->keys.identity = talloc_memdup(eap_sim_session, eap_session->identity,
								   eap_sim_session->keys.identity_len));
		eap_sim_state_enter(eap_session, EAP_SIM_SERVER_START);
		return RLM_MODULE_HANDLED;
	}

	return RLM_MODULE_HANDLED;
}

static int mod_load(void)
{
	if (fr_sim_init() < 0) return -1;

	sim_xlat_register();

	return 0;
}

static void mod_unload(void)
{
	sim_xlat_unregister();

	fr_sim_free();
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_sim;
rlm_eap_submodule_t rlm_eap_sim = {
	.name		= "eap_sim",
	.magic		= RLM_MODULE_INIT,

	.provides	= { FR_EAP_METHOD_SIM },
	.inst_size	= sizeof(rlm_eap_sim_t),
	.config		= submodule_config,

	.onload		= mod_load,
	.unload		= mod_unload,
	.session_init	= mod_session_init,	/* Initialise a new EAP session */
	.entry_point	= mod_process,		/* Process next round of EAP method */
};
