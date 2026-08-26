/*
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
 */

/**
 * $Id$
 *
 * @file rlm_eap_psk.c
 * @brief EAP-PSK (RFC 4764) interface to the EAP module
 *
 * The protocol state machine, message parsing, and cryptography all live
 * in the eap_psk process module (src/process/eap_psk).  This submodule
 * derives the next Packet-Type from the session state, pushes the request
 * into the configured eap-psk virtual server, and translates the reply
 * Packet-Type back into an EAP result.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/protocol/eap/psk/freeradius.h>

#include "crypto.h"

typedef struct {
	virtual_server_t	*virtual_server;	//!< eap-psk virtual server providing the
							///< policy sections for the exchange.
} rlm_eap_psk_t;

static conf_parser_t submodule_config[] = {
	{ FR_CONF_OFFSET_TYPE_FLAGS("virtual_server", FR_TYPE_VOID, CONF_FLAG_REQUIRED, rlm_eap_psk_t, virtual_server),
				    .func = virtual_server_cf_parse,
				    .uctx = &(virtual_server_cf_parse_uctx_t){
					    .process_module_name = "eap_psk",
				    } },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_eap_psk;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_eap_psk_dict[];
fr_dict_autoload_t rlm_eap_psk_dict[] = {
	{ .out = &dict_eap_psk, .base_dir = "eap/psk", .proto = "eap-psk" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_ms_mppe_send_key;
static fr_dict_attr_t const *attr_ms_mppe_recv_key;

extern fr_dict_attr_autoload_t rlm_eap_psk_dict_attr[];
fr_dict_attr_autoload_t rlm_eap_psk_dict_attr[] = {
	{ .out = &attr_ms_mppe_send_key, .name = "Vendor-Specific.Microsoft.MPPE-Send-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_ms_mppe_recv_key, .name = "Vendor-Specific.Microsoft.MPPE-Recv-Key", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	DICT_AUTOLOAD_TERMINATOR
};

/*
 *	The MSK is split into a 32-byte MS-MPPE-Recv-Key and a 32-byte
 *	MS-MPPE-Send-Key, as is done with all other EAP methods.
 */
#define EAP_PSK_MPPE_KEY_LEN	32

/** Translate the state machine's reply Packet-Type into an EAP result
 *
 * Runs after the virtual server (and the eap_psk process module inside
 * of it) finishes with this round.
 */
static unlang_action_t mod_encode(unlang_result_t *p_result, UNUSED module_ctx_t const *mctx, request_t *request)
{
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session = eap_session->opaque ?
					   talloc_get_type_abort(eap_session->opaque, eap_psk_session_t) : NULL;

	switch (request->reply->code) {
	case FR_PACKET_TYPE_VALUE_SUCCESS:
		if (session && (session->state == EAP_PSK_STATE_DONE)) {
			/*
			 *	Deliver the keying material.  The MSK is split
			 *	into the MS-MPPE-Recv-Key and MS-MPPE-Send-Key
			 *	halves.
			 */
			eap_add_reply(request->parent, attr_ms_mppe_recv_key,
				      session->msk, EAP_PSK_MPPE_KEY_LEN);
			eap_add_reply(request->parent, attr_ms_mppe_send_key,
				      session->msk + EAP_PSK_MPPE_KEY_LEN, EAP_PSK_MPPE_KEY_LEN);

			RETURN_UNLANG_OK;
		}
		RETURN_UNLANG_HANDLED;

	/*
	 *	The message failed validation and was not processed
	 *	(RFC 4764 Section 4.1).  A true silent discard cannot be
	 *	expressed through the EAP module, which sends a canned
	 *	EAP-Failure and discards the session on any failure
	 *	result, so an invalid message ends the session, as with
	 *	every other EAP method.
	 */
	case FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND:
		RETURN_UNLANG_INVALID;

	case FR_PACKET_TYPE_VALUE_FAILURE:
		RETURN_UNLANG_REJECT;

	default:
		RETURN_UNLANG_FAIL;
	}
}

/** Derive the next Packet-Type from the session state, and enter the virtual server
 *
 */
static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_eap_psk_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_eap_psk_t);
	eap_session_t		*eap_session = eap_session_get(request->parent);
	eap_psk_session_t	*session;

	if (!eap_session->opaque) {
		request->packet->code = FR_PACKET_TYPE_VALUE_IDENTITY_REQUEST;
		goto yield;
	}

	/*
	 *	Every EAP-PSK message from the peer must be of type
	 *	EAP-PSK, and carry at least a Flags byte.
	 */
	if ((eap_session->this_round->response->type.num != FR_EAP_METHOD_PSK) ||
	    !eap_session->this_round->response->type.data ||
	    (eap_session->this_round->response->type.length < 1)) {
		REDEBUG("Invalid EAP-PSK response");
		RETURN_UNLANG_INVALID;
	}

	session = talloc_get_type_abort(eap_session->opaque, eap_psk_session_t);
	switch (session->state) {
	case EAP_PSK_STATE_IDENTITY_REQUEST_SENT:
		request->packet->code = FR_PACKET_TYPE_VALUE_IDENTITY_RESPONSE;
		break;

	case EAP_PSK_STATE_RESULT_INDICATION_SENT:
		request->packet->code = FR_PACKET_TYPE_VALUE_RESULT_ACKNOWLEDGEMENT;
		break;

	default:
		REDEBUG("Unexpected EAP-PSK session state");
		RETURN_UNLANG_FAIL;
	}

yield:
	/*
	 *	Once the state machine finishes with this round, translate
	 *	the reply Packet-Type into an EAP result.
	 */
	(void)unlang_module_yield(request, mod_encode, NULL, 0, NULL);

	if (unlang_call_push(NULL, request, virtual_server_cs(inst->virtual_server), UNLANG_SUB_FRAME) < 0) {
		unlang_interpet_frame_discard(request);
		RETURN_UNLANG_FAIL;
	}

	return UNLANG_ACTION_PUSHED_CHILD;
}

static unlang_action_t mod_session_init(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	eap_session_t *eap_session = eap_session_get(request->parent);

	fr_assert(eap_session != NULL);

	eap_session->process = mod_process;

	return eap_session->process(p_result, mctx, request);
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 */
extern rlm_eap_submodule_t rlm_eap_psk;
rlm_eap_submodule_t rlm_eap_psk = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "eap_psk",
		.inst_size	= sizeof(rlm_eap_psk_t),
		.config		= submodule_config,
	},
	.provides	= { FR_EAP_METHOD_PSK },
	.session_init	= mod_session_init,		/* Initialise a new EAP session */
	.namespace	= &dict_eap_psk
};
