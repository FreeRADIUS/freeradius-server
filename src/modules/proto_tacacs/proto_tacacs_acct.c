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
 * @file proto_tacacs_acct.c
 * @brief TACACS+ accounting handler.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tacacs/tacacs.h>
#include "proto_tacacs.h"

typedef struct {
	uint32_t	session_timeout;		//!< Maximum time between the last response and next request.
	uint32_t	max_session;			//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	fr_state_tree_t	*state_tree;			//!< State tree to link multiple requests/responses.

	CONF_SECTION	*recv_request;
	void		*unlang_request;

	CONF_SECTION	*send_reply;
	void		*unlang_reply;
} proto_tacacs_acct_t;

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, proto_tacacs_acct_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, proto_tacacs_acct_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, proto_tacacs_acct_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER proto_tacacs_acct_config[] = {
	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t proto_tacacs_acct_dict[];
fr_dict_autoload_t proto_tacacs_acct_dict[] = {
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_tacacs_accounting_status;
static fr_dict_attr_t const *attr_tacacs_accounting_flags;
static fr_dict_attr_t const *attr_tacacs_data;
static fr_dict_attr_t const *attr_tacacs_server_message;
static fr_dict_attr_t const *attr_tacacs_state;

extern fr_dict_attr_autoload_t proto_tacacs_acct_dict_attr[];
fr_dict_attr_autoload_t proto_tacacs_acct_dict_attr[] = {
	{ .out = &attr_tacacs_accounting_status, .name = "TACACS-Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_accounting_flags, .name = "TACACS-Accounting-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "TACACS-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "TACACS-Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_state, .name = "TACACS-State", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },

	{ NULL }
};

static void accounting_failed(request_t *request, char const *msg)
{
	fr_pair_t	*vp;

	RPEDEBUG("%s", msg);

	/*
	 *	Set the server reply message.
	 */
	if (!fr_pair_find_by_da(&request->reply_pairs, attr_tacacs_server_message)) {
		MEM(pair_update_reply(&vp, attr_tacacs_server_message) >= 0);
		fr_pair_value_strdup(vp, "Accounting failed");
	}

	/*
	 *	Set the status.
	 */
	MEM(pair_update_reply(&vp, attr_tacacs_accounting_status) >= 0);
	vp->vp_uint8 = FR_ACCOUNTING_STATUS_VALUE_ERROR;
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	proto_tacacs_acct_t const	*inst = talloc_get_type_abort_const(mctx->instance, proto_tacacs_acct_t);
	rlm_rcode_t			rcode;
	CONF_SECTION			*unlang;
	fr_dict_enum_t const		*dv;
	fr_pair_t			*vp;
	fr_tacacs_packet_hdr_t const	*pkt = (fr_tacacs_packet_hdr_t const *) request->packet->data;

	REQUEST_VERIFY(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		request->component = "tacacs";

		/*
		 *	We always reply, unless specifically set to "Do not respond"
		 */
		request->reply->code = FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY;

		/*
		 *	Grab the VPS and data associated with the
		 *	TACACS-State attribute.  This is a synthetic /
		 *	internal attribute, which is composed of the
		 *	listener followed by the session ID
		 *
		 *	The session ID is unique per listener.
		 */
		if (!request->parent) {
			uint8_t buffer[sizeof(request->async->listen) + sizeof(pkt->session_id)];

			fr_assert(request->async->listen);
			memcpy(buffer, &request->async->listen, sizeof(request->async->listen));
			memcpy(buffer + sizeof(request->async->listen), &pkt->session_id, sizeof(pkt->session_id));

			vp = fr_pair_afrom_da(request->packet, attr_tacacs_state);
			if (vp) {
				fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);
				fr_pair_add(&request->request_pairs, vp);
			}

			fr_state_to_request(inst->state_tree, request);
		}

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(inst->recv_request), cf_filename(inst->recv_request));
		if (unlang_interpret_push_instruction(request, inst->unlang_request, RLM_MODULE_REJECT, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;

		case RLM_MODULE_HANDLED:
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			accounting_failed(request, "Failed to process the accounting packet");
			break;
		}

		/*
		 *	Run accounting foo { ... }
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, attr_tacacs_accounting_flags);
		if (!vp) goto setup_send;

		dv = fr_dict_enum_by_value(vp->da, &vp->data);
		if (!dv) goto setup_send;

		unlang = cf_section_find(request->server_cs, "accounting", dv->name);
		if (!unlang) {
			RDEBUG2("No 'accounting %s { ... }' section found - skipping...", dv->name);
			goto setup_send;
		}

		RDEBUG("Running 'accounting %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_PROCESS;
		FALL_THROUGH;

	case REQUEST_PROCESS:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;

		switch (rcode) {
		/*
		 *	The module has a number of OK return codes.
		 */
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_HANDLED:
			break;

		/*
		 *	The module failed, or said the request is
		 *	invalid, therefore we stop here.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			break;
		}

	setup_send:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(inst->send_reply), cf_filename(inst->send_reply));
		if (unlang_interpret_push_instruction(request, inst->unlang_reply, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
			RETURN_MODULE_FAIL;
		}

		request->request_state = REQUEST_SEND;
		FALL_THROUGH;

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) return UNLANG_ACTION_YIELD;

		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			break;

		case RLM_MODULE_HANDLED:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/* reply code is already set */
			break;
		}

		request->reply->timestamp = fr_time();

		/*
		 *	Save session-state list on Start discard it
		 *	for "Continue".
		 */
		if (!request->parent) {
			/*
			 *	Keep the state around for
			 *	authorization and accounting packets.
			 */
			if (pkt->seq_no >= 254) {
				fr_state_discard(inst->state_tree, request);

				/*
				 *	We can't create a valid response
				 */
			} else if (fr_request_to_state(inst->state_tree, request) < 0) {
				RWDEBUG("Failed saving state");
				request->reply->code = FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND;
			}
		}

		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_PACKET_TYPE_VALUE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			fr_state_discard(inst->state_tree, request);
			break;
		}

		break;

	default:
		RETURN_MODULE_FAIL;
	}

	RETURN_MODULE_OK;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *process_app_cs)
{
	proto_tacacs_acct_t	*inst = instance;

	/*
	 *	Usually we use the 'State' attribute. But, in this
	 *	case we are using the listener followed by the
	 *	TACACS-Session-ID as the state id.  It is 32-bits of
	 *	(allegedly) random value.  It MUST be unique per TCP
	 *	connection.
	 */
	inst->state_tree = fr_state_tree_init(inst, attr_tacacs_state, main_config->spawn_workers, inst->max_session,
					      inst->session_timeout, inst->state_server_id);

	return 0;
}

static virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Accounting-Request",
		.component = MOD_ACCOUNTING,
		.offset = offsetof(proto_tacacs_acct_t, recv_request),
		.instruction = offsetof(proto_tacacs_acct_t, unlang_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(proto_tacacs_acct_t, send_reply),
		.instruction = offsetof(proto_tacacs_acct_t, unlang_reply),
	},
	{
		.name = "accounting",
		.name2 = CF_IDENT_ANY,
		.component = MOD_ACCOUNTING,
	},

	COMPILE_TERMINATOR
};

extern fr_app_worker_t proto_tacacs_acct;
fr_app_worker_t proto_tacacs_acct = {
	.magic		= RLM_MODULE_INIT,
	.name		= "tacacs_acct",
	.config		= proto_tacacs_acct_config,
	.inst_size	= sizeof(proto_tacacs_acct_t),

	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
