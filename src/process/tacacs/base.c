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
 * @file src/lib/process/tacacs/base.c
 * @brief TACACS+ handler.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SARL (legal@networkradius.com)
 */

#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/process.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tacacs/tacacs.h>

/*
 *	This module runs many packet types, but it does mostly the
 *	same things for each one.  So we abstract the configuration.
 */
typedef struct {
	fr_dict_attr_t const *attr_process;
	int		reply;				//!< reply code

	fr_dict_attr_t const *attr_status;
	uint8_t		status_fail;

	char const	*fail_message;			//!< failed message

	CONF_SECTION	*recv_request;
	void		*unlang_request;

	CONF_SECTION	*send_reply;
	void		*unlang_reply;
} tacacs_unlang_t;

typedef struct {
	uint32_t	session_timeout;		//!< Maximum time between the last response and next request.
	uint32_t	max_session;			//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	fr_state_tree_t	*state_tree;			//!< State tree to link multiple requests/responses.

	tacacs_unlang_t	auth_start;
	tacacs_unlang_t	auth_cont;
	tacacs_unlang_t	autz;
	tacacs_unlang_t	acct;
} process_tacacs_t;

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, process_tacacs_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, process_tacacs_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, process_tacacs_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER config[] = {
	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t process_tacacs_dict[];
fr_dict_autoload_t process_tacacs_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;

static fr_dict_attr_t const *attr_tacacs_action;
static fr_dict_attr_t const *attr_tacacs_authentication_flags;
static fr_dict_attr_t const *attr_tacacs_authentication_type;
static fr_dict_attr_t const *attr_tacacs_authentication_service;
static fr_dict_attr_t const *attr_tacacs_authentication_status;

static fr_dict_attr_t const *attr_tacacs_authorization_status;
static fr_dict_attr_t const *attr_tacacs_accounting_status;
static fr_dict_attr_t const *attr_tacacs_accounting_flags;

static fr_dict_attr_t const *attr_tacacs_client_port;
static fr_dict_attr_t const *attr_tacacs_data;
static fr_dict_attr_t const *attr_tacacs_privilege_level;
static fr_dict_attr_t const *attr_tacacs_remote_address;
static fr_dict_attr_t const *attr_tacacs_server_message;
static fr_dict_attr_t const *attr_tacacs_session_id;
static fr_dict_attr_t const *attr_tacacs_state;

extern fr_dict_attr_autoload_t process_tacacs_dict_attr[];
fr_dict_attr_autoload_t process_tacacs_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_tacacs_action, .name = "Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_flags, .name = "Authentication-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_type, .name = "Authentication-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_service, .name = "Authentication-Service", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },

	{ .out = &attr_tacacs_authentication_status, .name = "Authentication-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authorization_status, .name = "Authorization-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },

	{ .out = &attr_tacacs_accounting_status, .name = "Accounting-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_accounting_flags, .name = "Accounting-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },

	{ .out = &attr_tacacs_client_port, .name = "Client-Port", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "Data", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_privilege_level, .name = "Privilege-Level", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_remote_address, .name = "Remote-Address", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "Packet.Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },

	{ NULL }
};

static void message_failed(request_t *request, tacacs_unlang_t const *ctx, char const *msg)
{
	fr_pair_t	*vp;

	if (!msg) msg = ctx->fail_message;

	RPEDEBUG("%s", msg);

	/*
	 *	Set the server reply message.  Note that we do not tell the user *why* they failed authentication.
	 */
	if (!fr_pair_find_by_da(&request->reply_pairs, attr_tacacs_server_message)) {
		MEM(pair_update_reply(&vp, attr_tacacs_server_message) >= 0);
		fr_pair_value_strdup(vp, msg);
	}

	/*
	 *	Set the status.
	 */
	MEM(pair_update_reply(&vp, ctx->attr_status) >= 0);
	vp->vp_uint8 = ctx->status_fail;
}


static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	process_tacacs_t const	*inst = talloc_get_type_abort_const(mctx->instance, process_tacacs_t);
	fr_pair_t			*vp;
	rlm_rcode_t			rcode;
	CONF_SECTION			*unlang;
	fr_dict_enum_t const		*dv = NULL;
	fr_dcursor_t			cursor;
	tacacs_unlang_t const		*ctx;
	fr_tacacs_packet_hdr_t const	*pkt = (fr_tacacs_packet_hdr_t const *) request->packet->data;

	REQUEST_VERIFY(request);

	/*
	 *	Wrapper to distinguish between Authentication Start & Continue.
	 */
	switch (request->packet->code) {
	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_START:
		ctx = &inst->auth_start;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHENTICATION_CONTINUE:
		ctx = &inst->auth_start;
		break;

	case FR_PACKET_TYPE_VALUE_AUTHORIZATION_REQUEST: 
		ctx = &inst->autz;
		break;

	case FR_PACKET_TYPE_VALUE_ACCOUNTING_REQUEST: 
		ctx = &inst->acct;
		break;

	default:
		REDEBUG("Ignoring packet - not a request from a client");
		RETURN_MODULE_FAIL;
	}

	switch (request->request_state) {
	case REQUEST_INIT:
		request->component = "tacacs";

		/*
		 *	We always reply, unless specifically set to "Do not respond"
		 */
		request->reply->code = ctx->reply;

		/*
		 *	Grab the VPS and data associated with the
		 *	State attribute.  This is a synthetic /
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

			vp = fr_pair_afrom_da(request->request_ctx, attr_tacacs_state);
			if (vp) {
				fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);
				fr_pair_append(&request->request_pairs, vp);
			}

			fr_state_to_request(inst->state_tree, request);
		}

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(ctx->recv_request), cf_filename(ctx->recv_request));
		if (unlang_interpret_push_instruction(request, ctx->unlang_request, RLM_MODULE_REJECT, UNLANG_TOP_FRAME) < 0) {
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

		if (rcode == RLM_MODULE_YIELD) RETURN_MODULE_YIELD;

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_DISALLOW:
		default:
			message_failed(request, ctx, NULL);
			goto setup_send;
		}

		/*
		 *	Only some packet types run authenticate foo { ... }
		 */
		if (ctx->attr_process == attr_tacacs_authentication_type) {
			fr_pair_t			*auth_type;

			/*
			 *	Find Authentication-Type, and complain if they have too many.
			 */
			auth_type = NULL;
			for (vp = fr_dcursor_iter_by_da_init(&cursor, &request->control_pairs, attr_auth_type);
			     vp;
			     vp = fr_dcursor_next(&cursor)) {
				if (!auth_type) {
					auth_type = vp;
					continue;
				}

				RWDEBUG("Ignoring extra %pP", vp);
			}

			/*
			 *	No Auth-Type, force it to reject.
			 */
			if (!auth_type) {
				vp = fr_pair_find_by_da(&request->request_pairs, attr_tacacs_authentication_type);
				if (!vp) {
					message_failed(request, ctx, "No Auth-Type or Authentication-Type configured: rejecting authentication.");
					goto setup_send;
				}

				/*
				 *	Look up the name of Authentication-Type
				 */
				dv = fr_dict_enum_by_value(vp->da, &vp->data);
				if (!dv) {
					message_failed(request, ctx, "Unknown value for Authentication-Type: rejecting authentication.");
					goto setup_send;
				}

				/*
				 *	Use that name to search for a matching Auth-Type which has been defined.
				 */
				dv = fr_dict_enum_by_name(attr_auth_type, dv->name, -1);
				if (!dv) {
					message_failed(request, ctx, "No Auth-Type found to match Authentication-Type: rejecting authentication.");
					goto setup_send;
				}
			} else {
				/*
				 *	Find the appropriate Auth-Type by name.
				 */
				vp = auth_type;
				dv = fr_dict_enum_by_value(attr_auth_type, &vp->data);
			}

			if (!dv) {
				message_failed(request, ctx, "Unknown Auth-Type found: rejecting the user");
				goto setup_send;
			}

			unlang = cf_section_find(request->server_cs, "authenticate", dv->name);
			if (!unlang) {
				message_failed(request, ctx, "No matching 'authenticate' section found: rejecting the user");
				goto setup_send;
			}

			RDEBUG("Running 'authenticate %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
			if (unlang_interpret_push_section(request, unlang, RLM_MODULE_NOTFOUND, UNLANG_TOP_FRAME) < 0) {
				RETURN_MODULE_FAIL;
			}

		} else if (ctx->attr_process == attr_tacacs_accounting_flags) {
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
			
		} else {
			goto setup_send;
		}

		request->request_state = REQUEST_PROCESS;
		FALL_THROUGH;

	case REQUEST_PROCESS:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) {
			*p_result = RLM_MODULE_HANDLED;
			return UNLANG_ACTION_STOP_PROCESSING;
		}

		if (rcode == RLM_MODULE_YIELD) RETURN_MODULE_YIELD;

		switch (rcode) {
			/*
			 *	An authentication module FAIL
			 *	return code, or any return code that
			 *	is not expected from authentication,
			 *	is the same as an explicit REJECT!
			 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_UPDATED:
		case RLM_MODULE_DISALLOW:
		default:
			message_failed(request, ctx, NULL);
			goto setup_send;

		case RLM_MODULE_OK:
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;
		}

	setup_send:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(ctx->send_reply), cf_filename(ctx->send_reply));
		if (unlang_interpret_push_instruction(request, ctx->unlang_reply, RLM_MODULE_NOOP, UNLANG_TOP_FRAME) < 0) {
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

		if (rcode == RLM_MODULE_YIELD) RETURN_MODULE_YIELD;

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
	process_tacacs_t	*inst = instance;

	/*
	 *	Usually we use the 'State' attribute. But, in this
	 *	case we are using the listener followed by the
	 *	Session-ID as the state id.  It is 32-bits of
	 *	(allegedly) random value.  It MUST be unique per TCP
	 *	connection.
	 */
	inst->state_tree = fr_state_tree_init(inst, attr_tacacs_state, main_config->spawn_workers, inst->max_session,
					      inst->session_timeout, inst->state_server_id);

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *process_app_cs)
{
	process_tacacs_t	*inst = instance;
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(process_app_cs));

	fr_assert(process_app_cs);
	fr_assert(server_cs);

	fr_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	/*
	 *	Set up the parameters for the various packet types.
	 */
	inst->auth_start = (tacacs_unlang_t) {
		.attr_process = attr_tacacs_authentication_type,
		.fail_message = "Failed to authenticate the user",
		.reply = FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY,
		.attr_status = attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	};

	inst->auth_cont = (tacacs_unlang_t) {
		.attr_process = attr_tacacs_authentication_type,
		.fail_message = "Failed to authenticate the user",
		.reply = FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY,
		.attr_status = attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	};

	inst->autz = (tacacs_unlang_t) {
		.fail_message = "Failed to authorize the user",
		.reply = FR_PACKET_TYPE_VALUE_AUTHORIZATION_REPLY,
		.attr_status = attr_tacacs_authorization_status,
		.status_fail = FR_TAC_PLUS_AUTHOR_STATUS_FAIL,
	};

	inst->acct = (tacacs_unlang_t) {
		.attr_process = attr_tacacs_accounting_flags,
		.fail_message = "Failed to process the accounting packet",
		.reply = FR_PACKET_TYPE_VALUE_ACCOUNTING_REPLY,
		.attr_status = attr_tacacs_accounting_status,
		.status_fail = FR_TAC_PLUS_ACCT_STATUS_ERROR,
	};

	return 0;
}

static virtual_server_compile_t compile_list[] = {
	/**
	 *	Basically, the TACACS+ protocol use same type "authenticate" to handle
	 *	Start and Continue requests. (yep, you're right. it's horrible)
	 *	Therefore, we split the same "auth" type into two different sections just
	 *	to allow the user to have different logic for that.
	 *
	 *	If you want to cry, just take a look at
	 *	https://tools.ietf.org/id/draft-ietf-opsawg-07.html#rfc.section.4
	 */
	{
		.name = "recv",
		.name2 = "Authentication-Start",
		.component = MOD_AUTHENTICATE,
		.offset = offsetof(process_tacacs_t, auth_start.recv_request),
		.instruction = offsetof(process_tacacs_t, auth_start.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Authentication-Start-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(process_tacacs_t, auth_start.send_reply),
		.instruction = offsetof(process_tacacs_t, auth_start.unlang_reply),
	},
	{
		.name = "recv",
		.name2 = "Authentication-Continue",
		.component = MOD_AUTHENTICATE,
		.offset = offsetof(process_tacacs_t, auth_cont.recv_request),
		.instruction = offsetof(process_tacacs_t, auth_cont.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Authentication-Continue-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(process_tacacs_t, auth_cont.send_reply),
		.instruction = offsetof(process_tacacs_t, auth_cont.unlang_reply),
	},

	{
		.name = "authenticate",
		.name2 = CF_IDENT_ANY,
		.component = MOD_AUTHENTICATE,
	},

	/* authorization */
	
	{
		.name = "recv",
		.name2 = "Authorization-Request",
		.component = MOD_AUTHORIZE,
		.offset = offsetof(process_tacacs_t, autz.recv_request),
		.instruction = offsetof(process_tacacs_t, autz.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Authorization-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(process_tacacs_t, autz.send_reply),
		.instruction = offsetof(process_tacacs_t, autz.unlang_reply),
	},

	/* accounting */

	{
		.name = "recv",
		.name2 = "Accounting-Request",
		.component = MOD_ACCOUNTING,
		.offset = offsetof(process_tacacs_t, acct.recv_request),
		.instruction = offsetof(process_tacacs_t, acct.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(process_tacacs_t, acct.send_reply),
		.instruction = offsetof(process_tacacs_t, acct.unlang_reply),
	},
	{
		.name = "accounting",
		.name2 = CF_IDENT_ANY,
		.component = MOD_ACCOUNTING,
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_tacacs;
fr_process_module_t process_tacacs = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_tacacs",
	.config		= config,
	.inst_size	= sizeof(process_tacacs_t),
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_tacacs,
};
