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
 * @file proto_tacacs_auth.c
 * @brief TACACS+ authentication handler.
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

/*
 *	This module runs both Start and Continue, but it does mostly
 *	the same things for each one.  So we abstract the
 *	configuration.
 */
typedef struct {
	CONF_SECTION	*recv_request;
	void		*unlang_request;

	CONF_SECTION	*send_reply;
	void		*unlang_reply;
} fr_tacacs_auth_request_ctx_t;

typedef struct {
	uint32_t	session_timeout;		//!< Maximum time between the last response and next request.
	uint32_t	max_session;			//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	fr_state_tree_t	*state_tree;			//!< State tree to link multiple requests/responses.

	fr_tacacs_auth_request_ctx_t	start;
	fr_tacacs_auth_request_ctx_t	cont;
} proto_tacacs_auth_t;

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, proto_tacacs_auth_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, proto_tacacs_auth_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, proto_tacacs_auth_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER proto_tacacs_auth_config[] = {
	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t proto_tacacs_auth_dict[];
fr_dict_autoload_t proto_tacacs_auth_dict[] = {
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
static fr_dict_attr_t const *attr_tacacs_client_port;
static fr_dict_attr_t const *attr_tacacs_data;
static fr_dict_attr_t const *attr_tacacs_privilege_level;
static fr_dict_attr_t const *attr_tacacs_remote_address;
static fr_dict_attr_t const *attr_tacacs_server_message;
static fr_dict_attr_t const *attr_tacacs_session_id;
static fr_dict_attr_t const *attr_tacacs_user_name;
static fr_dict_attr_t const *attr_tacacs_state;

extern fr_dict_attr_autoload_t proto_tacacs_auth_dict_attr[];
fr_dict_attr_autoload_t proto_tacacs_auth_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_tacacs_action, .name = "TACACS-Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_flags, .name = "TACACS-Authentication-Flags", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_type, .name = "TACACS-Authentication-Type", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_service, .name = "TACACS-Authentication-Service", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_authentication_status, .name = "TACACS-Authentication-Status", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_client_port, .name = "TACACS-Client-Port", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_data, .name = "TACACS-Data", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_privilege_level, .name = "TACACS-Privilege-Level", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_remote_address, .name = "TACACS-Remote-Address", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "TACACS-Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "TACACS-Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_user_name, .name = "TACACS-User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },

	{ NULL }
};

static void authentication_failed(REQUEST *request, char const *msg)
{
	VALUE_PAIR	*vp;

	RPEDEBUG("%s", msg);

	/*
	 *	Set the server reply message.  Note that we do not tell the user *why* they failed authentication.
	 */
	if (!fr_pair_find_by_da(request->reply->vps, attr_tacacs_server_message, TAG_ANY)) {
		MEM(pair_update_reply(&vp, attr_tacacs_server_message) >= 0);
		fr_pair_value_strdup(vp, "Authentication failed");
	}

	/*
	 *	Set the status.
	 */
	MEM(pair_update_reply(&vp, attr_tacacs_authentication_status) >= 0);
	vp->vp_uint8 = FR_TAC_PLUS_AUTHEN_STATUS_FAIL;
}


static rlm_rcode_t mod_process(module_ctx_t const *mctx, REQUEST *request)
{
	proto_tacacs_auth_t const	*inst = talloc_get_type_abort_const(mctx->instance, proto_tacacs_auth_t);
	VALUE_PAIR			*vp;
	VALUE_PAIR			*auth_type;
	rlm_rcode_t			rcode;
	CONF_SECTION			*unlang;
	fr_dict_enum_t const		*dv = NULL;
	fr_cursor_t			cursor;
	fr_tacacs_auth_request_ctx_t const *auth_ctx;
	fr_tacacs_packet_hdr_t const	*pkt = (fr_tacacs_packet_hdr_t const *) request->packet->data;

	REQUEST_VERIFY(request);

	/*
	 *	Wrapper to distinguish between Authentication Start & Continue.
	 */
	if (request->packet->code == FR_PACKET_TYPE_VALUE_AUTHENTICATION_START) {
		auth_ctx = &inst->start;
	} else {
		auth_ctx = &inst->cont;
	}

	switch (request->request_state) {
	case REQUEST_INIT:
		request->component = "tacacs";

		/*
		 *	We always reply, unless specifically set to "Do not respond"
		 */
		request->reply->code = FR_PACKET_TYPE_VALUE_AUTHENTICATION_REPLY;

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
				fr_pair_add(&request->packet->vps, vp);
			}

			fr_state_to_request(inst->state_tree, request);
		}

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(auth_ctx->recv_request), cf_filename(auth_ctx->recv_request));
		unlang_interpret_push_instruction(request, auth_ctx->unlang_request, RLM_MODULE_REJECT, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		FALL_THROUGH;

	case REQUEST_RECV:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

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
			authentication_failed(request, "Failed to authenticate the user");
			goto setup_send;
		}

		/*
		 *	Find TACACS-Authentication-Type, and complain if they have too many.
		 */
		auth_type = NULL;
		for (vp = fr_cursor_iter_by_da_init(&cursor, &request->control, attr_auth_type);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
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
			vp = fr_pair_find_by_da(request->packet->vps, attr_tacacs_authentication_type, TAG_ANY);
			if (!vp) {
				authentication_failed(request, "No Auth-Type or TACACS-Authentication-Type configured: rejecting authentication.");
				goto setup_send;
			}

			/*
			 *	Look up the name of TACACS-Authentication-Type
			 */
			dv = fr_dict_enum_by_value(vp->da, &vp->data);
			if (!dv) {
				authentication_failed(request, "Unknown value for TACACS-Authentication-Type: rejecting authentication.");
				goto setup_send;
			}

			/*
			 *	Use that name to search for a matching Auth-Type which has been defined.
			 */
			dv = fr_dict_enum_by_name(attr_auth_type, dv->name, -1);
			if (!dv) {	
				authentication_failed(request, "No Auth-Type found to match TACACS-Authentication-Type: rejecting authentication.");
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
			authentication_failed(request, "Unknown Auth-Type found: rejecting the user");
			goto setup_send;
		}

		unlang = cf_section_find(request->server_cs, "authenticate", dv->name);
		if (!unlang) {
			authentication_failed(request, "No matching 'authenticate' section found: rejecting the user");
			goto setup_send;
		}

		RDEBUG("Running 'authenticate %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_interpret_push_section(request, unlang, RLM_MODULE_NOTFOUND, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_PROCESS;
		FALL_THROUGH;

	case REQUEST_PROCESS:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

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
			authentication_failed(request, "Failed to authenticate the user");

			/*
			 *	Maybe the shared secret is wrong?
			 */
			if (RDEBUG_ENABLED2 &&
			    ((vp = fr_pair_find_by_da(request->packet->vps, attr_tacacs_user_name, TAG_ANY)) != NULL) &&
			    (fr_utf8_str((uint8_t const *) vp->vp_strvalue, vp->vp_length) < 0)) {
				RWDEBUG("Unprintable characters in the %s. "
					"Double-check the shared secret on the server "
					"and the NAS!", attr_tacacs_user_name->name);
			}
			goto setup_send;

		case RLM_MODULE_OK:
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;
		}

	setup_send:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(auth_ctx->send_reply), cf_filename(auth_ctx->send_reply));
		unlang_interpret_push_instruction(request, auth_ctx->unlang_reply, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_SEND;
		FALL_THROUGH;

	case REQUEST_SEND:
		rcode = unlang_interpret(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return RLM_MODULE_HANDLED;

		if (rcode == RLM_MODULE_YIELD) return RLM_MODULE_YIELD;

		fr_assert(request->log.unlang_indent == 0);

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
		return RLM_MODULE_FAIL;
	}

	return RLM_MODULE_OK;
}

static virtual_server_compile_t compile_list[] = {
	/**
	 *	Basically, the TACACS+ protocol use same type "authenticate" to handle
	 *	Start and Continue requests. (yep, you're right. it's horrible)
	 *	Therefore, we split the same "auth" type into two different sections just
	 *	to allow the user to have different logic for that.
	 *
	 *	If you want to cry, just take a look at
	 *	https://tools.ietf.org/id/draft-ietf-opsawg-tacacs-07.html#rfc.section.4
	 */
	{
		.name = "recv",
		.name2 = "Authentication-Start",
		.component = MOD_AUTHENTICATE,
		.offset = offsetof(proto_tacacs_auth_t, start.recv_request),
		.instruction = offsetof(proto_tacacs_auth_t, start.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Authentication-Start-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(proto_tacacs_auth_t, start.send_reply),
		.instruction = offsetof(proto_tacacs_auth_t, start.unlang_reply),
	},
	{
		.name = "recv",
		.name2 = "Authentication-Continue",
		.component = MOD_AUTHENTICATE,
		.offset = offsetof(proto_tacacs_auth_t, cont.recv_request),
		.instruction = offsetof(proto_tacacs_auth_t, cont.unlang_request),
	},
	{
		.name = "send",
		.name2 = "Authentication-Continue-Reply",
		.component = MOD_POST_AUTH,
		.offset = offsetof(proto_tacacs_auth_t, cont.send_reply),
		.instruction = offsetof(proto_tacacs_auth_t, cont.unlang_reply),
	},

	{
		.name = "authenticate",
		.name2 = CF_IDENT_ANY,
		.component = MOD_AUTHENTICATE,
	},

	COMPILE_TERMINATOR
};

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *process_app_cs)
{
	proto_tacacs_auth_t	*inst = instance;

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

static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *process_app_cs)
{
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(process_app_cs));
	CONF_SECTION		*server_cs;

	fr_assert(process_app_cs);
	fr_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	fr_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	attr_tacacs_state = fr_dict_attr_by_name(dict_tacacs, "TACACS-State");
	if (!attr_tacacs_state) {
		fr_dict_attr_flags_t	flags;

		memset(&flags, 0, sizeof(flags));
		flags.internal = true;

		if (fr_dict_attr_add(fr_dict_unconst(dict_tacacs), fr_dict_root(dict_tacacs),
				     "TACACS-State", -1, FR_TYPE_OCTETS, &flags) < 0) {
			cf_log_err(listen_cs, "Failed creating TACACS-State: %s", fr_strerror());
			return -1;
		}

		attr_tacacs_state = fr_dict_attr_by_name(dict_tacacs, "TACACS-State");
	}

	return 0;
}

extern fr_app_worker_t proto_tacacs_auth;
fr_app_worker_t proto_tacacs_auth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "tacacs_auth",
	.config		= proto_tacacs_auth_config,
	.inst_size	= sizeof(proto_tacacs_auth_t),

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
	.compile_list	= compile_list,
};
