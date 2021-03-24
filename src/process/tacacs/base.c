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
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/tacacs/tacacs.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t process_tacacs_dict[];
fr_dict_autoload_t process_tacacs_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_packet_type;

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
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },

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

typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*auth_start;
	CONF_SECTION	*auth_start_reply;

	CONF_SECTION	*auth_cont;
	CONF_SECTION	*auth_cont_reply;

	CONF_SECTION	*autz_request;
	CONF_SECTION	*autz_reply;

	CONF_SECTION	*acct_request;
	CONF_SECTION	*acct_reply;

	CONF_SECTION	*do_not_respond;
} process_tacacs_sections_t;

typedef struct {
	fr_time_delta_t	session_timeout;		//!< Maximum time between the last response and next request.
	uint32_t	max_session;			//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	fr_state_tree_t	*state_tree;			//!< State tree to link multiple requests/responses.

	process_tacacs_sections_t sections;

	CONF_SECTION	*server_cs;
} process_tacacs_t;

#define PROCESS_PACKET_TYPE		fr_tacacs_packet_code_t
#define PROCESS_CODE_MAX		FR_TACACS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_TACACS_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_TACACS_PACKET_CODE_VALID
#define PROCESS_INST			process_tacacs_t

#define PROCESS_STATE_EXTRA_FIELDS	fr_dict_attr_t const **attr_process; \
					fr_dict_attr_t const **attr_status; \
					char const	*attr_process_section; \
					uint8_t		status_fail; \
					char const	*fail_message;

#include <freeradius-devel/server/process.h>

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, process_tacacs_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, process_tacacs_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, process_tacacs_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER config[] = {
	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static void message_failed(request_t *request, PROCESS_INST *inst, fr_process_state_t const *ctx)
{
	fr_pair_t	*vp;
	char const	*msg;

	msg = ctx->fail_message;

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
	MEM(pair_update_reply(&vp, *ctx->attr_status) >= 0);
	vp->vp_uint8 = ctx->status_fail;

	fr_state_discard(inst->state_tree, request);
	fr_pair_delete_by_da(&request->request_pairs, attr_tacacs_state);
}

RECV(tacacs)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST	 		*inst = mctx->instance;
	fr_tacacs_packet_hdr_t const	*pkt = (fr_tacacs_packet_hdr_t const *) request->packet->data;

	PROCESS_TRACE;

	UPDATE_STATE_CS(packet);
	request->reply->code = state->default_reply; /* TCP, so we always reply */

	if (!request->parent) {
		fr_pair_t *vp;
		uint8_t buffer[sizeof(request->async->listen) + sizeof(pkt->session_id)];

		fr_assert(request->async->listen);
		memcpy(buffer, &request->async->listen, sizeof(request->async->listen));
		memcpy(buffer + sizeof(request->async->listen), &pkt->session_id, sizeof(pkt->session_id));

		vp = fr_pair_afrom_da(request->request_ctx, attr_tacacs_state);
		if (vp) {
			fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);
			fr_pair_append(&request->request_pairs, vp);

			fr_state_to_request(inst->state_tree, request);
		}
	}

	return CALL_RECV(generic);
}

RESUME(tacacs_type)
{
	rlm_rcode_t			rcode = *p_result;
	fr_process_state_t const	*state;
	PROCESS_INST	 		*inst = mctx->instance;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	switch (rcode) {
	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_UPDATED:
	case RLM_MODULE_DISALLOW:
	default:
		message_failed(request, inst, state);
		break;

	case RLM_MODULE_OK:
		break;

	case RLM_MODULE_HANDLED:
		break;
	}

	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request, rctx);
}

RESUME(recv_tacacs)
{
	rlm_rcode_t			rcode = *p_result;
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	PROCESS_INST	   		*inst = mctx->instance;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	switch (rcode) {
	case RLM_MODULE_NOOP:
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		request->reply->code = state->packet_type[rcode];

		/*
		 *	Run "authenticate foo" or "accounting foo"
		 */
		if (state->attr_process) {
			fr_pair_t *vp;
			fr_dict_enum_t const *dv;
			CONF_SECTION *subcs;

			vp = fr_pair_find_by_da(&request->request_pairs, *state->attr_process);
			if (!vp) vp = fr_pair_find_by_da(&request->control_pairs, *state->attr_process);
			if (!vp) {
				RDEBUG2("No attribute found for &request.%s - proceeding to 'send'", (*state->attr_process)->name);
				break;
			}

			dv = fr_dict_enum_by_value(vp->da, &vp->data);
			if (!dv) {
				RDEBUG2("No name found for &request.%s value %pV - proceeding to 'send'", (*state->attr_process)->name, &vp->data);
				break;
			}

			subcs = cf_section_find(unlang_call_current(request), state->attr_process_section, dv->name);
			if (!subcs) {
				RDEBUG2("No '%s %s { ... }' section found - skipping", state->attr_process_section, dv->name);
				break;
			}

			return unlang_module_yield_to_section(p_result, request,
							      subcs, RLM_MODULE_NOOP, resume_tacacs_type,
							      NULL, rctx);
		}
		break;

	case RLM_MODULE_HANDLED:
		fr_assert(request->reply->code != 0);
		break;

	case RLM_MODULE_FAIL:
	case RLM_MODULE_INVALID:
	case RLM_MODULE_REJECT:
	case RLM_MODULE_DISALLOW:
	default:
		request->reply->code = state->packet_type[rcode];
		message_failed(request, inst, state);
		break;
	}

	UPDATE_STATE_CS(reply);

	fr_assert(state->send != NULL);

	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->send,
					      NULL, rctx);
}

RESUME(send_tacacs)
{
	PROCESS_INST const   		*inst = mctx->instance;

	PROCESS_TRACE;

	/*
	 *	Save the state
	 */
	if (!request->parent &&
	    (fr_pair_find_by_da(&request->request_pairs, attr_tacacs_state) != NULL)) {
		fr_tacacs_packet_hdr_t const	*pkt = (fr_tacacs_packet_hdr_t const *) request->packet->data;

		/*
		 *	Keep the state around for
		 *	authorization and accounting packets.
		 */
		if (pkt->seq_no >= 254) {
			fr_state_discard(inst->state_tree, request);

			/*
			 *	We can't save it, so... oh well.
			 */
		} else if (fr_request_to_state(inst->state_tree, request) < 0) {
			RWDEBUG("Failed saving state");
			request->reply->code = FR_TACACS_DO_NOT_RESPOND;
		}
	}

	return CALL_RESUME(send_generic);
}

static fr_process_state_t const process_state[] = {
	[FR_TACACS_AUTH_START] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTH_START_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTH_START_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_TACACS_AUTH_START_REPLY,
		.recv = recv_tacacs,
		.resume = resume_recv_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, auth_start),

		.attr_process = &attr_tacacs_authentication_type,
		.attr_process_section = "authenticate",
		.fail_message = "Failed to authenticate the user",
		.attr_status = &attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	},
	[FR_TACACS_AUTH_START_REPLY] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTH_START_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTH_START_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTH_START_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, auth_start_reply),

		.fail_message = "Failed to authenticate the user",
		.attr_status = &attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	},

	[FR_TACACS_AUTH_CONTINUE] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTH_CONTINUE_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTH_CONTINUE_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_TACACS_AUTH_CONTINUE_REPLY,
		.recv = recv_tacacs,
		.resume = resume_recv_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, auth_cont),

		.attr_process = &attr_tacacs_authentication_type,
		.attr_process_section = "authenticate",
		.fail_message = "Failed to authenticate the user",
		.attr_status = &attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	},
	[FR_TACACS_AUTH_CONTINUE_REPLY] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTH_CONTINUE_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTH_CONTINUE_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTH_CONTINUE_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, auth_cont_reply),

		.fail_message = "Failed to authenticate the user",
		.attr_status = &attr_tacacs_authentication_status,
		.status_fail = FR_TAC_PLUS_AUTHEN_STATUS_FAIL,
	},

	[FR_TACACS_AUTZ_REQUEST] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTZ_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTZ_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_TACACS_AUTZ_REPLY,
		.recv = recv_tacacs,
		.resume = resume_recv_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, autz_request),

		.fail_message = "Failed to authorize the user",
		.attr_status = &attr_tacacs_authorization_status,
		.status_fail = FR_TAC_PLUS_AUTHOR_STATUS_FAIL,
	},
	[FR_TACACS_AUTZ_REPLY] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_AUTZ_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_AUTZ_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_AUTZ_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, autz_reply),

		.fail_message = "Failed to authorize the user",
		.attr_status = &attr_tacacs_authorization_status,
		.status_fail = FR_TAC_PLUS_AUTHOR_STATUS_FAIL,
	},

	[FR_TACACS_ACCT_REQUEST] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_ACCT_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_ACCT_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.default_reply = FR_TACACS_ACCT_REPLY,
		.recv = recv_tacacs,
		.resume = resume_recv_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, acct_request),

		.attr_process = &attr_tacacs_accounting_flags,
		.attr_process_section = "accounting",
		.fail_message = "Failed to process the accounting packet",
		.attr_status = &attr_tacacs_accounting_status,
		.status_fail = FR_TAC_PLUS_ACCT_STATUS_ERROR,
	},
	[FR_TACACS_ACCT_REPLY] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_NOOP] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_UPDATED] =	FR_TACACS_ACCT_REPLY,

			[RLM_MODULE_REJECT] =  	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_FAIL] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_INVALID] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_ACCT_REPLY,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_ACCT_REPLY,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, acct_reply),

		.fail_message = "Failed to process the accounting packet",
		.attr_status = &attr_tacacs_accounting_status,
		.status_fail = FR_TAC_PLUS_ACCT_STATUS_ERROR,
	},

	[FR_TACACS_DO_NOT_RESPOND] = {
		.packet_type = {
			[RLM_MODULE_OK] =	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_NOOP] =	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED] =	FR_TACACS_DO_NOT_RESPOND,

			[RLM_MODULE_REJECT] =  	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL] =	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] =	FR_TACACS_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND] =	FR_TACACS_DO_NOT_RESPOND,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_tacacs,
		.section_offset = offsetof(process_tacacs_sections_t, do_not_respond),
	},
};

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->instance, process_tacacs_t);
	fr_assert(PROCESS_PACKET_CODE_VALID(request->packet->code));

	request->component = "tacacs";
	fr_assert(request->dict == dict_tacacs);

	UPDATE_STATE(packet);

	// @todo - debug stuff!
//	tacacs_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
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
					      inst->session_timeout, inst->state_server_id,
					      fr_hash_string(cf_section_name2(inst->server_cs)));

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *process_app_cs)
{
	process_tacacs_t	*inst = instance;
	CONF_SECTION		*server_cs = cf_item_to_section(cf_parent(process_app_cs));

	fr_assert(process_app_cs);
	fr_assert(server_cs);

	fr_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	inst->server_cs = server_cs;
	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

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
	 *
	 *	  https://tools.ietf.org/html/rfc8907 Section 4.
	 *
	 *	This should be an abject lesson in how NOT to design a
	 *	protocol.  Pretty much everything they did was wrong.
	 */
	{
		.name = "recv",
		.name2 = "Authentication-Start",
		.component = MOD_AUTHENTICATE,
		.offset = PROCESS_CONF_OFFSET(auth_start),
	},
	{
		.name = "send",
		.name2 = "Authentication-Start-Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_start_reply),
	},
	{
		.name = "recv",
		.name2 = "Authentication-Continue",
		.component = MOD_AUTHENTICATE,
		.offset = PROCESS_CONF_OFFSET(auth_cont),
	},
	{
		.name = "send",
		.name2 = "Authentication-Continue-Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_cont_reply),
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
		.offset = PROCESS_CONF_OFFSET(autz_request),
	},
	{
		.name = "send",
		.name2 = "Authorization-Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(autz_reply),
	},

	/* accounting */

	{
		.name = "recv",
		.name2 = "Accounting-Request",
		.component = MOD_ACCOUNTING,
		.offset = PROCESS_CONF_OFFSET(acct_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Reply",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(acct_reply),
	},
	{
		.name = "accounting",
		.name2 = CF_IDENT_ANY,
		.component = MOD_ACCOUNTING,
	},

	{
		.name = "send",
		.name2 = "Do-Not-Response",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
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
