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
 * @file src/process/ttls/base.c
 * @brief TTLS process module
 *
 * @copyright 2021 The FreeRADIUS server project.
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/state.h>

#include <freeradius-devel/unlang/module.h>

#include <freeradius-devel/util/debug.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t process_ttls_dict[];
fr_dict_autoload_t process_ttls_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_stripped_user_name;

static fr_dict_attr_t const *attr_calling_station_id;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_nas_port;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_service_type;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_original_packet_code;
static fr_dict_attr_t const *attr_error_cause;

extern fr_dict_attr_autoload_t process_ttls_dict_attr[];
fr_dict_attr_autoload_t process_ttls_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_calling_station_id, .name = "Calling-Station-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_nas_port, .name = "NAS-Port", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_service_type, .name = "Service-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_original_packet_code, .name = "Extended-Attribute-1.Original-Packet-Code", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_error_cause, .name = "Error-Cause", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ NULL }
};

static fr_value_box_t const	*enum_auth_type_accept;
static fr_value_box_t const	*enum_auth_type_reject;

extern fr_dict_enum_autoload_t process_ttls_dict_enum[];
fr_dict_enum_autoload_t process_ttls_dict_enum[] = {
	{ .out = &enum_auth_type_accept, .name = "Accept", .attr = &attr_auth_type },
	{ .out = &enum_auth_type_reject, .name = "Reject", .attr = &attr_auth_type },
	{ NULL }
};

/*
 *	RADIUS state machine configuration
 */
typedef struct {
	uint64_t	nothing;		// so that "access_request" isn't at offset 0

	CONF_SECTION	*access_request;
	CONF_SECTION	*access_accept;
	CONF_SECTION	*access_reject;
	CONF_SECTION	*access_challenge;

	CONF_SECTION	*accounting_request;
	CONF_SECTION	*accounting_response;

	CONF_SECTION	*status_server;

	CONF_SECTION	*coa_request;
	CONF_SECTION	*coa_ack;
	CONF_SECTION	*coa_nak;

	CONF_SECTION	*disconnect_request;
	CONF_SECTION	*disconnect_ack;
	CONF_SECTION	*disconnect_nak;

	CONF_SECTION	*do_not_respond;
	CONF_SECTION	*protocol_error;	/* @todo - allow protocol error as a reject reply? */
} process_ttls_sections_t;

typedef struct {
	fr_time_delta_t	timeout;	//!< Maximum time between the last response and next request.
	uint32_t	max;		//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;	//!< Sets a specific byte in the state to allow the
						//!< authenticating server to be identified in packet
						//!<captures.
} process_ttls_session_t;

typedef struct {
	process_ttls_session_t 		session;	//!< Session settings.

	fr_state_tree_t			*state_tree;	//!< State tree to link multiple requests/responses.
} process_ttls_auth_t;

typedef struct {
	CONF_SECTION			*server_cs;	//!< Our virtual server.
	process_ttls_sections_t		sections;	//!< Pointers to various config sections
							///< we need to execute.
	process_ttls_auth_t		auth;		//!< Authentication configuration.
} process_ttls_t;

#define PROCESS_PACKET_TYPE		fr_radius_packet_code_t
#define PROCESS_CODE_MAX		FR_RADIUS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_RADIUS_CODE_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_RADIUS_PACKET_CODE_VALID
#define PROCESS_INST			process_ttls_t
#include <freeradius-devel/server/process.h>

static const conf_parser_t session_config[] = {
	{ FR_CONF_OFFSET("timeout", process_ttls_session_t, timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", process_ttls_session_t, max), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", process_ttls_session_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t auth_config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("session", 0, process_ttls_auth_t, session, session_config )},

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("Access-Request", 0, process_ttls_t, auth, auth_config) },

	CONF_PARSER_TERMINATOR
};

/*
 *	Debug the packet if requested.
 */
static void radius_packet_debug(request_t *request, fr_packet_t *packet, fr_pair_list_t *list, bool received)
{
#ifdef WITH_IFINDEX_NAME_RESOLUTION
	char if_name[IFNAMSIZ];
#endif

	if (!packet) return;
	if (!RDEBUG_ENABLED) return;

	log_request(L_DBG, L_DBG_LVL_1, request, __FILE__, __LINE__, "%s %s ID %d from %s%pV%s:%i to %s%pV%s:%i "
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       "%s%s%s"
#endif
		       "",
		       received ? "Received" : "Sending",
		       fr_radius_packet_name[packet->code],
		       packet->id,
		       packet->socket.inet.src_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->socket.inet.src_ipaddr),
		       packet->socket.inet.src_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->socket.inet.src_port,
		       packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "[" : "",
		       fr_box_ipaddr(packet->socket.inet.dst_ipaddr),
		       packet->socket.inet.dst_ipaddr.af == AF_INET6 ? "]" : "",
		       packet->socket.inet.dst_port
#ifdef WITH_IFINDEX_NAME_RESOLUTION
		       , packet->socket.inet.ifindex ? "via " : "",
		       packet->socket.inet.ifindex ? fr_ifname_from_ifindex(if_name, packet->socket.inet.ifindex) : "",
		       packet->socket.inet.ifindex ? " " : ""
#endif
		       );

	if (received || request->parent) {
		log_request_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	} else {
		log_request_proto_pair_list(L_DBG_LVL_1, request, NULL, list, NULL);
	}
}

RESUME(auth_type);

RESUME(access_request)
{
	rlm_rcode_t			rcode = *p_result;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_ttls_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_ttls_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	request->reply->code = state->packet_type[rcode];
	if (!request->reply->code) request->reply->code = state->default_reply;
	if (!request->reply->code) request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		RDEBUG("The 'recv Access-Request' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));

	send_reply:
		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	/*
	 *	Run authenticate foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_auth_type);
	if (!vp) goto send_reply;

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) goto send_reply;

	/*
	 *	The magic Auth-Type accept value
	 *	which means skip the authenticate
	 *	section...
	 */
	if (fr_value_box_cmp(enum_auth_type_accept, dv->value) == 0) {
		request->reply->code = FR_RADIUS_CODE_ACCESS_ACCEPT;
		goto send_reply;
	} else if (fr_value_box_cmp(enum_auth_type_reject, dv->value) == 0) {
		request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
		goto send_reply;
	}

	cs = cf_section_find(inst->server_cs, "authenticate", dv->name);
	if (!cs) {
		RDEBUG2("No 'authenticate %s { ... }' section found - skipping...", dv->name);
		goto send_reply;
	}

	/*
	 *	Run the "Authenticate = foo" section.
	 *
	 *	And continue with sending the generic reply.
	 */
	RDEBUG("Running 'authenticate %s' from file %s", cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(p_result, request,
					      cs, RLM_MODULE_NOOP, resume_auth_type,
					      NULL, 0, mctx->rctx);
}

RESUME(auth_type)
{
	static const fr_process_rcode_t auth_type_rcode = {
		[RLM_MODULE_OK] =	FR_RADIUS_CODE_ACCESS_ACCEPT,
		[RLM_MODULE_FAIL] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_INVALID] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_NOOP] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_NOTFOUND] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_REJECT] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_UPDATED] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_DISALLOW] = FR_RADIUS_CODE_ACCESS_REJECT,
	};

	rlm_rcode_t			rcode = *p_result;
	fr_pair_t			*vp;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->reply->code));

	if (auth_type_rcode[rcode] == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		request->reply->code = auth_type_rcode[rcode];
		UPDATE_STATE(reply);

		RDEBUG("The 'authenticate' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));

		fr_assert(state->send != NULL);
		return state->send(p_result, mctx, request);
	}

	/*
	 *	Most cases except handled...
	 */
	if (auth_type_rcode[rcode]) request->reply->code = auth_type_rcode[rcode];

	switch (request->reply->code) {
	case 0:
		RDEBUG("No reply code was set.  Forcing to Access-Reject");
		request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
		FALL_THROUGH;

	/*
	 *	Print complaints before running "send Access-Reject"
	 */
	case FR_RADIUS_CODE_ACCESS_REJECT:
		RDEBUG2("Failed to authenticate the user");

		/*
		 *	Maybe the shared secret is wrong?
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);
		if (vp) {
			if (RDEBUG_ENABLED2) {
				uint8_t const *p;

				p = (uint8_t const *) vp->vp_strvalue;
				while (*p) {
					int size;

					size = fr_utf8_char(p, -1);
					if (!size) {
						RWDEBUG("Unprintable characters in the password. "
							"Double-check the shared secret on the server "
							"and the NAS!");
						break;
					}
					p += size;
				}
			}
		}
		break;

	/*
	 *	Access-Challenge sections require a State.  If there is
	 *	none, create one here.  This is so that the State
	 *	attribute is accessible in the "send Access-Challenge"
	 *	section.
	 */
	case FR_RADIUS_CODE_ACCESS_CHALLENGE:
		if ((vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_state)) != NULL) {
			uint8_t buffer[16];

			fr_rand_buffer(buffer, sizeof(buffer));

			MEM(pair_update_reply(&vp, attr_state) >= 0);
			fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);
		}
		break;

	default:
		break;

	}
	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request);
}

RESUME(access_accept)
{
	fr_pair_t			*vp;
	process_ttls_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_ttls_t);

	PROCESS_TRACE;

	/*
	 *	Check that there is a name which can be used to
	 *	identify the user.  The configuration depends on
	 *	User-Name or Stripped-User-Name existing, and being
	 *	(mostly) unique to that user.
	 */
	if (!request->parent &&
	    ((vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name)) != NULL) &&
	    (vp->vp_strvalue[0] == '@') &&
	    !fr_pair_find_by_da(&request->request_pairs, NULL, attr_stripped_user_name)) {
		RWDEBUG("User-Name is anonymized, and no Stripped-User-Name exists.");
		RWDEBUG("It may be difficult or impossible to identify the user.");
		RWDEBUG("Please update Stripped-User-Name with information which identifies the user.");
	}

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME(access_reject)
{
	process_ttls_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_ttls_t);

	PROCESS_TRACE;

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME(access_challenge)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	process_ttls_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_ttls_t);

	PROCESS_TRACE;

	/*
	 *	Cache the state context.
	 *
	 *	If this fails, don't respond to the request.
	 */
	if (fr_request_to_state(inst->auth.state_tree, request) < 0) {
		request->reply->code = FR_RADIUS_CODE_DO_NOT_RESPOND;
		UPDATE_STATE_CS(reply);
		return CALL_SEND_STATE(state);
	}

	fr_assert(request->reply->code == FR_RADIUS_CODE_ACCESS_CHALLENGE);
	RETURN_MODULE_OK;
}

RESUME(protocol_error)
{
	fr_pair_t 			*vp;

	PROCESS_TRACE;

	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->reply->code));

	/*
	 *	https://tools.ietf.org/html/rfc7930#section-4
	 */
	vp = fr_pair_find_by_da_nested(&request->reply_pairs, NULL, attr_original_packet_code);
	if (!vp) {
		vp = fr_pair_afrom_da(request->reply_ctx, attr_original_packet_code);
		if (vp) {
			vp->vp_uint32 = request->packet->code;
			fr_pair_append(&request->reply_pairs, vp);
		}
	}

	/*
	 *	If there's no Error-Cause, then include a generic 404.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_error_cause);
	if (!vp) {
		vp = fr_pair_afrom_da(request->reply_ctx, attr_error_cause);
		if (vp) {
			vp->vp_uint32 = FR_ERROR_CAUSE_VALUE_INVALID_REQUEST;
			fr_pair_append(&request->reply_pairs, vp);
		}
	}

	/*
	 *	And do the generic processing after running a "send" section.
	 */
	return CALL_RESUME(send_generic);
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	(void) talloc_get_type_abort_const(mctx->mi->data, process_ttls_t);

	PROCESS_TRACE;

	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->packet->code));

	request->component = "radius";
	request->module = NULL;
	fr_assert(request->dict == dict_radius);

	UPDATE_STATE(packet);

	radius_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_ttls_t	*inst = talloc_get_type_abort(mctx->mi->data, process_ttls_t);

	inst->server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	inst->auth.state_tree = fr_state_tree_init(inst, attr_state, main_config->spawn_workers, inst->auth.session.max,
						   inst->auth.session.timeout, inst->auth.session.state_server_id,
						   fr_hash_string(cf_section_name2(inst->server_cs)));

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	CONF_SECTION	*server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	return 0;
}

/*
 *	rcodes not listed under a packet_type
 *	mean that the packet code will not be
 *	changed.
 */
static fr_process_state_t const process_state[] = {
	[ FR_RADIUS_CODE_ACCESS_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_ACCESS_ACCEPT,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_ACCESS_ACCEPT,

			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_ACCESS_REJECT
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_access_request,
		.section_offset = offsetof(process_ttls_sections_t, access_request),
	},
	[ FR_RADIUS_CODE_ACCESS_ACCEPT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_access_accept,
		.section_offset = offsetof(process_ttls_sections_t, access_accept),
	},
	[ FR_RADIUS_CODE_ACCESS_REJECT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_access_reject,
		.section_offset = offsetof(process_ttls_sections_t, access_reject),
	},
	[ FR_RADIUS_CODE_ACCESS_CHALLENGE ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_access_challenge,
		.section_offset = offsetof(process_ttls_sections_t, access_challenge),
	},


	[ FR_RADIUS_CODE_PROTOCOL_ERROR ] = { /* @todo - fill out required fields */
		.packet_type = {
			[RLM_MODULE_FAIL] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW] = FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_protocol_error,
		.section_offset = offsetof(process_ttls_sections_t, protocol_error),
	},
	[ FR_RADIUS_CODE_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_RADIUS_CODE_DO_NOT_RESPOND,

			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_ttls_sections_t, do_not_respond),
	}
};

static virtual_server_compile_t const compile_list[] = {
	{
		.section = SECTION_NAME("recv", "Access-Request"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(access_request),
	},
	{
		.section = SECTION_NAME("send", "Access-Accept"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(access_accept),
	},
	{
		.section = SECTION_NAME("send", "Access-Challenge"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(access_challenge),
	},
	{
		.section = SECTION_NAME("send", "Access-Reject"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(access_reject),
	},

	{
		.section = SECTION_NAME("send", "Protocol-Error"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(protocol_error),
	},
	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
	{
		.section = SECTION_NAME("authenticate", CF_IDENT_ANY),
		.actions = &mod_actions_authenticate
	},
	COMPILE_TERMINATOR
};

extern fr_process_module_t process_ttls;
fr_process_module_t process_ttls = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "ttls",
		.config		= config,
		.inst_size	= sizeof(process_ttls_t),

		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_radius
};
