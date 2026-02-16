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
 * @file src/process/radius/base.c
 * @brief RADIUS process module
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
#include <freeradius-devel/server/rcode.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/unlang/xlat.h>

#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/value.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t process_radius_dict[];
fr_dict_autoload_t process_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_stripped_user_name;

static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_proxy_state;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_original_packet_code;
static fr_dict_attr_t const *attr_error_cause;

extern fr_dict_attr_autoload_t process_radius_dict_attr[];
fr_dict_attr_autoload_t process_radius_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_proxy_state, .name = "Proxy-State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ .out = &attr_original_packet_code, .name = "Extended-Attribute-1.Original-Packet-Code", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_error_cause, .name = "Error-Cause", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	DICT_AUTOLOAD_TERMINATOR
};

static fr_value_box_t const	*enum_auth_type_accept;
static fr_value_box_t const	*enum_auth_type_reject;

extern fr_dict_enum_autoload_t process_radius_dict_enum[];
fr_dict_enum_autoload_t process_radius_dict_enum[] = {
	{ .out = &enum_auth_type_accept, .name = "Accept", .attr = &attr_auth_type },
	{ .out = &enum_auth_type_reject, .name = "Reject", .attr = &attr_auth_type },
	DICT_AUTOLOAD_TERMINATOR
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
	CONF_SECTION	*protocol_error;

	CONF_SECTION	*new_client;
	CONF_SECTION	*add_client;
	CONF_SECTION	*deny_client;
} process_radius_sections_t;

typedef struct {
	fr_state_config_t		session;	//!< track state session information.
	fr_state_tree_t			*state_tree;	//!< State tree to link multiple requests/responses.
} process_radius_auth_t;

typedef struct {
	CONF_SECTION			*server_cs;	//!< Our virtual server.
	process_radius_sections_t	sections;	//!< Pointers to various config sections
							///< we need to execute.
	process_radius_auth_t		auth;		//!< Authentication configuration.
} process_radius_t;

/** Records fields from the original request so we have a known good copy
 */
typedef struct {
	fr_value_box_list_head_t	proxy_state;	//!< These need to be copied into the response in exactly
							///< the same order as they were added.
	unlang_result_t			result;
} process_radius_rctx_t;

#define FR_RADIUS_PROCESS_CODE_VALID(_x) (FR_RADIUS_PACKET_CODE_VALID(_x) || (_x == FR_RADIUS_CODE_DO_NOT_RESPOND))

#define PROCESS_PACKET_TYPE		fr_radius_packet_code_t
#define PROCESS_CODE_MAX		FR_RADIUS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_RADIUS_CODE_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_RADIUS_PROCESS_CODE_VALID
#define PROCESS_INST			process_radius_t
#define PROCESS_RCTX			process_radius_rctx_t
#define PROCESS_CODE_DYNAMIC_CLIENT	FR_RADIUS_CODE_ACCESS_ACCEPT
#include <freeradius-devel/server/process.h>

static const conf_parser_t auth_config[] = {
	{ FR_CONF_POINTER("session", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) state_session_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t config[] = {
	{ FR_CONF_POINTER("Access-Request", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) auth_config,
	  .offset = offsetof(process_radius_t, auth), },

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

/** Keep a copy of some attributes to keep them from being tampered with
 *
 */
static inline CC_HINT(always_inline)
void radius_request_pairs_store(request_t *request, process_radius_rctx_t *rctx)
{
	fr_pair_t		*proxy_state;

	/*
	 *	Don't bother allocing the struct if there's no proxy state to store
	 */
	proxy_state = fr_pair_find_by_da(&request->request_pairs, NULL, attr_proxy_state);
	if (!proxy_state) return;

	fr_value_box_list_init(&rctx->proxy_state);

	/*
	 *	We don't use fr_pair_list_copy_by_da, to avoid doing the lookup for
	 *	the first proxy-state attr again.
	 */
	do {
		fr_value_box_t *proxy_state_value;

		MEM((proxy_state_value = fr_value_box_acopy(rctx, &proxy_state->data)));
		fr_value_box_list_insert_tail(&rctx->proxy_state, proxy_state_value);
	} while ((proxy_state = fr_pair_find_by_da(&request->request_pairs, proxy_state, attr_proxy_state)));
}

static inline CC_HINT(always_inline)
void radius_request_pairs_to_reply(request_t *request, process_radius_rctx_t *rctx)
{
	/*
	 *	Proxy-State is a link-level signal between RADIUS
	 *	client and server.  RFC 2865 Section 5.33 says that
	 *	Proxy-State is an opaque field, and implementations
	 *	most not examine it, interpret it, or assign it any
	 *	meaning.  Implementations must also copy all Proxy-State
	 *	from the request to the reply.
	 *
	 *	The rlm_radius module already deletes any Proxy-State
	 *	from the reply before appending the proxy reply to the
	 *	current reply.
	 *
	 *	If any policy creates Proxy-State, that could affect
	 *	individual RADIUS links (perhaps), and that would be
	 *	wrong.  As such, we nuke any nonsensical Proxy-State
	 *	added by policies or errant modules, and instead just
	 *	do exactly what the RFCs require us to do.  No more.
	 */
	fr_pair_delete_by_da(&request->reply_pairs, attr_proxy_state);

	RDEBUG3("Adding Proxy-State attributes from request");
	RINDENT();
	fr_value_box_list_foreach(&rctx->proxy_state, proxy_state_value) {
		fr_pair_t *vp;

		MEM(vp = fr_pair_afrom_da(request->reply_ctx, attr_proxy_state));
		if (unlikely(fr_value_box_copy(vp, &vp->data, proxy_state_value) < 0)) {
			RDEBUG2("Failed to copy Proxy-State value %pV", proxy_state_value);
			talloc_free(vp);
			break;
		}
		fr_pair_append(&request->reply_pairs, vp);
		RDEBUG3("reply.%pP", vp);
	}
	REXDENT();
}

/** A wrapper around recv generic which stores fields from the request
 */
RECV(generic_radius_request)
{
	radius_request_pairs_store(request, mctx->rctx);

	return CALL_RECV(generic);
}

/** A wrapper around send generic which restores fields
 *
 */
RESUME(generic_radius_response)
{
	radius_request_pairs_to_reply(request, talloc_get_type_abort(mctx->rctx, process_radius_rctx_t));

	return CALL_RESUME(send_generic);
}

RECV(access_request)
{
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	if (fr_state_restore(inst->auth.state_tree, request) < 0) {
		return CALL_SEND_TYPE(FR_RADIUS_CODE_ACCESS_REJECT);
	}

	return CALL_RECV(generic_radius_request);
}

RESUME(auth_type);

RESUME(access_request)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	See if the return code from "recv Access-Request" says we reject, or continue.
	 */
	UPDATE_STATE(packet);

	/*
	 *	A policy or a module can hard-code the reply, in which case we can process that immediately,
	 *	and bypass the "authenticate" section.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
	if (vp && FR_RADIUS_PROCESS_CODE_VALID(vp->vp_uint32)) {
		request->reply->code = vp->vp_uint32;
		(void) fr_pair_delete(&request->reply_pairs, vp);
	} else {
		/*
		 *	Get the default reply packet based on the rcode.
		 */
		request->reply->code = state->packet_type[rcode];
		if (!request->reply->code) request->reply->code = state->default_reply;
	}

	/*
	 *	Either the code above or a module set reject, we're done.
	 */
	if (request->reply->code == FR_RADIUS_CODE_ACCESS_REJECT) {
		RDEBUG("The 'recv Access-Request' section returned %s - rejecting the request",
		       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));

	send_reply:
		UPDATE_STATE(reply);

		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	/*
	 *	Something set a reply, bypass the "authenticate" section.
	 */
	if (request->reply->code) {
		goto send_reply;
	}

	/*
	 *	Run authenticate foo { ... }
	 *
	 *	If we can't find Auth-Type, OR if we can't find
	 *	Auth-Type = foo, then it's a reject.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_auth_type);
	if (!vp) {
		RDEBUG("No 'Auth-Type' attribute found, cannot authenticate the user - rejecting the request");

	reject:
		request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
		goto send_reply;
	}

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) {
		RDEBUG("Invalid value for 'Auth-Type' attribute, cannot authenticate the user - rejecting the request");
		goto reject;
	}

	/*
	 *	The magic Auth-Type Accept value which means skip the authenticate section.
	 *
	 *	And Reject means always reject.  Tho the admin should instead just return "reject" from the
	 *	section.
	 */
	if (fr_value_box_cmp(enum_auth_type_accept, dv->value) == 0) {
		request->reply->code = FR_RADIUS_CODE_ACCESS_ACCEPT;
		goto send_reply;

	} else if (fr_value_box_cmp(enum_auth_type_reject, dv->value) == 0) {
		goto reject;
	}

	cs = cf_section_find(inst->server_cs, "authenticate", dv->name);
	if (!cs) {
		RDEBUG2("No 'authenticate %s { ... }' section found - rejecting the request", dv->name);
		goto reject;
	}

	/*
	 *	Run the "Authenticate = foo" section.
	 *
	 *	And continue with sending the generic reply.
	 */
	RDEBUG("Running 'authenticate %s' from file %s", cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, RLM_MODULE_NOOP, resume_auth_type,
					      NULL, 0, mctx->rctx);
}

RESUME(auth_type)
{
	static const fr_process_rcode_t auth_type_rcode = {
		[RLM_MODULE_REJECT] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_FAIL] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_OK] =	FR_RADIUS_CODE_ACCESS_ACCEPT,
		[RLM_MODULE_HANDLED] =	0,
		[RLM_MODULE_INVALID] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_DISALLOW] = FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_NOTFOUND] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_NOOP] =	FR_RADIUS_CODE_ACCESS_REJECT,
		[RLM_MODULE_UPDATED] =	FR_RADIUS_CODE_ACCESS_ACCEPT,
		[RLM_MODULE_TIMEOUT] =  FR_RADIUS_CODE_ACCESS_REJECT,
	};

	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_pair_t			*vp;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	Allow user to specify response packet type here, too.
	 */
	if (!auth_type_rcode[rcode]) {
		vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
		if (vp && FR_RADIUS_PROCESS_CODE_VALID(vp->vp_uint32)) {
			request->reply->code = vp->vp_uint32;
			(void) fr_pair_delete(&request->reply_pairs, vp);
		}
	} else {
		request->reply->code = auth_type_rcode[rcode];
	}

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
						REDEBUG("Unprintable characters in the password. "
							"Double-check the shared secret on the server "
							"and the NAS!");
						REDEBUG("For more information, please see " DOC_ROOT_URL "/troubleshooting/network/shared_secret.html");
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
		if ((vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_state)) == NULL) {
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

RESUME_FLAG(access_accept,UNUSED,)
{
	fr_pair_t			*vp;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

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
	radius_request_pairs_to_reply(request, mctx->rctx);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME_FLAG(access_reject,UNUSED,)
{
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	PROCESS_TRACE;

	fr_state_discard(inst->auth.state_tree, request);
	radius_request_pairs_to_reply(request, mctx->rctx);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME(access_challenge)
{
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	PROCESS_TRACE;

	/*
	 *	Cache the state context, unless this is a subrequest.
	 *	Subrequest state context will be handled by the caller.
	 *
	 *	If this fails, don't respond to the request.
	 */
	if (!request->parent && fr_state_store(inst->auth.state_tree, request) < 0) {
		return CALL_SEND_TYPE(FR_RADIUS_CODE_DO_NOT_RESPOND);
	}

	fr_assert(request->reply->code == FR_RADIUS_CODE_ACCESS_CHALLENGE);
	radius_request_pairs_to_reply(request, mctx->rctx);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** A wrapper around recv generic which stores fields from the request
 */
RECV(accounting_request)
{
	radius_request_pairs_store(request, mctx->rctx);

	return CALL_RECV(generic);
}

RESUME(acct_type)
{
	static const fr_process_rcode_t acct_type_rcode = {
		[RLM_MODULE_FAIL] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_INVALID] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_NOTFOUND] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_REJECT] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_DISALLOW] = FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_TIMEOUT] =  FR_RADIUS_CODE_DO_NOT_RESPOND,
	};

	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(FR_RADIUS_PROCESS_CODE_VALID(request->reply->code));

	if (acct_type_rcode[rcode]) {
		fr_assert(acct_type_rcode[rcode] == FR_RADIUS_CODE_DO_NOT_RESPOND);

		request->reply->code = acct_type_rcode[rcode];
		UPDATE_STATE(reply);

		RDEBUG("The 'accounting' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));

		fr_assert(state->send != NULL);
		return state->send(p_result, mctx, request);
	}

	request->reply->code = FR_RADIUS_CODE_ACCOUNTING_RESPONSE;
	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request);
}

RESUME(accounting_request)
{
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);
	fr_assert(state->packet_type[rcode] != 0);

	request->reply->code = state->packet_type[rcode];
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		RDEBUG("The 'recv Accounting-Request' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));

	send_reply:
		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	/*
	 *	Run accounting foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_acct_status_type);
	if (!vp) goto send_reply;

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) goto send_reply;

	cs = cf_section_find(inst->server_cs, "accounting", dv->name);
	if (!cs) {
		RDEBUG2("No 'accounting %s { ... }' section found - skipping...", dv->name);
		goto send_reply;
	}

	/*
	 *	Run the "Acct-Status-Type = foo" section.
	 *
	 *	And continue with sending the generic reply.
	 */
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, RLM_MODULE_NOOP, resume_acct_type,
					      NULL, 0, mctx->rctx);
}

#if 0
// @todo - send canned responses like in v3?
RECV(status_server)
{
	RETURN_UNLANG_FAIL;
}

RESUME(status_server)
{
	RETURN_UNLANG_FAIL;
}
#endif

RESUME_FLAG(protocol_error,UNUSED,)
{
	fr_pair_t 			*vp;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

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
	 *	Discard any session state associated with the request.
	 */
	if (request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) {
		fr_state_discard(inst->auth.state_tree, request);
	}

	/*
	 *	Add Proxy-State back.
	 */
	radius_request_pairs_to_reply(request, talloc_get_type_abort(mctx->rctx, process_radius_rctx_t));

	/*
	 *	And do the generic processing after running a "send" section.
	 */
	return CALL_RESUME(send_generic);
}

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	(void) talloc_get_type_abort_const(mctx->mi->data, process_radius_t);

	PROCESS_TRACE;

	request->component = "radius";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_radius);

	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->packet->code));

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	radius_packet_debug(request, request->packet, &request->request_pairs, true);

	if (unlikely(request_is_dynamic_client(request))) {
		return new_client(p_result, mctx, request);
	}

	return state->recv(p_result, mctx, request);
}

static xlat_arg_parser_t const xlat_func_radius_secret_verify_args[] = {
        { .required = true, .single = true, .type = FR_TYPE_OCTETS },
        XLAT_ARG_PARSER_TERMINATOR
};

/** Validates a request against a know shared secret
 *
 * Designed for the specific purpose of verifying dynamic clients
 * against a know shared secret.
 *
 * Example:
@verbatim
%radius.secret.verify(<secret>)
@endverbatim
 *
 * @ingroup xlat_functions
 */
static xlat_action_t xlat_func_radius_secret_verify(TALLOC_CTX *ctx, fr_dcursor_t *out, UNUSED xlat_ctx_t const *xctx,
                                                    request_t *request, fr_value_box_list_t *args)
{
	fr_value_box_t  *secret, *vb;
	int		ret;
	bool		require_message_authenticator = false;

	XLAT_ARGS(args, &secret);

	if (request->proto_dict != dict_radius) return XLAT_ACTION_FAIL;

	MEM(vb = fr_value_box_alloc(ctx, FR_TYPE_BOOL, NULL));

	/*
	 *	Only Access-Requests require a Message-Authenticator.
	 *	All the other packet types are signed using the
	 *	authenticator field.
	 */
	if (request->packet->code == FR_RADIUS_CODE_ACCESS_REQUEST) require_message_authenticator = true;

	ret = fr_radius_verify(request->packet->data, NULL, secret->vb_octets, secret->vb_length, require_message_authenticator, false);
	switch (ret) {
	case 0:
		vb->vb_bool = true;
		break;

	default:
		RPEDEBUG("Invalid packet");
		return XLAT_ACTION_FAIL;

	case -FR_RADIUS_FAIL_MA_INVALID:
	case -FR_RADIUS_FAIL_VERIFY:
		RPEDEBUG("Failed to verify the packet signature");
		vb->vb_bool = false;
		break;
	}
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_radius_t	*inst = talloc_get_type_abort(mctx->mi->data, process_radius_t);

	inst->server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.session.max_rounds, >=, 32);
	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.session.max_rounds, <=, 100);

	inst->auth.session.thread_safe = main_config->spawn_workers;
	inst->auth.session.context_id = fr_hash_string(cf_section_name2(inst->server_cs));

	MEM(inst->auth.state_tree = fr_state_tree_init(inst, attr_state, &inst->auth.session));

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	CONF_SECTION	*server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	return 0;
}

static int mod_load(void)
{
	xlat_t	*xlat;

	if (unlikely(!(xlat = xlat_func_register(NULL, "radius.secret.verify", xlat_func_radius_secret_verify,
						 FR_TYPE_BOOL)))) return -1;

	xlat_func_args_set(xlat, xlat_func_radius_secret_verify_args);

	return 0;
}

static void mod_unload(void)
{
	xlat_func_unregister("radius.secret.verify");
}

/*
 *	rcodes not listed under a packet_type
 *	mean that the packet code will not be
 *	changed.
 */
static fr_process_state_t const process_state[] = {
	[ FR_RADIUS_CODE_ACCESS_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_access_request,
		.resume = resume_access_request,
		.section_offset = offsetof(process_radius_sections_t, access_request),
	},
	[ FR_RADIUS_CODE_ACCESS_ACCEPT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_access_accept,
		.section_offset = offsetof(process_radius_sections_t, access_accept),
	},
	[ FR_RADIUS_CODE_ACCESS_REJECT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
		.send = send_generic,
		.resume = resume_access_reject,
		.section_offset = offsetof(process_radius_sections_t, access_reject),
	},
	[ FR_RADIUS_CODE_ACCESS_CHALLENGE ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_access_challenge,
		.section_offset = offsetof(process_radius_sections_t, access_challenge),
	},

	[ FR_RADIUS_CODE_ACCOUNTING_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_ACCOUNTING_RESPONSE,
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_ACCOUNTING_RESPONSE,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_ACCOUNTING_RESPONSE,
			[RLM_MODULE_HANDLED]	= FR_RADIUS_CODE_ACCOUNTING_RESPONSE,

			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_accounting_request,
		.resume = resume_accounting_request,
		.section_offset = offsetof(process_radius_sections_t, accounting_request),
	},
	[ FR_RADIUS_CODE_ACCOUNTING_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_generic_radius_response,
		.section_offset = offsetof(process_radius_sections_t, accounting_response),
	},
	[ FR_RADIUS_CODE_STATUS_SERVER ] = { /* @todo - negotiation, stats, etc. */
		.packet_type = {
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_ACCESS_ACCEPT,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_ACCESS_ACCEPT,

			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_radius_sections_t, status_server),
	},
	[ FR_RADIUS_CODE_COA_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_COA_ACK,
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_COA_ACK,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_COA_ACK,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_COA_ACK,

			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_generic_radius_request,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_radius_sections_t, coa_request),
	},
	[ FR_RADIUS_CODE_COA_ACK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_generic_radius_response,
		.section_offset = offsetof(process_radius_sections_t, coa_ack),
	},
	[ FR_RADIUS_CODE_COA_NAK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_NOTFOUND,
		.send = send_generic,
		.resume = resume_generic_radius_response,
		.section_offset = offsetof(process_radius_sections_t, coa_nak),
	},
	[ FR_RADIUS_CODE_DISCONNECT_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_RADIUS_CODE_DISCONNECT_ACK,
			[RLM_MODULE_OK]		= FR_RADIUS_CODE_DISCONNECT_ACK,
			[RLM_MODULE_UPDATED]	= FR_RADIUS_CODE_DISCONNECT_ACK,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_DISCONNECT_ACK,

			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_generic_radius_request,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_radius_sections_t, disconnect_request),
	},
	[ FR_RADIUS_CODE_DISCONNECT_ACK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_generic_radius_response,
		.section_offset = offsetof(process_radius_sections_t, disconnect_ack),
	},
	[ FR_RADIUS_CODE_DISCONNECT_NAK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_NOTFOUND,
		.send = send_generic,
		.resume = resume_generic_radius_response,
		.section_offset = offsetof(process_radius_sections_t, disconnect_nak),
	},
	[ FR_RADIUS_CODE_PROTOCOL_ERROR ] = { /* @todo - fill out required fields */
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_protocol_error,
		.section_offset = offsetof(process_radius_sections_t, protocol_error),
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_HANDLED,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_radius_sections_t, do_not_respond),
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
		.section = SECTION_NAME("recv", "Accounting-Request"),
		.actions = &mod_actions_preacct,
		.offset = PROCESS_CONF_OFFSET(accounting_request),
	},
	{
		.section = SECTION_NAME("send", "Accounting-Response"),
		.actions = &mod_actions_accounting,
		.offset = PROCESS_CONF_OFFSET(accounting_response),
	},

	{
		.section = SECTION_NAME("recv", "Status-Server"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(status_server),
	},
	{
		.section = SECTION_NAME("recv", "CoA-Request"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(coa_request),
	},
	{
		.section = SECTION_NAME("send", "CoA-ACK"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(coa_ack),
	},
	{
		.section = SECTION_NAME("send", "CoA-NAK"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(coa_nak),
	},
	{
		.section = SECTION_NAME("recv", "Disconnect-Request"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(disconnect_request),
	},
	{
		.section = SECTION_NAME("send", "Disconnect-ACK"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(disconnect_ack),
	},
	{
		.section = SECTION_NAME("send", "Disconnect-NAK"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(disconnect_nak),
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
	{
		.section = SECTION_NAME("accounting", CF_IDENT_ANY),
		.actions = &mod_actions_authenticate
	},

	DYNAMIC_CLIENT_SECTIONS,

	COMPILE_TERMINATOR
};

extern fr_process_module_t process_radius;
fr_process_module_t process_radius = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "radius",
		.config		= config,
		MODULE_INST(process_radius_t),
		MODULE_RCTX(process_radius_rctx_t),

		.onload		= mod_load,
		.unload		= mod_unload,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_radius,
	.packet_type	= &attr_packet_type
};
