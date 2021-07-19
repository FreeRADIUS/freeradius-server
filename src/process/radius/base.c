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
 * @copyright 2021 Network RADIUS SARL (legal@networkradius.com)
 */
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/server/protocol.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/state.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t process_radius_dict[];
fr_dict_autoload_t process_radius_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_stripped_user_name;

static fr_dict_attr_t const *attr_acct_status_type;
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

extern fr_dict_attr_autoload_t process_radius_dict_attr[];
fr_dict_attr_autoload_t process_radius_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
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

extern fr_dict_enum_autoload_t process_radius_dict_enum[];
fr_dict_enum_autoload_t process_radius_dict_enum[] = {
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
} process_radius_sections_t;

typedef struct {
	bool		log_stripped_names;
	bool		log_auth;		//!< Log authentication attempts.
	bool		log_auth_badpass;	//!< Log failed authentications.
	bool		log_auth_goodpass;	//!< Log successful authentications.
	char const	*auth_badpass_msg;	//!< Additional text to append to failed auth messages.
	char const	*auth_goodpass_msg;	//!< Additional text to append to successful auth messages.

	char const	*denied_msg;		//!< Additional text to append if the user is already logged
						//!< in (simultaneous use check failed).

	fr_time_delta_t	session_timeout;	//!< Maximum time between the last response and next request.
	uint32_t	max_session;		//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;	//!< Sets a specific byte in the state to allow the
						//!< authenticating server to be identified in packet
						//!<captures.

	fr_state_tree_t	*state_tree;		//!< State tree to link multiple requests/responses.
} process_radius_auth_t;

typedef struct {
	CONF_SECTION			*server_cs;	//!< Our virtual server.
	process_radius_sections_t	sections;	//!< Pointers to various config sections
							///< we need to execute.
	process_radius_auth_t		auth;		//!< Authentication configuration.
} process_radius_t;

#define PROCESS_PACKET_TYPE		fr_radius_packet_code_t
#define PROCESS_CODE_MAX		FR_RADIUS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_RADIUS_CODE_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_RADIUS_PACKET_CODE_VALID
#define PROCESS_INST			process_radius_t
#include <freeradius-devel/server/process.h>

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, process_radius_auth_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, process_radius_auth_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, process_radius_auth_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER log_config[] = {
	{ FR_CONF_OFFSET("stripped_names", FR_TYPE_BOOL, process_radius_auth_t, log_stripped_names), .dflt = "no" },
	{ FR_CONF_OFFSET("auth", FR_TYPE_BOOL, process_radius_auth_t, log_auth), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_badpass", FR_TYPE_BOOL, process_radius_auth_t, log_auth_badpass), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_goodpass", FR_TYPE_BOOL,process_radius_auth_t,  log_auth_goodpass), .dflt = "no" },
	{ FR_CONF_OFFSET("msg_badpass", FR_TYPE_STRING, process_radius_auth_t, auth_badpass_msg) },
	{ FR_CONF_OFFSET("msg_goodpass", FR_TYPE_STRING, process_radius_auth_t, auth_goodpass_msg) },
	{ FR_CONF_OFFSET("msg_denied", FR_TYPE_STRING, process_radius_auth_t, denied_msg), .dflt = "You are already logged in - access denied" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER auth_config[] = {
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER config[] = {
	{ FR_CONF_POINTER("Access-Request", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) auth_config,
	  .offset = offsetof(process_radius_t, auth), },

	CONF_PARSER_TERMINATOR
};

/*
 *	Debug the packet if requested.
 */
static void radius_packet_debug(request_t *request, fr_radius_packet_t *packet, fr_pair_list_t *list, bool received)
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
		       fr_packet_codes[packet->code],
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

#define RAUTH(fmt, ...)		log_request(L_AUTH, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)

/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
static char *auth_name(char *buf, size_t buflen, request_t *request)
{
	fr_pair_t	*cli;
	fr_pair_t	*pair;
	uint32_t	port = 0;	/* RFC 2865 NAS-Port is 4 bytes */
	char const	*tls = "";
	RADCLIENT	*client = client_from_request(request);

	cli = fr_pair_find_by_da(&request->request_pairs, attr_calling_station_id, 0);

	pair = fr_pair_find_by_da(&request->request_pairs, attr_nas_port, 0);
	if (pair != NULL) port = pair->vp_uint32;

	if (request->packet->socket.inet.dst_port == 0) tls = " via proxy to virtual server";

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
		 client ? client->shortname : "", port,
		 (cli ? " cli " : ""), (cli ? cli->vp_strvalue : ""),
		 tls);

	return buf;
}

/*
 *	Make sure user/pass are clean and then create an attribute
 *	which contains the log message.
 */
static void CC_HINT(format (printf, 4, 5)) auth_message(process_radius_auth_t const *inst,
							request_t *request, bool goodpass, char const *fmt, ...)
{
	va_list		 ap;

	bool		logit;
	char const	*extra_msg = NULL;

	char		password_buff[128];
	char const	*password_str = NULL;

	char		buf[1024];
	char		extra[1024];
	char		*p;
	char		*msg;
	fr_pair_t	*username = NULL;
	fr_pair_t	*password = NULL;

	/*
	 *	No logs?  Then no logs.
	 */
	if (!inst->log_auth) return;

	/*
	 * Get the correct username based on the configured value
	 */
	if (!inst->log_stripped_names) {
		username = fr_pair_find_by_da(&request->request_pairs, attr_user_name, 0);
	} else {
		username = fr_pair_find_by_da(&request->request_pairs, attr_stripped_user_name, 0);
		if (!username) username = fr_pair_find_by_da(&request->request_pairs, attr_user_name, 0);
	}

	/*
	 *	Clean up the password
	 */
	if (inst->log_auth_badpass || inst->log_auth_goodpass) {
		password = fr_pair_find_by_da(&request->request_pairs, attr_user_password, 0);
		if (!password) {
			fr_pair_t *auth_type;

			auth_type = fr_pair_find_by_da(&request->control_pairs, attr_auth_type, 0);
			if (auth_type) {
				snprintf(password_buff, sizeof(password_buff), "<via Auth-Type = %s>",
					 fr_dict_enum_name_by_value(auth_type->da, &auth_type->data));
				password_str = password_buff;
			} else {
				password_str = "<no User-Password attribute>";
			}
		} else if (fr_pair_find_by_da(&request->request_pairs, attr_chap_password, 0)) {
			password_str = "<CHAP-Password>";
		}
	}

	if (goodpass) {
		logit = inst->log_auth_goodpass;
		extra_msg = inst->auth_goodpass_msg;
	} else {
		logit = inst->log_auth_badpass;
		extra_msg = inst->auth_badpass_msg;
	}

	if (extra_msg) {
		extra[0] = ' ';
		p = extra + 1;
		if (xlat_eval(p, sizeof(extra) - 1, request, extra_msg, NULL, NULL) < 0) return;
	} else {
		*extra = '\0';
	}

	/*
	 *	Expand the input message
	 */
	va_start(ap, fmt);
	msg = fr_vasprintf(request, fmt, ap);
	va_end(ap);

	RAUTH("%s: [%pV%s%pV] (%s)%s",
	      msg,
	      username ? &username->data : fr_box_strvalue("<no User-Name attribute>"),
	      logit ? "/" : "",
	      logit ? (password_str ? fr_box_strvalue(password_str) : &password->data) : fr_box_strvalue(""),
	      auth_name(buf, sizeof(buf), request),
	      extra);

	talloc_free(msg);
}

RECV(access_request)
{
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	/*
	 *	Only reject if the state has already been thawed.
	 *	It could be that the state value wasn't intended
	 *	for us, and we're just proxying upstream.
	 */
	if (fr_state_to_request(inst->auth.state_tree, request) < 0) {
		fr_process_state_t const	*state;
		CONF_SECTION			*cs;

		request->reply->code = FR_RADIUS_CODE_ACCESS_REJECT;
		UPDATE_STATE_CS(reply);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	return CALL_RECV(generic);
}

RESUME(auth_type);

RESUME(access_request)
{
	rlm_rcode_t			rcode = request->rcode;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_t const		*dv;
	fr_process_state_t const	*state;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	request->reply->code = state->packet_type[rcode];
	if (!request->reply->code) request->reply->code = state->default_reply;
	if (!request->reply->code) request->reply->code = PROCESS_CODE_DO_NOT_RESPOND;
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		RDEBUG("The 'recv Access-Request' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

	send_reply:
		fr_assert(state->send != NULL);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	/*
	 *	Run authenticate foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_auth_type, 0);
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
					      NULL, rctx);
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

	rlm_rcode_t			rcode = request->rcode;
	fr_pair_t			*vp;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->reply->code));

	if (auth_type_rcode[rcode] == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		request->reply->code = auth_type_rcode[rcode];
		UPDATE_STATE(reply);

		RDEBUG("The 'authenticate' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

		fr_assert(state->send != NULL);
		return state->send(p_result, mctx, request, rctx);
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
		vp = fr_pair_find_by_da(&request->request_pairs, attr_user_password, 0);
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
		if ((vp = fr_pair_find_by_da(&request->reply_pairs, attr_state, 0)) != NULL) {
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
	return state->send(p_result, mctx, request, rctx);
}

RESUME_NO_RCTX(access_accept)
{
	fr_pair_t			*vp;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_module_success_message, 0);
	if (vp) {
		auth_message(&inst->auth, request, true, "Login OK (%pV)", &vp->data);
	} else {
		auth_message(&inst->auth, request, true, "Login OK");
	}

	/*
	 *	Check that there is a name which can be used to
	 *	identify the user.  The configuration depends on
	 *	User-Name or Stripped-User-Name existing, and being
	 *	(mostly) unique to that user.
	 */
	if (!request->parent &&
	    ((vp = fr_pair_find_by_da(&request->request_pairs, attr_user_name, 0)) != NULL) &&
	    (vp->vp_strvalue[0] == '@') &&
	    !fr_pair_find_by_da(&request->request_pairs, attr_stripped_user_name, 0)) {
		RWDEBUG("User-Name is anonymized, and no Stripped-User-Name exists.");
		RWDEBUG("It may be difficult or impossible to identify the user.");
		RWDEBUG("Please update Stripped-User-Name with information which identifies the user.");
	}

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME_NO_RCTX(access_reject)
{
	fr_pair_t			*vp;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	vp = fr_pair_find_by_da(&request->request_pairs, attr_module_failure_message, 0);
	if (vp) {
		auth_message(&inst->auth, request, false, "Login incorrect (%pV)", &vp->data);
	} else {
		auth_message(&inst->auth, request, false, "Login incorrect");
	}

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME(access_challenge)
{
	CONF_SECTION			*cs;
	fr_process_state_t const	*state;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	/*
	 *	Cache the state context.
	 *
	 *	If this fails, don't respond to the request.
	 */
	if (fr_request_to_state(inst->auth.state_tree, request) < 0) {
		request->reply->code = FR_RADIUS_CODE_DO_NOT_RESPOND;
		UPDATE_STATE_CS(reply);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, rctx);
	}

	fr_assert(request->reply->code == FR_RADIUS_CODE_ACCESS_CHALLENGE);
	RETURN_MODULE_OK;
}

RESUME(acct_type)
{
	static const fr_process_rcode_t acct_type_rcode = {
		[RLM_MODULE_FAIL] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_INVALID] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_NOTFOUND] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_REJECT] =	FR_RADIUS_CODE_DO_NOT_RESPOND,
		[RLM_MODULE_DISALLOW] = FR_RADIUS_CODE_DO_NOT_RESPOND,
	};

	rlm_rcode_t			rcode = request->rcode;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->reply->code));

	if (acct_type_rcode[rcode]) {
		fr_assert(acct_type_rcode[rcode] == FR_RADIUS_CODE_DO_NOT_RESPOND);

		request->reply->code = acct_type_rcode[rcode];
		UPDATE_STATE(reply);

		RDEBUG("The 'accounting' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

		fr_assert(state->send != NULL);
		return state->send(p_result, mctx, request, rctx);
	}

	request->reply->code = FR_RADIUS_CODE_ACCOUNTING_RESPONSE;
	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request, rctx);
}

RESUME(accounting_request)
{
	rlm_rcode_t			rcode = request->rcode;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_t const		*dv;
	fr_process_state_t const	*state;
	process_radius_t const		*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);
	fr_assert(state->packet_type[rcode] != 0);

	request->reply->code = state->packet_type[rcode];
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_RADIUS_CODE_DO_NOT_RESPOND) {
		RDEBUG("The 'recv Accounting-Request' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

	send_reply:
		fr_assert(state->send != NULL);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, rctx);
	}

	/*
	 *	Run accounting foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_status_type, 0);
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
	return unlang_module_yield_to_section(p_result, request,
					      cs, RLM_MODULE_NOOP, resume_acct_type,
					      NULL, rctx);
}

#if 0
// @todo - send canned responses like in v3?
RECV(status_server)
{
	RETURN_MODULE_FAIL;
}

RESUME(status_server)
{
	RETURN_MODULE_FAIL;
}
#endif

RESUME(protocol_error)
{
	fr_pair_t 			*vp;

	PROCESS_TRACE;

	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->reply->code));

	/*
	 *	https://tools.ietf.org/html/rfc7930#section-4
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_original_packet_code, 0);
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
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_error_cause, 0);
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

	(void) talloc_get_type_abort_const(mctx->instance, process_radius_t);

	PROCESS_TRACE;

	fr_assert(FR_RADIUS_PACKET_CODE_VALID(request->packet->code));

	request->component = "radius";
	request->module = NULL;
	fr_assert(request->dict == dict_radius);

	UPDATE_STATE(packet);

	radius_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *process_app_cs)
{
	process_radius_t	*inst = instance;

	inst->auth.state_tree = fr_state_tree_init(inst, attr_state, main_config->spawn_workers, inst->auth.max_session,
						   inst->auth.session_timeout, inst->auth.state_server_id,
						   fr_hash_string(cf_section_name2(inst->server_cs)));

	return 0;
}

static int mod_bootstrap(void *instance, CONF_SECTION *cs)
{
	process_radius_t	*inst = instance;

	inst->server_cs = cf_section_find_in_parent(cs, "server", CF_IDENT_ANY);
	if (virtual_server_section_attribute_define(inst->server_cs, "authenticate", attr_auth_type) < 0) return -1;

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
		.recv = recv_access_request,
		.resume = resume_access_request,
		.section_offset = offsetof(process_radius_sections_t, access_request),
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
		.section_offset = offsetof(process_radius_sections_t, access_accept),
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
		.section_offset = offsetof(process_radius_sections_t, access_reject),
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_accounting_request,
		.section_offset = offsetof(process_radius_sections_t, accounting_request),
	},
	[ FR_RADIUS_CODE_ACCOUNTING_RESPONSE ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_NOTFOUND]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_ACCESS_REJECT
		},
		.rcode = RLM_MODULE_NOOP,
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_radius_sections_t, coa_request),
	},
	[ FR_RADIUS_CODE_COA_ACK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_radius_sections_t, coa_ack),
	},
	[ FR_RADIUS_CODE_COA_NAK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_COA_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_COA_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.section_offset = offsetof(process_radius_sections_t, disconnect_request),
	},
	[ FR_RADIUS_CODE_DISCONNECT_ACK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_radius_sections_t, disconnect_ack),
	},
	[ FR_RADIUS_CODE_DISCONNECT_NAK ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_INVALID]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_REJECT]	= FR_RADIUS_CODE_DISCONNECT_NAK,
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DISCONNECT_NAK
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_radius_sections_t, disconnect_nak),
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
			[RLM_MODULE_DISALLOW]	= FR_RADIUS_CODE_DO_NOT_RESPOND
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_radius_sections_t, do_not_respond),
	}
};

static virtual_server_compile_t const compile_list[] = {
	{
		.name = "recv",
		.name2 = "Access-Request",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(access_request),
	},
	{
		.name = "send",
		.name2 = "Access-Accept",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(access_accept),
	},
	{
		.name = "send",
		.name2 = "Access-Challenge",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(access_challenge),
	},
	{
		.name = "send",
		.name2 = "Access-Reject",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(access_reject),
	},

	{
		.name = "recv",
		.name2 = "Accounting-Request",
		.component = MOD_PREACCT,
		.offset = PROCESS_CONF_OFFSET(accounting_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Response",
		.component = MOD_ACCOUNTING,
		.offset = PROCESS_CONF_OFFSET(accounting_response),
	},

	{
		.name = "recv",
		.name2 = "Status-Server",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(status_server),
	},
	{
		.name = "recv",
		.name2 = "CoA-Request",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(coa_request),
	},
	{
		.name = "send",
		.name2 = "CoA-ACK",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(coa_ack),
	},
	{
		.name = "send",.name2 = "CoA-NAK",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(coa_nak),
	},
	{
		.name = "recv",
		.name2 = "Disconnect-Request",
		.component = MOD_AUTHORIZE,
		.offset = PROCESS_CONF_OFFSET(disconnect_request),
	},
	{
		.name = "send",
		.name2 = "Disconnect-ACK",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(disconnect_ack),
	},
	{
		.name = "send",
		.name2 = "Disconnect-NAK",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(disconnect_nak),
	},
	{
		.name = "send",
		.name2 = "Protocol-Error",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(protocol_error),
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},
	{
		.name = "authenticate",
		.name2 = CF_IDENT_ANY,
		.component = MOD_AUTHENTICATE
	},
	{
		.name = "accounting",
		.name2 = CF_IDENT_ANY,
		.component = MOD_AUTHENTICATE
	},
	COMPILE_TERMINATOR
};

extern fr_process_module_t process_radius;
fr_process_module_t process_radius = {
	.magic		= RLM_MODULE_INIT,
	.name		= "process_radius",
	.config		= config,
	.inst_size	= sizeof(process_radius_t),

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,

	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_radius,
};
