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
 * @brief RADIUS handler
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
#include <freeradius-devel/server/process.h>
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


static fr_dict_attr_t const *attr_packet_type;

static fr_dict_attr_t const *attr_acct_status_type;

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_calling_station_id;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_stripped_user_name;

static fr_dict_attr_t const *attr_nas_port;
static fr_dict_attr_t const *attr_service_type;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;

extern fr_dict_attr_autoload_t process_radius_dict_attr[];
fr_dict_attr_autoload_t process_radius_dict_attr[] = {
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },

	{ .out = &attr_calling_station_id, .name = "Calling-Station-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_nas_port, .name = "NAS-Port", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_service_type, .name = "Service-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },

	{ NULL }
};

/*
 *	RADIUS state machine configuration
 */
typedef struct radius_unlang_packets_s {
	uint64_t	nothing;		// so that "access_request" isn't at offset 0

	CONF_SECTION *access_request;
	CONF_SECTION *access_accept;
	CONF_SECTION *access_reject;
	CONF_SECTION *access_challenge;

	CONF_SECTION *accounting_request;
	CONF_SECTION *accounting_response;

	CONF_SECTION *status_server;

	CONF_SECTION *coa_request;
	CONF_SECTION *coa_ack;
	CONF_SECTION *coa_nak;

	CONF_SECTION *disconnect_request;
	CONF_SECTION *disconnect_ack;
	CONF_SECTION *disconnect_nak;

	CONF_SECTION *do_not_respond;
	CONF_SECTION *protocol_error; /* @todo - allow protocol error as a reject reply? */
} radius_unlang_packets_t;

typedef struct {
	bool		log_stripped_names;
	bool		log_auth;			//!< Log authentication attempts.
	bool		log_auth_badpass;		//!< Log successful authentications.
	bool		log_auth_goodpass;		//!< Log failed authentications.
	char const	*auth_badpass_msg;		//!< Additional text to append to successful auth messages.
	char const	*auth_goodpass_msg;		//!< Additional text to append to failed auth messages.

	char const	*denied_msg;			//!< Additional text to append if the user is already logged
							//!< in (simultaneous use check failed).

	uint32_t	session_timeout;		//!< Maximum time between the last response and next request.
	uint32_t	max_session;			//!< Maximum ongoing session allowed.

	uint8_t       	state_server_id;		//!< Sets a specific byte in the state to allow the
							//!< authenticating server to be identified in packet
							//!< captures.

	fr_state_tree_t	*state_tree;			//!< State tree to link multiple requests/responses.
} radius_auth_t;

typedef struct process_radius_s {
	radius_unlang_packets_t packets;
	radius_auth_t		auth;
} process_radius_t;

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, radius_auth_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, radius_auth_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, radius_auth_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER log_config[] = {
	{ FR_CONF_OFFSET("stripped_names", FR_TYPE_BOOL, radius_auth_t, log_stripped_names), .dflt = "no" },
	{ FR_CONF_OFFSET("auth", FR_TYPE_BOOL, radius_auth_t, log_auth), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_badpass", FR_TYPE_BOOL, radius_auth_t, log_auth_badpass), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_goodpass", FR_TYPE_BOOL,radius_auth_t,  log_auth_goodpass), .dflt = "no" },
	{ FR_CONF_OFFSET("msg_badpass", FR_TYPE_STRING, radius_auth_t, auth_badpass_msg) },
	{ FR_CONF_OFFSET("msg_goodpass", FR_TYPE_STRING, radius_auth_t, auth_goodpass_msg) },
	{ FR_CONF_OFFSET("msg_denied", FR_TYPE_STRING, radius_auth_t, denied_msg), .dflt = "You are already logged in - access denied" },

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
 *	RADIUS state machine tables for rcode to packet.
 */
typedef unsigned int fr_packet_rcode_t[RLM_MODULE_NUMCODES];

typedef struct radius_state_s {
	fr_packet_rcode_t	*packet_type;
	size_t			offset;
	rlm_rcode_t		rcode;		// default rcode
	unsigned int	       	reject;		// reject packet
	module_method_t		recv;		// for incoming requests
	unlang_module_resume_t	send;		// for sending replies
	unlang_module_resume_t	resume;
} radius_state_t;

static radius_state_t radius_state[FR_RADIUS_MAX_PACKET_CODE];

static fr_packet_rcode_t access_request = {
	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t auth_type_rcode = {
	[RLM_MODULE_OK] =	FR_CODE_ACCESS_ACCEPT,
	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_NOOP] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_UPDATED] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t access_accept = {
	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t access_reject = {
	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t access_challenge = {
	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t accounting_request = {
	[RLM_MODULE_NOOP] =	FR_CODE_ACCOUNTING_RESPONSE,
	[RLM_MODULE_OK] =	FR_CODE_ACCOUNTING_RESPONSE,
	[RLM_MODULE_UPDATED] =	FR_CODE_ACCOUNTING_RESPONSE,
	[RLM_MODULE_HANDLED] =	FR_CODE_ACCOUNTING_RESPONSE,

	[RLM_MODULE_FAIL] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_INVALID] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_REJECT] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_DISALLOW] = FR_CODE_DO_NOT_RESPOND,
};

static fr_packet_rcode_t acct_type_rcode = {
	[RLM_MODULE_FAIL] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_INVALID] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_REJECT] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_DISALLOW] = FR_CODE_DO_NOT_RESPOND,
};

static fr_packet_rcode_t accounting_response = {
	[RLM_MODULE_FAIL] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_INVALID] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_REJECT] =	FR_CODE_DO_NOT_RESPOND,
	[RLM_MODULE_DISALLOW] = FR_CODE_DO_NOT_RESPOND,
};

static fr_packet_rcode_t status_server = {
	[RLM_MODULE_OK] =	FR_CODE_ACCESS_ACCEPT,
	[RLM_MODULE_UPDATED] =	FR_CODE_ACCESS_ACCEPT,

	[RLM_MODULE_FAIL] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_INVALID] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_REJECT] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_NOOP] =	FR_CODE_ACCESS_REJECT,
	[RLM_MODULE_DISALLOW] = FR_CODE_ACCESS_REJECT,
};

static fr_packet_rcode_t coa_request = {
	[RLM_MODULE_NOOP] =	FR_CODE_COA_ACK,
	[RLM_MODULE_OK] =	FR_CODE_COA_ACK,
	[RLM_MODULE_UPDATED] =	FR_CODE_COA_ACK,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_COA_ACK,

	[RLM_MODULE_FAIL] =	FR_CODE_COA_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_COA_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_COA_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_COA_NAK
};

static fr_packet_rcode_t coa_ack = {
	[RLM_MODULE_FAIL] =	FR_CODE_COA_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_COA_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_COA_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_COA_NAK
};

static fr_packet_rcode_t coa_nak = {
	[RLM_MODULE_FAIL] =	FR_CODE_COA_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_COA_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_COA_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_COA_NAK
};

static fr_packet_rcode_t disconnect_request = {
	[RLM_MODULE_NOOP] =	FR_CODE_DISCONNECT_ACK,
	[RLM_MODULE_OK] =	FR_CODE_DISCONNECT_ACK,
	[RLM_MODULE_UPDATED] =	FR_CODE_DISCONNECT_ACK,
	[RLM_MODULE_NOTFOUND] =	FR_CODE_DISCONNECT_ACK,

	[RLM_MODULE_FAIL] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_DISCONNECT_NAK
};

static fr_packet_rcode_t disconnect_ack = {
	[RLM_MODULE_FAIL] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_DISCONNECT_NAK
};

static fr_packet_rcode_t disconnect_nak = {
	[RLM_MODULE_FAIL] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_INVALID] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_REJECT] =	FR_CODE_DISCONNECT_NAK,
	[RLM_MODULE_DISALLOW] = FR_CODE_DISCONNECT_NAK
};

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

	cli = fr_pair_find_by_da(&request->request_pairs, attr_calling_station_id);

	pair = fr_pair_find_by_da(&request->request_pairs, attr_nas_port);
	if (pair != NULL) port = pair->vp_uint32;

	if (request->packet->socket.inet.dst_port == 0) tls = " via proxy to virtual server";

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
		 request->client->shortname, port,
		 (cli ? " cli " : ""), (cli ? cli->vp_strvalue : ""),
		 tls);

	return buf;
}

/*
 *	Make sure user/pass are clean and then create an attribute
 *	which contains the log message.
 */
static void CC_HINT(format (printf, 4, 5)) auth_message(radius_auth_t const *inst,
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
		username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	} else {
		username = fr_pair_find_by_da(&request->request_pairs, attr_stripped_user_name);
		if (!username) username = fr_pair_find_by_da(&request->request_pairs, attr_user_name);
	}

	/*
	 *	Clean up the password
	 */
	if (inst->log_auth_badpass || inst->log_auth_goodpass) {
		password = fr_pair_find_by_da(&request->request_pairs, attr_user_password);
		if (!password) {
			fr_pair_t *auth_type;

			auth_type = fr_pair_find_by_da(&request->control_pairs, attr_auth_type);
			if (auth_type) {
				snprintf(password_buff, sizeof(password_buff), "<via Auth-Type = %s>",
					 fr_dict_enum_name_by_value(auth_type->da, &auth_type->data));
				password_str = password_buff;
			} else {
				password_str = "<no User-Password attribute>";
			}
		} else if (fr_pair_find_by_da(&request->request_pairs, attr_chap_password)) {
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

/*
 *	RADIUS state machine functions
 */
#define UPDATE_STATE_CS(_x) do { \
			state = &radius_state[request->_x->code]; \
			cs = *(CONF_SECTION **) (((uint8_t *) &inst->packets) + state->offset); \
		} while (0)

#define UPDATE_STATE(_x) state = &radius_state[request->_x->code]

#define RCODE2PACKET(_x) ((*state->packet_type)[_x])

#define RECV(_x) static unlang_action_t recv_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
#define SEND(_x) static unlang_action_t send_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, UNUSED void *rctx)
#define RESUME(_x) static unlang_action_t resume_ ## _x(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request, UNUSED void *rctx)

#define RADIUS_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_RADIUS_MAX_PACKET_CODE))
#if 0
RECV(access_request)
{
	RETURN_MODULE_FAIL;
}
#endif

RESUME(auth_type);

RESUME(access_request)
{
	rlm_rcode_t		rcode = request->rcode;
	fr_pair_t		*vp;
	CONF_SECTION		*cs;
	fr_dict_enum_t const	*dv;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);
	fr_assert(RCODE2PACKET(rcode) != 0);

	request->reply->code = RCODE2PACKET(rcode);
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
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
	vp = fr_pair_find_by_da(&request->request_pairs, attr_auth_type);
	if (!vp) goto send_reply;

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) goto send_reply;

	cs = cf_section_find(request->server_cs, "authenticate", dv->name);
	if (!cs) {
		RDEBUG2("No 'authenticate %s { ... }' section found - skipping...", dv->name);
		goto send_reply;
	}

	/*
	 *	Run the "Autheenticate = foo" section.
	 *
	 *	And continue with sending the generic reply.
	 */
	return unlang_module_yield_to_section(p_result, request,
					      cs, RLM_MODULE_NOOP, resume_auth_type,
					      NULL, NULL);
}

RESUME(auth_type)
{
	rlm_rcode_t		rcode = request->rcode;
	fr_pair_t		*vp;
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(RADIUS_PACKET_CODE_VALID(request->reply->code));

	if (auth_type_rcode[rcode] == FR_CODE_DO_NOT_RESPOND) {
		request->reply->code = auth_type_rcode[rcode];
		UPDATE_STATE_CS(reply);

		RDEBUG("The 'authenticate' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

		fr_assert(state->send != NULL);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	/*
	 *	Set the reply code.
	 */
	request->reply->code = auth_type_rcode[rcode];
	if (!request->reply->code) {
		RDEBUG("No reply code was set.  Forcing to Access-Reject");
		request->reply->code = FR_CODE_ACCESS_REJECT;

	} else switch (request->reply->code) {
	/*
	 *	Print complaints before running "send Access-Reject"
	 */
	case FR_CODE_ACCESS_REJECT:
		RDEBUG2("Failed to authenticate the user");

		/*
		 *	Maybe the shared secret is wrong?
		 */
		vp = fr_pair_find_by_da(&request->request_pairs, attr_user_password);
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
	 *	Access-Challenge packets require a State.  If there is
	 *	none, create one here.  This is so that the State
	 *	attribute is accessible in the "send Access-Challenge"
	 *	section.
	 */
	case FR_CODE_ACCESS_CHALLENGE:
		if ((vp = fr_pair_find_by_da(&request->reply_pairs, attr_state)) != NULL) {
			uint8_t buffer[16];

			fr_rand_buffer(buffer, sizeof(buffer));

			MEM(pair_update_reply(&vp, attr_state) >= 0);
			fr_pair_value_memdup(vp, buffer, sizeof(buffer), false);
		}
		break;

	default:
		break;

	}
	UPDATE_STATE_CS(reply);

	fr_assert(state->send != NULL);
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->send,
					      NULL, NULL);
}

RESUME(access_accept)
{
	fr_pair_t *vp;
	process_radius_t *inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	vp = fr_pair_find_by_da(&request->request_pairs, attr_module_success_message);
	if (vp){
		auth_message(&inst->auth, request, true, "Login OK (%pV)", &vp->data);
	} else {
		auth_message(&inst->auth, request, true, "Login OK");
	}

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME(access_reject)
{
	fr_pair_t *vp;
	process_radius_t *inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	vp = fr_pair_find_by_da(&request->request_pairs, attr_module_failure_message);
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
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	/*
	 *	Cache the state context.
	 *
	 *	If this fails, don't respond to the request.
	 */
	if (fr_request_to_state(inst->auth.state_tree, request) < 0) {
		request->reply->code = FR_CODE_DO_NOT_RESPOND;
		UPDATE_STATE_CS(reply);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	fr_assert(request->reply->code == FR_CODE_ACCESS_CHALLENGE);
	RETURN_MODULE_OK;
}

RESUME(acct_type)
{
	rlm_rcode_t		rcode = request->rcode;
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	fr_assert(RADIUS_PACKET_CODE_VALID(request->reply->code));

	if (acct_type_rcode[rcode]) {
		fr_assert(acct_type_rcode[rcode] == FR_CODE_DO_NOT_RESPOND);

		request->reply->code = acct_type_rcode[rcode];
		UPDATE_STATE_CS(reply);

		RDEBUG("The 'accounting' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

		fr_assert(state->send != NULL);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	request->reply->code = FR_CODE_ACCOUNTING_RESPONSE;
	UPDATE_STATE_CS(reply);

	fr_assert(state->send != NULL);
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->send,
					      NULL, NULL);
}

RESUME(accounting_request)
{
	rlm_rcode_t		rcode = request->rcode;
	fr_pair_t		*vp;
	CONF_SECTION		*cs;
	fr_dict_enum_t const	*dv;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);
	fr_assert(RCODE2PACKET(rcode) != 0);

	request->reply->code = RCODE2PACKET(rcode);
	UPDATE_STATE_CS(reply);

	if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
		RDEBUG("The 'recv Accounting-Request' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"));

	send_reply:
		fr_assert(state->send != NULL);
		return unlang_module_yield_to_section(p_result, request,
						      cs, state->rcode, state->send,
						      NULL, NULL);
	}

	/*
	 *	Run accounting foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_status_type);
	if (!vp) goto send_reply;

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) goto send_reply;

	cs = cf_section_find(request->server_cs, "accounting", dv->name);
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
					      NULL, NULL);
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

RECV(generic)
{
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	if (request->parent && RDEBUG_ENABLED) {
		RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->request_pairs, NULL);
	}

	request->component = "radius";
	fr_assert(request->dict == dict_radius);

	UPDATE_STATE_CS(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type");
		RETURN_MODULE_FAIL;
	}

	RDEBUG("Running 'recv %s' from file %s", cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, NULL);
}

RESUME(recv_generic)
{
	rlm_rcode_t		rcode = request->rcode;
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);
	fr_assert(RCODE2PACKET(rcode) != 0);

	request->reply->code = RCODE2PACKET(rcode);
	UPDATE_STATE_CS(reply);

	fr_assert(state->send != NULL);
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->send,
					      NULL, NULL);
}

SEND(generic)
{
	fr_pair_t 		*vp;
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	ERROR("HERE %s", __FUNCTION__);

	fr_assert(RADIUS_PACKET_CODE_VALID(request->reply->code));

	UPDATE_STATE_CS(reply);

	/*
	 *	Allow for over-ride of reply code, IF it's
	 *	within range, AND we've pre-compiled the
	 *	unlang.
	 *
	 *	Add reply->packet-type in case we're
	 *	being called via the `call {}` keyword.
	 *
	 *	@todo - enforce that this is an allowed reply for the
	 *	request.
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, attr_packet_type);
	if (!vp) {
		MEM(fr_pair_update_by_da(request->reply_ctx, &vp,
					 &request->reply_pairs, attr_packet_type) >= 0);
		vp->vp_uint32 = request->reply->code;

	} else if (RADIUS_PACKET_CODE_VALID(vp->vp_uint32)) {
		request->reply->code = vp->vp_uint32;
		UPDATE_STATE_CS(reply);

	} else {
		RWDEBUG("Ignoring invalid value %u for &reply.Packet-Type", vp->vp_uint32);
	}

	RDEBUG("Running 'send %s' from file %s", cf_section_name2(cs), cf_filename(cs));
	return unlang_module_yield_to_section(p_result, request,
					      cs, state->rcode, state->resume,
					      NULL, NULL);
}

RESUME(send_generic)
{
	rlm_rcode_t		rcode = request->rcode;
	CONF_SECTION		*cs;
	radius_state_t const	*state;
	process_radius_t	*inst = talloc_get_type_abort_const(mctx->instance, process_radius_t);

	ERROR("HERE %s", __FUNCTION__);

	fr_assert(RADIUS_PACKET_CODE_VALID(request->reply->code));

	/*
	 *	If they delete &reply.Packet-Type, tough for them.
	 */
	UPDATE_STATE_CS(reply);

	fr_assert(rcode < RLM_MODULE_NUMCODES);
	switch (RCODE2PACKET(rcode)) {
	case 0:			/* don't change the reply */
		fr_assert(request->reply->code != 0);
		break;

	default:
		/*
		 *	ACK can turn into NAK, but not vice versa.
		 *	And anything can say "don't respond".
		 */
		if ((RCODE2PACKET(rcode) != request->reply->code) &&
		    ((RCODE2PACKET(rcode) == state->reject) || (RCODE2PACKET(rcode) == FR_CODE_DO_NOT_RESPOND))) {
			char const *old = cf_section_name2(cs);

			request->reply->code = RCODE2PACKET(rcode);
			UPDATE_STATE_CS(reply);

			RWDEBUG("Failed running 'send %s', changing reply to %s", old, cf_section_name2(cs));

			return unlang_module_yield_to_section(p_result, request,
							      cs, state->rcode, state->send,
							      NULL, NULL);
		}

		fr_assert(!RCODE2PACKET(rcode) || (RCODE2PACKET(rcode) == request->reply->code));
		break;

	case FR_CODE_DO_NOT_RESPOND:
		RDEBUG("The 'send %s' section returned %s - not sending a response",
		       fr_table_str_by_value(rcode_table, rcode, "???"),
		       cf_section_name2(cs));
		request->reply->code = FR_CODE_DO_NOT_RESPOND;
		break;
	}

	request->reply->timestamp = fr_time();

	/*
	 *	Check for "do not respond".
	 */
	if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
		RDEBUG("Not sending reply to client.");
		RETURN_MODULE_OK;
	}

	if (request->parent && RDEBUG_ENABLED) {
		RDEBUG("Sending %s ID %i", fr_packet_codes[request->reply->code], request->reply->id);
		log_request_pair_list(L_DBG_LVL_1, request, NULL, &request->reply_pairs, NULL);
	}

	RETURN_MODULE_OK;
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	radius_state_t 	const	*state;

	fr_assert(RADIUS_PACKET_CODE_VALID(request->packet->code));

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type");
		RETURN_MODULE_FAIL;
	}

	return state->recv(p_result, mctx, request);
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *process_app_cs)
{
	process_radius_t	*inst = instance;

	inst->auth.state_tree = fr_state_tree_init(inst, attr_state, main_config->spawn_workers, inst->auth.max_session,
						   inst->auth.session_timeout, inst->auth.state_server_id);

	return 0;
}

static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *cs)
{
	CONF_SECTION		*server_cs;

	server_cs = cf_item_to_section(cf_parent(cs));
	fr_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	return 0;
}

static radius_state_t radius_state[FR_RADIUS_MAX_PACKET_CODE] = {
	[ FR_CODE_ACCESS_REQUEST ] = {
		.packet_type = &access_request,
		.rcode = RLM_MODULE_REJECT,
		.recv = recv_generic,
		.resume = resume_access_request,
		.offset = offsetof(radius_unlang_packets_t, access_request),
	},
	[ FR_CODE_ACCESS_ACCEPT ] = {
		.packet_type = &access_accept,
		.rcode = RLM_MODULE_NOOP,
		.reject = FR_CODE_ACCESS_REJECT,
		.send = send_generic,
		.resume = resume_access_accept,
		.offset = offsetof(radius_unlang_packets_t, access_accept),
	},
	[ FR_CODE_ACCESS_REJECT ] = {
		.packet_type = &access_reject,
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_access_reject,
		.offset = offsetof(radius_unlang_packets_t, access_reject),
	},
	[ FR_CODE_ACCESS_CHALLENGE ] = {
		.packet_type = &access_challenge,
		.rcode = RLM_MODULE_NOOP,
		.reject = FR_CODE_ACCESS_REJECT,
		.send = send_generic,
		.resume = resume_access_challenge,
		.offset = offsetof(radius_unlang_packets_t, access_challenge),
	},

	[ FR_CODE_ACCOUNTING_REQUEST ] = {
		.packet_type = &accounting_request,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_accounting_request,
		.offset = offsetof(radius_unlang_packets_t, accounting_request),
	},
	[ FR_CODE_ACCOUNTING_RESPONSE ] = {
		.packet_type = &accounting_response,
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.offset = offsetof(radius_unlang_packets_t, accounting_response),
	},

	[ FR_CODE_STATUS_SERVER ] = {
		.packet_type = &status_server,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.offset = offsetof(radius_unlang_packets_t, status_server),
	},

	[ FR_CODE_COA_REQUEST ] = {
		.packet_type = &coa_request,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.offset = offsetof(radius_unlang_packets_t, coa_request),
	},
	[ FR_CODE_COA_ACK ] = {
		.packet_type = &coa_ack,
		.rcode = RLM_MODULE_NOOP,
		.reject = FR_CODE_COA_NAK,
		.send = send_generic,
		.resume = resume_send_generic,
		.offset = offsetof(radius_unlang_packets_t, coa_ack),
	},
	[ FR_CODE_COA_NAK ] = {
		.packet_type = &coa_nak,
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.offset = offsetof(radius_unlang_packets_t, coa_nak),
	},

	[ FR_CODE_DISCONNECT_REQUEST ] = {
		.packet_type = &disconnect_request,
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_recv_generic,
		.offset = offsetof(radius_unlang_packets_t, disconnect_request),
	},
	[ FR_CODE_DISCONNECT_ACK ] = {
		.packet_type = &disconnect_ack,
		.rcode = RLM_MODULE_NOOP,
		.reject = FR_CODE_DISCONNECT_NAK,
		.send = send_generic,
		.resume = resume_send_generic,
		.offset = offsetof(radius_unlang_packets_t, disconnect_ack),
	},
	[ FR_CODE_DISCONNECT_NAK ] = {
		.packet_type = &disconnect_nak,
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.offset = offsetof(radius_unlang_packets_t, disconnect_nak),
	},
};

#undef CONF
#define CONF(_x) .offset = offsetof(process_radius_t, packets._x)

static const virtual_server_compile_t compile_list[] = {
	{
		.name = "recv",
		.name2 = "Access-Request",
		.component = MOD_AUTHORIZE,
		CONF(access_request),
	},
	{
		.name = "send",
		.name2 = "Access-Accept",
		.component = MOD_POST_AUTH,
		CONF(access_accept),
	},
	{
		.name = "send",
		.name2 = "Access-Challenge",
		.component = MOD_POST_AUTH,
		CONF(access_challenge),
	},
	{
		.name = "send",
		.name2 = "Access-Reject",
		.component = MOD_POST_AUTH,
		CONF(access_reject),
	},

	{
		.name = "recv",
		.name2 = "Accounting-Request",
		.component = MOD_PREACCT,
		CONF(accounting_request),
	},
	{
		.name = "send",
		.name2 = "Accounting-Response",
		.component = MOD_ACCOUNTING,
		CONF(accounting_response),
	},

	{
		.name = "recv",
		.name2 = "Status-Server",
		.component = MOD_AUTHORIZE,
		CONF(status_server),
	},


	{
		.name = "recv",
		.name2 = "CoA-Request",
		.component = MOD_AUTHORIZE,
		CONF(coa_request),
	},
	{
		.name = "send",
		.name2 = "CoA-ACK",
		.component = MOD_POST_AUTH,
		CONF(coa_ack),
	},
	{
		.name = "send",.name2 = "CoA-NAK",
		.component = MOD_AUTHORIZE,
		CONF(coa_nak),
	},
	{
		.name = "recv",
		.name2 = "Disconnect-Request",
		.component = MOD_AUTHORIZE,
		CONF(disconnect_request),
	},
	{
		.name = "send",
		.name2 = "Disconnect-ACK",
		.component = MOD_POST_AUTH,
		CONF(disconnect_ack),
	},
	{
		.name = "send",
		.name2 = "Disconnect-NAK",
		.component = MOD_POST_AUTH,
		CONF(disconnect_nak),
	},
	{
		.name = "send",
		.name2 = "Protocol-Error",
		.component = MOD_POST_AUTH,
		CONF(protocol_error),
	},
	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		CONF(do_not_respond),
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
