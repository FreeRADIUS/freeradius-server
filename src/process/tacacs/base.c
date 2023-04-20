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
 * @file src/process/tacacs/base.c
 * @brief TACACS+ handler.
 * @author Jorge Pereira <jpereira@freeradius.org>
 *
 * @copyright 2020 The FreeRADIUS server project.
 * @copyright 2020 Network RADIUS SAS (legal@networkradius.com)
 */


#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/io/master.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/server/protocol.h>
#include <freeradius-devel/server/state.h>
#include <freeradius-devel/tacacs/tacacs.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/protocol/tacacs/tacacs.h>

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_tacacs;

extern fr_dict_autoload_t process_tacacs_dict[];
fr_dict_autoload_t process_tacacs_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_tacacs, .proto = "tacacs" },
	{ NULL }
};

static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_stripped_user_name;
static fr_dict_attr_t const *attr_packet_type;

static fr_dict_attr_t const *attr_tacacs_action;
static fr_dict_attr_t const *attr_tacacs_authentication_action;
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
static fr_dict_attr_t const *attr_tacacs_sequence_number;
static fr_dict_attr_t const *attr_tacacs_state;

static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_chap_password;

extern fr_dict_attr_autoload_t process_tacacs_dict_attr[];
fr_dict_attr_autoload_t process_tacacs_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_stripped_user_name, .name = "Stripped-User-Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
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
	{ .out = &attr_tacacs_authentication_action, .name = "Action", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_session_id, .name = "Packet.Session-Id", .type = FR_TYPE_UINT32, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_sequence_number, .name = "Packet.Sequence-Number", .type = FR_TYPE_UINT8, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_server_message, .name = "Server-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_tacacs_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },

	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },

	{ NULL }
};

static fr_value_box_t const	*enum_auth_type_accept;
static fr_value_box_t const	*enum_auth_type_reject;

extern fr_dict_enum_autoload_t process_tacacs_dict_enum[];
fr_dict_enum_autoload_t process_tacacs_dict_enum[] = {
	{ .out = &enum_auth_type_accept, .name = "Accept", .attr = &attr_auth_type },
	{ .out = &enum_auth_type_reject, .name = "Reject", .attr = &attr_auth_type },
	{ NULL }
};


typedef struct {
	uint64_t	nothing;		// so that the next field isn't at offset 0

	CONF_SECTION	*auth_start;
	CONF_SECTION	*auth_pass;
	CONF_SECTION	*auth_fail;
	CONF_SECTION	*auth_getdata;
	CONF_SECTION	*auth_getuser;
	CONF_SECTION	*auth_getpass;
	CONF_SECTION	*auth_restart;
	CONF_SECTION	*auth_error;

	CONF_SECTION	*auth_cont;
	CONF_SECTION	*auth_cont_abort;

	CONF_SECTION	*autz_request;
	CONF_SECTION	*autz_pass_add;
	CONF_SECTION	*autz_pass_replace;
	CONF_SECTION	*autz_fail;
	CONF_SECTION	*autz_error;

	CONF_SECTION	*acct_request;
	CONF_SECTION	*acct_success;
	CONF_SECTION	*acct_error;

	CONF_SECTION	*do_not_respond;
} process_tacacs_sections_t;

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

	uint32_t	max_rounds;		//!< maximum number of authentication rounds allowed

	uint8_t       	state_server_id;	//!< Sets a specific byte in the state to allow the
						//!< authenticating server to be identified in packet
						//!<captures.

	fr_state_tree_t	*state_tree;		//!< State tree to link multiple requests/responses.
} process_tacacs_auth_t;

typedef struct {
	CONF_SECTION	*server_cs;		//!< Our virtual server.

	uint32_t	session_id;		//!< current session ID

	process_tacacs_sections_t sections;	//!< Pointers to various config sections
						///< we need to execute

	process_tacacs_auth_t	auth;		//!< Authentication configuration.
} process_tacacs_t;

typedef struct {
	uint32_t       	rounds;			//!< how many rounds were taken
	uint32_t	reply;			//!< for multiround state machine
	uint8_t		seq_no;			//!< sequence number of last request.
	fr_pair_list_t	list;			//!< copied from the request
} process_tacacs_session_t;


#define PROCESS_PACKET_TYPE		fr_tacacs_packet_code_t
#define PROCESS_CODE_MAX		FR_TACACS_CODE_MAX
#define PROCESS_PACKET_CODE_VALID	FR_TACACS_PACKET_CODE_VALID
#define PROCESS_INST			process_tacacs_t

#include <freeradius-devel/server/process.h>

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, process_tacacs_auth_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, process_tacacs_auth_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("max_rounds", FR_TYPE_UINT32, process_tacacs_auth_t, max_rounds), .dflt = "4" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, process_tacacs_auth_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER log_config[] = {
	{ FR_CONF_OFFSET("stripped_names", FR_TYPE_BOOL, process_tacacs_auth_t, log_stripped_names), .dflt = "no" },
	{ FR_CONF_OFFSET("auth", FR_TYPE_BOOL, process_tacacs_auth_t, log_auth), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_badpass", FR_TYPE_BOOL, process_tacacs_auth_t, log_auth_badpass), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_goodpass", FR_TYPE_BOOL,process_tacacs_auth_t,  log_auth_goodpass), .dflt = "no" },
	{ FR_CONF_OFFSET("msg_badpass", FR_TYPE_STRING, process_tacacs_auth_t, auth_badpass_msg) },
	{ FR_CONF_OFFSET("msg_goodpass", FR_TYPE_STRING, process_tacacs_auth_t, auth_goodpass_msg) },
	{ FR_CONF_OFFSET("msg_denied", FR_TYPE_STRING, process_tacacs_auth_t, denied_msg), .dflt = "You are already logged in - access denied" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER auth_config[] = {
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER config[] = {
	{ FR_CONF_POINTER("Authentication", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) auth_config,
	  .offset = offsetof(process_tacacs_t, auth), },

	CONF_PARSER_TERMINATOR
};


#define RAUTH(fmt, ...)		log_request(L_AUTH, L_DBG_LVL_OFF, request, __FILE__, __LINE__, fmt, ## __VA_ARGS__)

/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
static char *auth_name(char *buf, size_t buflen, request_t *request)
{
	char const	*tls = "";
	fr_client_t	*client = client_from_request(request);

	if (request->packet->socket.inet.dst_port == 0) tls = " via proxy to virtual server";

	snprintf(buf, buflen, "from client %.128s%s",
		 client ? client->shortname : "", tls);

	return buf;
}


/*
 *	Make sure user/pass are clean and then create an attribute
 *	which contains the log message.
 */
static void CC_HINT(format (printf, 4, 5)) auth_message(process_tacacs_auth_t const *inst,
							request_t *request, bool goodpass, char const *fmt, ...)
{
	va_list		 ap;

	bool		logit;
	char const	*extra_msg = NULL;

	char		password_buff[256];
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
	 *	Get the correct username based on the configured value
	 */
	if (!inst->log_stripped_names) {
		username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	} else {
		username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_stripped_user_name);
		if (!username) username = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
	}

	/*
	 *	Clean up the password
	 */
	if (inst->log_auth_badpass || inst->log_auth_goodpass) {
		password = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_password);
		if (!password) {
			fr_pair_t *auth_type;

			auth_type = fr_pair_find_by_da(&request->control_pairs, NULL, attr_auth_type);
			if (auth_type) {
				snprintf(password_buff, sizeof(password_buff), "<via Auth-Type = %s>",
					 fr_dict_enum_name_by_value(auth_type->da, &auth_type->data));
				password_str = password_buff;
			} else {
				password_str = "<no User-Password attribute>";
			}
		} else if (fr_pair_find_by_da(&request->request_pairs, NULL, attr_chap_password)) {
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
 *	Synthesize a State attribute from connection && session information.
 */
static int state_create(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, bool reply)
{
	uint8_t		buffer[12];
	uint32_t	hash;
	fr_pair_t 	*vp;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_session_id);
	if (!vp) return -1;

	fr_nbo_from_uint32(buffer, vp->vp_uint32);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_sequence_number);
	if (!vp) return -1;

	/*
	 *	Requests have odd sequence numbers, and replies have even sequence numbers.
	 *	So if we want to synthesize a state in a reply which gets matched with the next
	 *	request, we have to add 2 to it.
	 */
	hash = vp->vp_uint8 + ((int) reply << 1);

	fr_nbo_from_uint32(buffer + 4, hash);

	/*
	 *	Hash in the listener.  For now, we don't allow internally proxied requests.
	 */
	fr_assert(request->async != NULL);
	fr_assert(request->async->listen != NULL);
	hash = fr_hash(&request->async->listen, sizeof(request->async->listen));

	fr_nbo_from_uint32(buffer + 8, hash);

	vp = fr_pair_afrom_da(ctx, attr_tacacs_state);
	if (!vp) return -1;

	(void) fr_pair_value_memdup(vp, buffer, 12, false);

	fr_pair_append(out, vp);

	return 0;
}

/** Try and determine what the response packet type should be
 *
 * We check three sources:
 * - reply.``<status_attr>``
 * - reply.Packet-Type
 * - State machine packet type assignments for the section rcode
 *
 * @param[in] request		The current request.
 * @param[in] status_da		Specialised status attribute.
 * @param[in] status2code	Mapping table of *packet* status types to rcodes.
 * @param[in] state		Mappings for process state machine
 * @param[in] process_rcode	Mappings for Auth-Type / Acct-Type, which don't use the process state machine
 * @param[in] rcode		The last section rcode.
 * @return
 *	- >0 if we determined a reply code.
 *	- 0 if we couldn't - Usually indicates additional sections should be run.
 */
static uint32_t reply_code(request_t *request, fr_dict_attr_t const *status_da,
			   uint32_t const status2code[static UINT8_MAX + 1],
			   fr_process_state_t const *state, fr_process_rcode_t const process_rcode, rlm_rcode_t rcode)
{
	fr_pair_t *vp;
	uint32_t code;

	/*
	 *  First check the protocol attribute for this packet type.
	 *
	 *  Should be one of:
	 *   - Authentication-Status
	 *   - Authorization-Status
	 *   - Accounting-Status
	 */
	fr_assert(status_da->type == FR_TYPE_UINT8);

	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, status_da);
	if (vp) {
		code = status2code[vp->vp_uint8];
		if (FR_TACACS_PACKET_CODE_VALID(code)) {
			RDEBUG("Setting reply Packet-Type from %pP", vp);
			return code;
		}
		REDEBUG("Ignoring invalid status %pP", vp);
	}

	if (state) {
		code = state->packet_type[rcode];
		if (FR_TACACS_PACKET_CODE_VALID(code)) return code;
	}

	if (process_rcode) {
		code = process_rcode[rcode];
		if (FR_TACACS_PACKET_CODE_VALID(code)) return code;
	}

	/*
	 *	Otherwise use Packet-Type (if set)
	 */
	vp = fr_pair_find_by_da(&request->reply_pairs, NULL, attr_packet_type);
	if (vp && FR_TACACS_PACKET_CODE_VALID(vp->vp_uint32)) {
		RDEBUG("Setting reply Packet-Type from %pV", &vp->data);
		return vp->vp_uint32;
	}

	return 0;
}

RECV(auth_start)
{
	fr_process_state_t const	*state;
	fr_pair_t			*vp;

	/*
	 *	Only "Login" is supported.  The others are "change password" and "sendauth", which aren't
	 *	used.
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_action);
	if (!vp) {
	fail:
		request->reply->code = FR_TACACS_CODE_AUTH_ERROR;
		UPDATE_STATE(reply);

		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	if (vp->vp_uint8 != FR_ACTION_VALUE_LOGIN) {
		RDEBUG("Invalid authentication action %u", vp->vp_uint8);
		goto fail;
	}

	/*
	 *	There is no state to restore, so we just run the section as normal.
	 */

	return CALL_RECV(generic);
}

RESUME(auth_type);

static const uint32_t authen_status_to_packet_code[UINT8_MAX + 1] = {
	[FR_TAC_PLUS_AUTHEN_STATUS_PASS] = FR_TACACS_CODE_AUTH_PASS,
	[FR_TAC_PLUS_AUTHEN_STATUS_FAIL] = FR_TACACS_CODE_AUTH_FAIL,
	[FR_TAC_PLUS_AUTHEN_STATUS_GETDATA] = FR_TACACS_CODE_AUTH_GETDATA,
	[FR_TAC_PLUS_AUTHEN_STATUS_GETUSER] = FR_TACACS_CODE_AUTH_GETUSER,
	[FR_TAC_PLUS_AUTHEN_STATUS_GETPASS] = FR_TACACS_CODE_AUTH_GETPASS,
	[FR_TAC_PLUS_AUTHEN_STATUS_RESTART] = FR_TACACS_CODE_AUTH_RESTART,
	[FR_TAC_PLUS_AUTHEN_STATUS_ERROR] = FR_TACACS_CODE_AUTH_ERROR,
};

RESUME(auth_start)
{
	rlm_rcode_t			rcode = *p_result;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	See if the return code from "recv" which says we reject, or continue.
	 */
	UPDATE_STATE(packet);

	/*
	 *	Nothing set the reply, so let's see if we need to do so.
	 *
	 *	If the admin didn't set authentication-status, just
	 *	use the defaults from the state machine.
	 */
	if (!request->reply->code) {
		request->reply->code = reply_code(request,
						  attr_tacacs_authentication_status,
						  authen_status_to_packet_code, state, NULL, rcode);
	} else {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->reply->code));
	}

	/*
	 *	Check for multi-round authentication.
	 *
	 *	We only run the automatic state machine (start -> getuser -> getpass -> pass/fail)
	 *	when the admin does NOT set any reply type, or any reply authentication status.
	 *
	 *	However, do DO always save and restore the attributes from the start packet, so that they are
	 *	visible in a later packet.
	 */
	if (!request->reply->code) {
		process_tacacs_session_t *session;
		fr_tacacs_packet_t const *packet = (fr_tacacs_packet_t const *) request->packet->data;

		session = request_data_reference(request, inst, 0);
		if (!session) {
			/*
			 *	This function is called for resuming both "start" and "continue" packets, so
			 *	we have to check for "start" here.
			 *
			 *	We only do multi-round authentication for the ASCII authentication type.
			 *	Other authentication types are defined to be one request/reply only.
			 */
			if (!packet_is_authen_start_request(packet) ||
			    (packet->authen_start.authen_type != FR_AUTHENTICATION_TYPE_VALUE_ASCII)) {
				goto auth_type;
			}

			vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
			if (vp && vp->vp_length == 0) {
				RDEBUG("No User-Name, replying with Authentication-GetUser");
				request->reply->code = FR_TACACS_CODE_AUTH_GETUSER;

			} else {
				RDEBUG("User-Name = %pV, replying with Authentication-GetPass", &vp->data);
				request->reply->code = FR_TACACS_CODE_AUTH_GETPASS;
			}

			goto send_reply;
		}

		/*
		 *	Last reply was "get username", we now get the password.
		 */
		if (session->reply == FR_TAC_PLUS_AUTHEN_STATUS_GETUSER) {
			RDEBUG("No User-Password, replying with Authentication-GetPass");
			request->reply->code = FR_TACACS_CODE_AUTH_GETPASS;
			goto send_reply;
		}

		/*
		 *	We either have a password, or the admin screwed up the configuration somehow.  Just go
		 *	run "Auth-Type foo".
		 */
		goto auth_type;
	}

	/*
	 *	Something set the reply code, skip
	 *	the normal auth flow and respond immediately.
	 */
	if (request->reply->code) {
		switch (request->reply->code) {
		case FR_TACACS_CODE_AUTH_FAIL:
			RDEBUG("The 'recv Authentication-Start' section returned %s - rejecting the request",
			       fr_table_str_by_value(rcode_table, rcode, "<INVALID>"));
			break;

		default:
			RDEBUG("Reply packet type was set to %s", fr_tacacs_packet_names[request->reply->code]);
			break;
		}

	send_reply:
		UPDATE_STATE(reply);

		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	/*
	 *	Run authenticate foo { ... }
	 *
	 *	If we can't find Auth-Type, OR if we can't find Auth-Type = foo, then it's a reject.
	 *
	 *	We prefer the local Auth-Type to the Authentication-Type in the packet.  But if there's no
	 *	Auth-Type set by the admin, then we use what's in the packet.
	 */
	auth_type:
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_auth_type);
	if (!vp) vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_authentication_type);
	if (!vp) {
		RDEBUG("No 'Auth-Type' or 'Authentication-Type' attribute found, "
		       "cannot authenticate the user - rejecting the request");

	reject:
		request->reply->code = FR_TACACS_CODE_AUTH_FAIL;
		goto send_reply;
	}

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) {
		RDEBUG("Invalid value for '%s' attribute, cannot authenticate the user - rejecting the request",
		       vp->da->name);

		goto reject;
	}

	/*
	 *	The magic Auth-Type Accept value which means skip the authenticate section.
	 *
	 *	And Reject means always reject.  Tho the admin should just return "reject" from the section.
	 */
	if (vp->da == attr_auth_type) {
		if (fr_value_box_cmp(enum_auth_type_accept, dv->value) == 0) {
			request->reply->code = FR_TACACS_CODE_AUTH_PASS;
			goto send_reply;

		} else if (fr_value_box_cmp(enum_auth_type_reject, dv->value) == 0) {
			request->reply->code = FR_TACACS_CODE_AUTH_FAIL;
			goto send_reply;
		}
	}

	cs = cf_section_find(inst->server_cs, "authenticate", dv->name);
	if (!cs) {
		RDEBUG2("No 'authenticate %s { ... }' section found - rejecting the request", dv->name);
		goto reject;
	}

	/*
	 *	Run the "authenticate foo { ... }" section.
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
		[RLM_MODULE_OK] =	FR_TACACS_CODE_AUTH_PASS,
		[RLM_MODULE_FAIL] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_INVALID] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_NOOP] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_NOTFOUND] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_REJECT] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_UPDATED] =	FR_TACACS_CODE_AUTH_FAIL,
		[RLM_MODULE_DISALLOW] = FR_TACACS_CODE_AUTH_FAIL,
	};

	rlm_rcode_t			rcode = *p_result;
	fr_process_state_t const	*state;
	fr_pair_t			*vp;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	If nothing set the reply code, then try to set it from various other things.
	 *
	 *	The user could have set Authentication-Status
	 *	or Packet-Type to something other than
	 *	pass...
	 */
	if (!request->reply->code) {
		request->reply->code = reply_code(request,
						  attr_tacacs_authentication_status,
						  authen_status_to_packet_code, NULL, auth_type_rcode, rcode);
	} else {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->reply->code));
	}

	switch (request->reply->code) {
	case 0:
		RDEBUG("No reply code was set.  Forcing to Authentication-Fail");
	fail:
		request->reply->code = FR_TACACS_CODE_AUTH_FAIL;
		FALL_THROUGH;

	/*
	 *	Print complaints before running "send Access-Reject"
	 */
	case FR_TACACS_CODE_AUTH_FAIL:
		RDEBUG2("Failed to authenticate the user");
		break;

	case FR_TACACS_CODE_AUTH_GETDATA:
	case FR_TACACS_CODE_AUTH_GETUSER:
	case FR_TACACS_CODE_AUTH_GETPASS:
		vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_authentication_type);
		if (vp && (vp->vp_uint32 != FR_AUTHENTICATION_TYPE_VALUE_ASCII)) {
			RDEBUG2("Cannot send challenges for %pP", vp);
			goto fail;
		}
		break;

	default:
		break;

	}
	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request);
}

RESUME_NO_RCTX(auth_pass)
{
	fr_pair_t			*vp;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	PROCESS_TRACE;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_module_success_message);
	if (vp) {
		auth_message(&inst->auth, request, true, "Login OK (%pV)", &vp->data);
	} else {
		auth_message(&inst->auth, request, true, "Login OK");
	}

	// @todo - worry about user identity existing?

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME_NO_RCTX(auth_fail)
{
	fr_pair_t			*vp;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	PROCESS_TRACE;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_module_failure_message);
	if (vp) {
		auth_message(&inst->auth, request, false, "Login incorrect (%pV)", &vp->data);
	} else {
		auth_message(&inst->auth, request, false, "Login incorrect");
	}

	// @todo - insert server message saying "failed"
	// and also for FAIL

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME_NO_RCTX(auth_restart)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	PROCESS_TRACE;

	fr_state_discard(inst->auth.state_tree, request);
	RETURN_MODULE_OK;
}

RESUME(auth_get)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);
	process_tacacs_session_t	*session;

	PROCESS_TRACE;

	/*
	 *	Track multi-round authentication flows.  Note that they can only start with an
	 *	"Authentication-Start" packet, but they can continue with an "Authentication-Continue" packet.
	 *
	 *	If there's no session being tracked, then we create one for a start packet.
	 */
	session = request_data_reference(request, inst, 0);
	if (!session) {
		fr_tacacs_packet_t const *packet = (fr_tacacs_packet_t const *) request->packet->data;
		fr_pair_t *vp, *copy;

		if (!packet_is_authen_start_request(packet)) goto send_reply;

		MEM(session = talloc_zero(NULL, process_tacacs_session_t));
		if (request_data_talloc_add(request, inst, 0, process_tacacs_session_t, session, true, true, true) < 0) {
			talloc_free(session);
			goto send_reply;
		}

		/*
		 *	These are the only things which saved.  The rest of the fields are either static (and statically
		 *	known), or are irrelevant.
		 */
		fr_pair_list_init(&session->list);
#undef COPY
#define COPY(_attr) do { \
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, _attr); \
	if (!vp) break; \
	MEM(copy = fr_pair_copy(session, vp));	\
	fr_pair_append(&session->list, copy); \
} while (0)

		COPY(attr_user_name);
		COPY(attr_tacacs_client_port);
		COPY(attr_tacacs_remote_address);
		COPY(attr_tacacs_privilege_level);

	} else {
		session->rounds++;

		if (session->rounds > inst->auth.max_rounds) {
			REDEBUG("Too many rounds of authentication - failing the session");
			return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_FAIL);
		}

		/*
		 *	There's no need to cache the User-Password, as the "getpass" packet is the last one in
		 *	the chain.  The client will send a "continue" packet containing the password, and the
		 *	admin will reply to that with pass/fail.
		 */
	}
	session->reply = request->reply->code;
	session->seq_no = request->packet->data[2];

send_reply:
	/*
	 *	Cache the session state context.
	 */
	if ((state_create(request->reply_ctx, &request->reply_pairs, request, true) < 0) ||
	    (fr_request_to_state(inst->auth.state_tree, request) < 0)) {
		return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
	}

	RETURN_MODULE_OK;
}

RECV(auth_cont)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);
	process_tacacs_session_t	*session;

	if ((state_create(request->request_ctx, &request->request_pairs, request, false) < 0) ||
	    (fr_state_to_request(inst->auth.state_tree, request) < 0)) {
		return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
	}

	/*
	 *	Restore key fields from the original Authentication-Start packet.
	 */
	session = request_data_reference(request, inst, 0);
	if (session) {
		if (request->packet->data[2] <= session->seq_no) {
			REDEBUG("Client sent invalid sequence number %02x, expected >%02x", request->packet->data[2], session->seq_no);
		error:
			return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
		}

		if (fr_pair_list_copy(request->request_ctx, &request->request_pairs, &session->list) < 0) goto error;
	}

	return CALL_RECV(generic);
}

/*
 *	The client aborted the session.  The reply should be RESTART or FAIL.
 */
RECV(auth_cont_abort)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	if ((state_create(request->request_ctx, &request->request_pairs, request, false) < 0) ||
	    (fr_state_to_request(inst->auth.state_tree, request) < 0)) {
		return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
	}

	return CALL_RECV(generic);
}

RESUME(auth_cont_abort)
{
	fr_process_state_t const	*state;

	if (!request->reply->code) request->reply->code = FR_TACACS_CODE_AUTH_RESTART;

	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return CALL_SEND_STATE(state);
}


static const uint32_t author_status_to_packet_code[UINT8_MAX + 1] = {
	[FR_TAC_PLUS_AUTHOR_STATUS_PASS_ADD] = FR_TACACS_CODE_AUTZ_PASS_ADD,
	[FR_TAC_PLUS_AUTHOR_STATUS_PASS_REPL] = FR_TACACS_CODE_AUTZ_PASS_REPLACE,
	[FR_TAC_PLUS_AUTHOR_STATUS_FAIL] = FR_TACACS_CODE_AUTZ_FAIL,
	[FR_TAC_PLUS_AUTHOR_STATUS_ERROR] = FR_TACACS_CODE_AUTZ_ERROR,
};


RESUME(autz_request)
{
	rlm_rcode_t			rcode = *p_result;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	/*
	 *	See if the return code from "recv" which says we reject, or continue.
	 */
	UPDATE_STATE(packet);

	/*
	 *	Nothing set the reply, so let's see if we need to do so.
	 *
	 *	If the admin didn't set authorization-status, just
	 *	use the defaults from the state machine.
	 */
	if (!request->reply->code) {
		request->reply->code = reply_code(request, attr_tacacs_authorization_status,
						  author_status_to_packet_code, state, NULL, rcode);
		if (!request->reply->code) request->reply->code = FR_TACACS_CODE_AUTZ_ERROR;

	} else {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->reply->code));
	}

	RDEBUG("Reply packet type set to %s", fr_tacacs_packet_names[request->reply->code]);

	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return CALL_SEND_STATE(state);
}

static const uint32_t acct_status_to_packet_code[UINT8_MAX + 1] = {
	[FR_TAC_PLUS_ACCT_STATUS_SUCCESS] = FR_TACACS_CODE_ACCT_SUCCESS,
	[FR_TAC_PLUS_ACCT_STATUS_ERROR] = FR_TACACS_CODE_ACCT_ERROR,
};

RESUME(acct_type)
{
	static const fr_process_rcode_t acct_type_rcode = {
		[RLM_MODULE_OK] =	FR_TACACS_CODE_ACCT_SUCCESS,
		[RLM_MODULE_UPDATED] =	FR_TACACS_CODE_ACCT_SUCCESS,
		[RLM_MODULE_NOOP] =	FR_TACACS_CODE_ACCT_ERROR,
		[RLM_MODULE_FAIL] =	FR_TACACS_CODE_ACCT_ERROR,
		[RLM_MODULE_INVALID] =	FR_TACACS_CODE_ACCT_ERROR,
		[RLM_MODULE_NOTFOUND] =	FR_TACACS_CODE_ACCT_ERROR,
		[RLM_MODULE_REJECT] =	FR_TACACS_CODE_ACCT_ERROR,
		[RLM_MODULE_DISALLOW] = FR_TACACS_CODE_ACCT_ERROR,
	};

	rlm_rcode_t			rcode = *p_result;
	fr_process_state_t const	*state;

	PROCESS_TRACE;

	/*
	 *	One more chance to override
	 */
	if (!request->reply->code) {
		request->reply->code = reply_code(request, attr_tacacs_accounting_status, acct_status_to_packet_code,
						  NULL, acct_type_rcode, rcode);
		if (!request->reply->code) request->reply->code = FR_TACACS_CODE_ACCT_ERROR;
	} else {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->reply->code));
	}

	UPDATE_STATE(reply);

	fr_assert(state->send != NULL);
	return state->send(p_result, mctx, request);
}

static const bool acct_flag_valid[8] = {
	false, true, true, false, /* invalid, start, stop, invalid */
	true, true, false, false, /* watchdog - no update, watchdog - update, invalid, invalid */
};

RECV(accounting_request)
{
	fr_pair_t *vp;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_accounting_flags);

	/*
	 *	RFC 8907 Section 7.2
	 */
	if (vp && !acct_flag_valid[(vp->vp_uint8 & 0x0e) >> 1]) {
		RWDEBUG("Invalid accounting request flag field %02x", vp->vp_uint8);
		return CALL_SEND_TYPE(FR_TACACS_CODE_ACCT_ERROR);
	}

	return CALL_RECV(generic);
}

RESUME(accounting_request)
{
	rlm_rcode_t			rcode = *p_result;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const		*dv;
	fr_process_state_t const	*state;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);

	PROCESS_TRACE;

	fr_assert(rcode < RLM_MODULE_NUMCODES);

	UPDATE_STATE(packet);

	/*
	 *	Nothing set the reply, so let's see if we need to do so.
	 *
	 *	If the admin didn't set accounting-status, just
	 *	use the defaults from the state machine.
	 */
	if (!request->reply->code) {
		request->reply->code = reply_code(request, attr_tacacs_accounting_status,
						  acct_status_to_packet_code, state, NULL, rcode);
	} else {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->reply->code));
	}

	/*
	 *	Something set the reply code, so we reply and don't run "accounting foo { ... }"
	 */
	if (request->reply->code) {
		fr_assert(FR_TACACS_PACKET_CODE_VALID(request->packet->code));

		RDEBUG("Reply packet type was set to %s", fr_tacacs_packet_names[request->reply->code]);

		UPDATE_STATE(reply);

		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	/*
	 *	Run accounting foo { ... }
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_accounting_flags);
	if (!vp) {
	fail:
		request->reply->code = FR_TACACS_CODE_ACCT_ERROR;
		UPDATE_STATE(reply);
		fr_assert(state->send != NULL);
		return CALL_SEND_STATE(state);
	}

	dv = fr_dict_enum_by_value(vp->da, &vp->data);
	if (!dv) goto fail;

	cs = cf_section_find(inst->server_cs, "accounting", dv->name);
	if (!cs) {
		RDEBUG2("No 'accounting %s { ... }' section found - skipping...", dv->name);
		goto fail;
	}

	/*
	 *	Run the "accounting foo { ... }" section.
	 *
	 *	And continue with sending the generic reply.
	 */
	return unlang_module_yield_to_section(p_result, request,
					      cs, RLM_MODULE_NOOP, resume_acct_type,
					      NULL, 0, mctx->rctx);
}

static unlang_action_t mod_process(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->inst->data, process_tacacs_t);
	fr_assert(FR_TACACS_PACKET_CODE_VALID(request->packet->code));

	request->component = "tacacs";
	request->module = NULL;
	fr_assert(request->dict == dict_tacacs);

	UPDATE_STATE(packet);

	// @todo - debug stuff!
//	tacacs_packet_debug(request, request->packet, &request->request_pairs, true);

	return state->recv(p_result, mctx, request);
}


static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_tacacs_t	*inst = talloc_get_type_abort(mctx->inst->data, process_tacacs_t);

	inst->auth.state_tree = fr_state_tree_init(inst, attr_tacacs_state, main_config->spawn_workers, inst->auth.max_session,
						   inst->auth.session_timeout, inst->auth.state_server_id,
						   fr_hash_string(cf_section_name2(inst->server_cs)));
	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	process_tacacs_t	*inst = talloc_get_type_abort(mctx->inst->data, process_tacacs_t);

	inst->server_cs = cf_item_to_section(cf_parent(mctx->inst->conf));
	if (virtual_server_section_attribute_define(inst->server_cs, "authenticate", attr_auth_type) < 0) return -1;

	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.max_rounds, >=, 1);
	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.max_rounds, <=, 8);

	FR_INTEGER_BOUND_CHECK("session.max", inst->auth.max_session, >=, 64);
	FR_INTEGER_BOUND_CHECK("session.max", inst->auth.max_session, <=, (1 << 18));

	return 0;
}

/*
 *	rcodes not listed under a packet_type
 *	mean that the packet code will not be
 *	changed.
 */
static fr_process_state_t const process_state[] = {
	/*
	 *	Authentication
	 */
	[ FR_TACACS_CODE_AUTH_START ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_auth_start,
		.resume = resume_auth_start,
		.section_offset = offsetof(process_tacacs_sections_t, auth_start),
	},
	[ FR_TACACS_CODE_AUTH_PASS ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_pass,
		.section_offset = offsetof(process_tacacs_sections_t, auth_pass),
	},
	[ FR_TACACS_CODE_AUTH_FAIL ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_fail,
		.section_offset = offsetof(process_tacacs_sections_t, auth_fail),
	},
	[ FR_TACACS_CODE_AUTH_GETDATA ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getdata),
	},
	[ FR_TACACS_CODE_AUTH_GETPASS ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getpass),
	},
	[ FR_TACACS_CODE_AUTH_GETUSER ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getuser),
	},
	[ FR_TACACS_CODE_AUTH_RESTART ] = {
		.packet_type = {
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_restart,
		.section_offset = offsetof(process_tacacs_sections_t, auth_restart),
	},
	[ FR_TACACS_CODE_AUTH_ERROR ] = {
		.packet_type = {
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_auth_restart,
		.section_offset = offsetof(process_tacacs_sections_t, auth_error),
	},

	[ FR_TACACS_CODE_AUTH_CONT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_auth_cont,
		.resume = resume_auth_start, /* we go back to running 'authenticate', etc. */
		.section_offset = offsetof(process_tacacs_sections_t, auth_cont),
	},
	[ FR_TACACS_CODE_AUTH_CONT_ABORT ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_auth_cont_abort,
		.resume = resume_auth_cont_abort,
		.section_offset = offsetof(process_tacacs_sections_t, auth_cont_abort),
	},

	/*
	 *	Authorization
	 */
	[ FR_TACACS_CODE_AUTZ_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_TACACS_CODE_AUTZ_PASS_ADD,
			[RLM_MODULE_OK]		= FR_TACACS_CODE_AUTZ_PASS_ADD,
			[RLM_MODULE_UPDATED]	= FR_TACACS_CODE_AUTZ_PASS_ADD,
			[RLM_MODULE_HANDLED]	= FR_TACACS_CODE_AUTZ_PASS_ADD,

			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTZ_FAIL,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_generic,
		.resume = resume_autz_request,
		.section_offset = offsetof(process_tacacs_sections_t, autz_request),
	},
	[ FR_TACACS_CODE_AUTZ_PASS_ADD ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTZ_FAIL,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_pass_add),
	},
	[ FR_TACACS_CODE_AUTZ_PASS_REPLACE ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTZ_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTZ_FAIL,
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_pass_replace),
	},
	[ FR_TACACS_CODE_AUTZ_FAIL ] = {
		.packet_type = {
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_fail),
	},
	[ FR_TACACS_CODE_AUTZ_ERROR ] = {
		.packet_type = {
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_error),
	},

	/*
	 *	Accounting
	 */
	[ FR_TACACS_CODE_ACCT_REQUEST ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_ACCT_ERROR,
		},
		.rcode = RLM_MODULE_NOOP,
		.recv = recv_accounting_request,
		.resume = resume_accounting_request,
		.section_offset = offsetof(process_tacacs_sections_t, acct_request),
	},
	[ FR_TACACS_CODE_ACCT_SUCCESS ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_ACCT_ERROR
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, acct_success),
	},
	[ FR_TACACS_CODE_ACCT_ERROR ] = {
		.packet_type = {
		},
		.rcode = RLM_MODULE_NOOP,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, acct_error),
	},
};


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
		.name2 = "Authentication-Pass",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_pass),
	},
	{
		.name = "send",
		.name2 = "Authentication-Fail",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_fail),
	},
	{
		.name = "send",
		.name2 = "Authentication-GetData",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_getdata),
	},
	{
		.name = "send",
		.name2 = "Authentication-GetUser",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_getuser),
	},
	{
		.name = "send",
		.name2 = "Authentication-GetPass",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_getpass),
	},
	{
		.name = "send",
		.name2 = "Authentication-Restart",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_restart),
	},
	{
		.name = "send",
		.name2 = "Authentication-Error",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(auth_error),
	},
	{
		.name = "recv",
		.name2 = "Authentication-Continue",
		.component = MOD_AUTHENTICATE,
		.offset = PROCESS_CONF_OFFSET(auth_cont),
	},
	{
		.name = "recv",
		.name2 = "Authentication-Continue-Abort",
		.component = MOD_AUTHENTICATE,
		.offset = PROCESS_CONF_OFFSET(auth_cont_abort),
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
		.name2 = "Authorization-Pass-Add",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(autz_pass_add),
	},
	{
		.name = "send",
		.name2 = "Authorization-Pass-Replace",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(autz_pass_replace),
	},
	{
		.name = "send",
		.name2 = "Authorization-Fail",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(autz_fail),
	},
	{
		.name = "send",
		.name2 = "Authorization-Error",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(autz_error),
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
		.name2 = "Accounting-Success",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(acct_success),
	},
	{
		.name = "send",
		.name2 = "Accounting-Error",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(acct_error),
	},

	{
		.name = "accounting",
		.name2 = CF_IDENT_ANY,
		.component = MOD_ACCOUNTING,
	},

	{
		.name = "send",
		.name2 = "Do-Not-Respond",
		.component = MOD_POST_AUTH,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_tacacs;
fr_process_module_t process_tacacs = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "tacacs",
		.config		= config,
		.inst_size	= sizeof(process_tacacs_t),
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_tacacs,
};
