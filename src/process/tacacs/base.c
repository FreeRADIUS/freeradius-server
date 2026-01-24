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
#include <freeradius-devel/server/rcode.h>
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
	DICT_AUTOLOAD_TERMINATOR
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
static fr_dict_attr_t const *attr_tacacs_user_message;

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
	{ .out = &attr_tacacs_user_message, .name = "User-Message", .type = FR_TYPE_STRING, .dict = &dict_tacacs },

	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_tacacs },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_tacacs },

	DICT_AUTOLOAD_TERMINATOR
};

static fr_value_box_t const	*enum_auth_type_accept;
static fr_value_box_t const	*enum_auth_type_reject;
static fr_value_box_t const	*enum_auth_flags_noecho;
static fr_value_box_t const	*enum_tacacs_auth_type_ascii;

extern fr_dict_enum_autoload_t process_tacacs_dict_enum[];
fr_dict_enum_autoload_t process_tacacs_dict_enum[] = {
	{ .out = &enum_auth_type_accept, .name = "Accept", .attr = &attr_auth_type },
	{ .out = &enum_auth_type_reject, .name = "Reject", .attr = &attr_auth_type },
	{ .out = &enum_auth_flags_noecho, .name = "No-Echo", .attr = &attr_tacacs_authentication_flags },
	{ .out = &enum_tacacs_auth_type_ascii, .name = "ASCII", .attr = &attr_tacacs_authentication_type },
	DICT_AUTOLOAD_TERMINATOR
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

	CONF_SECTION	*new_client;
	CONF_SECTION	*add_client;
	CONF_SECTION	*deny_client;
} process_tacacs_sections_t;

typedef struct {
	fr_state_config_t      	session;	//!< track state session information.
	fr_state_tree_t		*state_tree;	//!< State tree to link multiple requests/responses.
} process_tacacs_auth_t;

typedef struct {
	CONF_SECTION			*server_cs;	//!< Our virtual server.

	uint32_t			session_id;	//!< current session ID

	process_tacacs_sections_t	sections;	//!< Pointers to various config sections
							///< we need to execute

	process_tacacs_auth_t		auth;		//!< Authentication configuration.


} process_tacacs_t;

typedef struct {
	uint32_t	reply;			//!< for multiround state machine
	uint8_t		seq_no;			//!< sequence number of last request.
	fr_pair_list_t	list;			//!< copied from the request
} process_tacacs_session_t;


#define PROCESS_PACKET_TYPE		fr_tacacs_packet_code_t
#define PROCESS_CODE_MAX		FR_TACACS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_TACACS_CODE_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_TACACS_PACKET_CODE_VALID
#define PROCESS_INST			process_tacacs_t
#define PROCESS_CODE_DYNAMIC_CLIENT	FR_TACACS_CODE_AUTH_PASS

#include <freeradius-devel/server/process.h>

static const conf_parser_t auth_config[] = {
	{ FR_CONF_POINTER("session", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) state_session_config },

	CONF_PARSER_TERMINATOR
};

static const conf_parser_t config[] = {
	{ FR_CONF_POINTER("Authentication", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = (void const *) auth_config,
	  .offset = offsetof(process_tacacs_t, auth), },

	CONF_PARSER_TERMINATOR
};


/*
 *	Synthesize a State attribute from connection && session information.
 */
static int state_create(TALLOC_CTX *ctx, fr_pair_list_t *out, request_t *request, bool reply)
{
	uint64_t	hash;
	uint32_t	sequence;
	fr_pair_t 	*vp;

	if (!request->async->listen) return -1;

	vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_tacacs_session_id);
	if (!vp) return -1;

	hash = fr_hash64(&vp->vp_uint32, sizeof(vp->vp_uint32));

	vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_tacacs_sequence_number);
	if (!vp) return -1;

	/*
	 *	Requests have odd sequence numbers, and replies have even sequence numbers.
	 *	So if we want to synthesize a state in a reply which gets matched with the next
	 *	request, we have to add 2 to it.
	 */
	sequence = vp->vp_uint8 + ((int) reply << 1);
	hash = fr_hash64_update(&sequence, sizeof(sequence), hash);

	hash = fr_hash64_update(&request->async->listen, sizeof(request->async->listen), hash);

	vp = fr_pair_afrom_da(ctx, attr_tacacs_state);
	if (!vp) return -1;

	(void) fr_pair_value_memdup(vp, (uint8_t const *) &hash, sizeof(hash), false);

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
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

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
			vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_authentication_type);
			if (!packet_is_authen_start_request(packet) ||
			    (vp && (fr_value_box_cmp(&vp->data, enum_tacacs_auth_type_ascii) != 0))) {
				goto auth_type;
			}

			vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_user_name);
			if (!vp) {
				RDEBUG("No User-Name, replying with Authentication-GetUser");
				request->reply->code = FR_TACACS_CODE_AUTH_GETUSER;
			} else {
				RDEBUG("User-Name = %pV, replying with Authentication-GetPass", &vp->data);
				request->reply->code = FR_TACACS_CODE_AUTH_GETPASS;
				goto add_auth_flags;
			}

			goto send_reply;
		}

		/*
		 *	Last reply was "get username", we now get the password.
		 */
		if (session->reply == FR_TACACS_CODE_AUTH_GETUSER) {
			RDEBUG("No User-Password, replying with Authentication-GetPass");
			request->reply->code = FR_TACACS_CODE_AUTH_GETPASS;

			/*
			 *	Pre-set the authentication flags reply to No-Echo
			 *	RFC 8907 says this should be set when the data being
			 *	requested is sensitive and should not be echoed to the
			 *	user as it is being entered.
			 */
		add_auth_flags:
			MEM(pair_append_reply(&vp, attr_tacacs_authentication_flags) >= 0);
			if (unlikely(fr_value_box_copy(vp, &vp->data, enum_auth_flags_noecho) < 0)) {
				RPEDEBUG("Failed creating Authentication-Flags attribute with No-Echo flag");
				pair_delete_reply(vp);
				goto reject;
			}
			vp->data.enumv = attr_tacacs_authentication_flags;
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
	return unlang_module_yield_to_section(RESULT_P, request,
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
		[RLM_MODULE_UPDATED] =	FR_TACACS_CODE_AUTH_PASS,
		[RLM_MODULE_DISALLOW] = FR_TACACS_CODE_AUTH_FAIL,
	};

	rlm_rcode_t			rcode = RESULT_RCODE;
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

RESUME_FLAG(auth_pass, UNUSED,)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

	PROCESS_TRACE;

	// @todo - worry about user identity existing?

	fr_state_discard(inst->auth.state_tree, request);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME_FLAG(auth_fail, UNUSED,)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

	PROCESS_TRACE;

	// @todo - insert server message saying "failed"
	// and also for FAIL

	fr_state_discard(inst->auth.state_tree, request);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME_FLAG(auth_restart, UNUSED,)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

	PROCESS_TRACE;

	fr_state_discard(inst->auth.state_tree, request);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RESUME(auth_get)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);
	process_tacacs_session_t	*session;
	fr_pair_t			*vp, *copy;

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
	RDEBUG2("%pP", copy); \
} while (0)

		RDEBUG2("Caching session attributes:");
		RINDENT();
		COPY(attr_user_name);
		COPY(attr_tacacs_client_port);
		COPY(attr_tacacs_remote_address);
		COPY(attr_tacacs_privilege_level);
		COPY(attr_tacacs_authentication_type);
		REXDENT();

	} else {
		/*
		 *	It is possible that the user name or password are added on subsequent Authentication-Continue
		 *	packets following replies with Authentication-GetUser or Authentication-GetPass.
		 *	Check if they are already in the session cache, and if not, add them.
		 */
#define COPY_MISSING(_attr) do { \
	vp = fr_pair_find_by_da(&session->list, NULL, _attr); \
	if (vp) break; \
	COPY(_attr); \
} while (0)

		RDEBUG2("Caching additional session attributes:");
		RINDENT();
		COPY_MISSING(attr_user_name);
		COPY_MISSING(attr_user_password);
		REXDENT();
	}
	session->reply = request->reply->code;
	session->seq_no = request->packet->data[2];

send_reply:
	/*
	 *	Cache the session state context.
	 */
	if ((state_create(request->reply_ctx, &request->reply_pairs, request, true) < 0) ||
	    (fr_state_store(inst->auth.state_tree, request) < 0)) {
		return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

RECV(auth_cont)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);
	process_tacacs_session_t	*session;

	if ((state_create(request->request_ctx, &request->request_pairs, request, false) < 0) ||
	    (fr_state_restore(inst->auth.state_tree, request) < 0)) {
		return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
	}

	/*
	 *	Restore key fields from the original Authentication-Start packet.
	 */
	session = request_data_reference(request, inst, 0);
	if (session) {
		fr_pair_t *vp = NULL, *copy;

		if (request->packet->data[2] <= session->seq_no) {
			REDEBUG("Client sent invalid sequence number %02x, expected >%02x", request->packet->data[2], session->seq_no);
		error:
			return CALL_SEND_TYPE(FR_TACACS_CODE_AUTH_ERROR);
		}

		if (fr_debug_lvl >= L_DBG_LVL_2) {
			RDEBUG2("Restoring session attributes:");
			RINDENT();
			while ((vp = fr_pair_list_next(&session->list, vp))) {
				RDEBUG2("%pP", vp);
			}
			REXDENT();
		}
		if (fr_pair_list_copy(request->request_ctx, &request->request_pairs, &session->list) < 0) goto error;

		/*
		 *	Copy the returned user_message into the attribute we requested.
		 */
#define EXTRACT(_attr) \
	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_tacacs_user_message); \
	if (!vp) break; \
	fr_value_box_set_secret(&vp->data, _attr->flags.secret); \
	if (pair_append_request(&copy, _attr) < 0) break; \
	if (fr_pair_value_copy(copy, vp) < 0) { \
		fr_pair_remove(&request->request_pairs, copy); \
		talloc_free(copy); \
		break; \
	} \
	RDEBUG2("Populated %pP from user_message", copy)

		switch (session->reply) {
		case FR_TACACS_CODE_AUTH_GETUSER:
			EXTRACT(attr_user_name);
			break;

		case FR_TACACS_CODE_AUTH_GETPASS:
			EXTRACT(attr_user_password);
			break;

		default:
			break;
		}
	}

	return CALL_RECV(generic);
}

/*
 *	The client aborted the session.  The reply should be RESTART or FAIL.
 */
RECV(auth_cont_abort)
{
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

	if ((state_create(request->request_ctx, &request->request_pairs, request, false) < 0) ||
	    (fr_state_restore(inst->auth.state_tree, request) < 0)) {
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
	rlm_rcode_t			rcode = RESULT_RCODE;
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

	rlm_rcode_t			rcode = RESULT_RCODE;
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
	rlm_rcode_t			rcode = RESULT_RCODE;
	fr_pair_t			*vp;
	CONF_SECTION			*cs;
	fr_dict_enum_value_t const	*dv;
	fr_process_state_t const	*state;
	process_tacacs_t const		*inst = talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);

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
	return unlang_module_yield_to_section(RESULT_P, request,
					      cs, RLM_MODULE_NOOP, resume_acct_type,
					      NULL, 0, mctx->rctx);
}

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_tacacs_t);
	fr_assert(FR_TACACS_PACKET_CODE_VALID(request->packet->code));

	request->component = "tacacs";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_tacacs);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	// @todo - debug stuff!
//	tacacs_packet_debug(request, request->packet, &request->request_pairs, true);

	if (unlikely(request_is_dynamic_client(request))) {
		return new_client(p_result, mctx, request);
	}

	return state->recv(p_result, mctx, request);
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_tacacs_t	*inst = talloc_get_type_abort(mctx->mi->data, process_tacacs_t);

	inst->server_cs = cf_item_to_section(cf_parent(mctx->mi->conf));

	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.session.max_rounds, >=, 1);
	FR_INTEGER_BOUND_CHECK("session.max_rounds", inst->auth.session.max_rounds, <=, 8);

	FR_INTEGER_BOUND_CHECK("session.max", inst->auth.session.max_sessions, >=, 64);
	FR_INTEGER_BOUND_CHECK("session.max", inst->auth.session.max_sessions, <=, (1 << 18));

	inst->auth.session.thread_safe = main_config->spawn_workers;
	inst->auth.session.context_id = fr_hash_string(cf_section_name2(inst->server_cs));

	inst->auth.state_tree = fr_state_tree_init(inst, attr_tacacs_state, &inst->auth.session);
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
	/*
	 *	Authentication
	 */
	[ FR_TACACS_CODE_AUTH_START ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_auth_start,
		.resume = resume_auth_start,
		.section_offset = offsetof(process_tacacs_sections_t, auth_start),
	},
	[ FR_TACACS_CODE_AUTH_PASS ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_auth_pass,
		.section_offset = offsetof(process_tacacs_sections_t, auth_pass),
	},
	[ FR_TACACS_CODE_AUTH_FAIL ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
		.send = send_generic,
		.resume = resume_auth_fail,
		.section_offset = offsetof(process_tacacs_sections_t, auth_fail),
	},
	[ FR_TACACS_CODE_AUTH_GETDATA ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getdata),
	},
	[ FR_TACACS_CODE_AUTH_GETPASS ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getpass),
	},
	[ FR_TACACS_CODE_AUTH_GETUSER ] = {
		.packet_type = {
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_auth_get,
		.section_offset = offsetof(process_tacacs_sections_t, auth_getuser),
	},
	[ FR_TACACS_CODE_AUTH_RESTART ] = {
		.packet_type = {
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_auth_restart,
		.section_offset = offsetof(process_tacacs_sections_t, auth_restart),
	},
	[ FR_TACACS_CODE_AUTH_ERROR ] = {
		.packet_type = {
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
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
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
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
			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_AUTH_FAIL,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
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
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
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
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
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
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_pass_replace),
	},
	[ FR_TACACS_CODE_AUTZ_FAIL ] = {
		.packet_type = {
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, autz_fail),
	},
	[ FR_TACACS_CODE_AUTZ_ERROR ] = {
		.packet_type = {
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_REJECT,
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
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
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
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_ACCT_ERROR,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_OK,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, acct_success),
	},
	[ FR_TACACS_CODE_ACCT_ERROR ] = {
		.packet_type = {
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_FAIL,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, acct_error),
	},
	[ FR_TACACS_CODE_DO_NOT_RESPOND ] = {
		.packet_type = {
			[RLM_MODULE_NOOP]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_OK]		= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_UPDATED]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_HANDLED]	= FR_TACACS_CODE_DO_NOT_RESPOND,

			[RLM_MODULE_NOTFOUND]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_FAIL]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_INVALID]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_REJECT]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_DISALLOW]	= FR_TACACS_CODE_DO_NOT_RESPOND,
			[RLM_MODULE_TIMEOUT]	= FR_TACACS_CODE_DO_NOT_RESPOND
		},
		.default_rcode = RLM_MODULE_NOOP,
		.result_rcode = RLM_MODULE_HANDLED,
		.send = send_generic,
		.resume = resume_send_generic,
		.section_offset = offsetof(process_tacacs_sections_t, do_not_respond),
	}
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
		.section = SECTION_NAME("recv", "Authentication-Start"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(auth_start),
	},
	{
		.section = SECTION_NAME("send", "Authentication-Pass"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_pass),
	},
	{
		.section = SECTION_NAME("send", "Authentication-Fail"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_fail),
	},
	{
		.section = SECTION_NAME("send", "Authentication-GetData"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_getdata),
	},
	{
		.section = SECTION_NAME("send", "Authentication-GetUser"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_getuser),
	},
	{
		.section = SECTION_NAME("send", "Authentication-GetPass"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_getpass),
	},
	{
		.section = SECTION_NAME("send", "Authentication-Restart"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_restart),
	},
	{
		.section = SECTION_NAME("send", "Authentication-Error"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(auth_error),
	},
	{
		.section = SECTION_NAME("recv", "Authentication-Continue"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(auth_cont),
	},
	{
		.section = SECTION_NAME("recv", "Authentication-Continue-Abort"),
		.actions = &mod_actions_authenticate,
		.offset = PROCESS_CONF_OFFSET(auth_cont_abort),
	},

	{
		.section = SECTION_NAME("authenticate", CF_IDENT_ANY),
		.actions = &mod_actions_authenticate,
	},

	/* authorization */

	{
		.section = SECTION_NAME("recv", "Authorization-Request"),
		.actions = &mod_actions_authorize,
		.offset = PROCESS_CONF_OFFSET(autz_request),
	},
	{
		.section = SECTION_NAME("send", "Authorization-Pass-Add"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(autz_pass_add),
	},
	{
		.section = SECTION_NAME("send", "Authorization-Pass-Replace"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(autz_pass_replace),
	},
	{
		.section = SECTION_NAME("send", "Authorization-Fail"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(autz_fail),
	},
	{
		.section = SECTION_NAME("send", "Authorization-Error"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(autz_error),
	},

	/* accounting */

	{
		.section = SECTION_NAME("recv", "Accounting-Request"),
		.actions = &mod_actions_accounting,
		.offset = PROCESS_CONF_OFFSET(acct_request),
	},
	{
		.section = SECTION_NAME("send", "Accounting-Success"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(acct_success),
	},
	{
		.section = SECTION_NAME("send", "Accounting-Error"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(acct_error),
	},

	{
		.section = SECTION_NAME("accounting", CF_IDENT_ANY),
		.actions = &mod_actions_accounting,
	},

	{
		.section = SECTION_NAME("send", "Do-Not-Respond"),
		.actions = &mod_actions_postauth,
		.offset = PROCESS_CONF_OFFSET(do_not_respond),
	},

	DYNAMIC_CLIENT_SECTIONS,

	COMPILE_TERMINATOR
};


extern fr_process_module_t process_tacacs;
fr_process_module_t process_tacacs = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "tacacs",
		.config		= config,
		MODULE_INST(process_tacacs_t),
		MODULE_RCTX(process_rctx_t),
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate
	},
	.process	= mod_process,
	.compile_list	= compile_list,
	.dict		= &dict_tacacs,
	.packet_type	= &attr_packet_type
};
