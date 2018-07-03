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
 * @file proto_radius_auth.c
 * @brief RADIUS Access-Request processing.
 *
 * @copyright 2016 The FreeRADIUS server project.
 * @copyright 2016 Alan DeKok (aland@deployingradius.com)
 */
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/unlang.h>
#include <freeradius-devel/dict.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

#ifndef USEC
#define USEC (1000000)
#endif

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
} proto_radius_auth_t;

static const CONF_PARSER session_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_UINT32, proto_radius_auth_t, session_timeout), .dflt = "15" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, proto_radius_auth_t, max_session), .dflt = "4096" },
	{ FR_CONF_OFFSET("state_server_id", FR_TYPE_UINT8, proto_radius_auth_t, state_server_id) },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER log_config[] = {
	{ FR_CONF_OFFSET("stripped_names", FR_TYPE_BOOL, proto_radius_auth_t, log_stripped_names), .dflt = "no" },
	{ FR_CONF_OFFSET("auth", FR_TYPE_BOOL, proto_radius_auth_t, log_auth), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_badpass", FR_TYPE_BOOL, proto_radius_auth_t, log_auth_badpass), .dflt = "no" },
	{ FR_CONF_OFFSET("auth_goodpass", FR_TYPE_BOOL,proto_radius_auth_t,  log_auth_goodpass), .dflt = "no" },
	{ FR_CONF_OFFSET("msg_badpass", FR_TYPE_STRING, proto_radius_auth_t, auth_badpass_msg) },
	{ FR_CONF_OFFSET("msg_goodpass", FR_TYPE_STRING, proto_radius_auth_t, auth_goodpass_msg) },
	{ FR_CONF_OFFSET("msg_denied", FR_TYPE_STRING, proto_radius_auth_t, denied_msg), .dflt = "You are already logged in - access denied" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER proto_radius_auth_config[] = {
	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_config },

	{ FR_CONF_POINTER("session", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) session_config },

	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_radius;

extern fr_dict_autoload_t proto_radius_auth_dict[];
fr_dict_autoload_t proto_radius_auth_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_calling_station_id;
static fr_dict_attr_t const *attr_auth_type;
static fr_dict_attr_t const *attr_module_failure_message;
static fr_dict_attr_t const *attr_module_success_message;
static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_chap_password;
static fr_dict_attr_t const *attr_service_type;
static fr_dict_attr_t const *attr_state;
static fr_dict_attr_t const *attr_user_name;
static fr_dict_attr_t const *attr_user_password;
static fr_dict_attr_t const *attr_nas_port;

extern fr_dict_attr_autoload_t proto_radius_auth_dict_attr[];
fr_dict_attr_autoload_t proto_radius_auth_dict_attr[] = {
	{ .out = &attr_auth_type, .name = "Auth-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_module_failure_message, .name = "Module-Failure-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_module_success_message, .name = "Module-Success-Message", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_packet_type, .name = "Packet-Type", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },

	{ .out = &attr_calling_station_id, .name = "Calling-Station-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_chap_password, .name = "CHAP-Password", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_service_type, .name = "Service-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_state, .name = "State", .type = FR_TYPE_OCTETS, .dict = &dict_radius },
	{ .out = &attr_user_name, .name = "User-Name", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_user_password, .name = "User-Password", .type = FR_TYPE_STRING, .dict = &dict_radius },
	{ .out = &attr_nas_port, .name = "NAS-Port", .type = FR_TYPE_UINT32, .dict = &dict_radius },

	{ NULL }
};

/*
 *	Return a short string showing the terminal server, port
 *	and calling station ID.
 */
static char *auth_name(char *buf, size_t buflen, REQUEST *request, bool do_cli)
{
	VALUE_PAIR	*cli;
	VALUE_PAIR	*pair;
	uint32_t	port = 0;	/* RFC 2865 NAS-Port is 4 bytes */
	char const	*tls = "";

	cli = fr_pair_find_by_da(request->packet->vps, attr_calling_station_id, TAG_ANY);
	if (!cli) do_cli = false;

	pair = fr_pair_find_by_da(request->packet->vps, attr_nas_port, TAG_ANY);
	if (pair != NULL) port = pair->vp_uint32;

	if (request->packet->dst_port == 0) tls = " via proxy to virtual server";

	snprintf(buf, buflen, "from client %.128s port %u%s%.128s%s",
		 request->client->shortname, port,
		 (do_cli ? " cli " : ""), (do_cli ? cli->vp_strvalue : ""),
		 tls);

	return buf;
}

/*
 *	Make sure user/pass are clean and then create an attribute
 *	which contains the log message.
 */
static void CC_HINT(format (printf, 4, 5)) auth_message(proto_radius_auth_t const *inst,
							REQUEST *request, bool goodpass, char const *fmt, ...)
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
	VALUE_PAIR	*username = NULL;

	/*
	 * Get the correct username based on the configured value
	 */
	if (!inst->log_stripped_names) {
		username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
	} else {
		username = request->username;
	}

	/*
	 *	Clean up the password
	 */
	if (inst->log_auth_badpass || inst->log_auth_goodpass) {
		if (!request->password) {
			VALUE_PAIR *auth_type;

			auth_type = fr_pair_find_by_da(request->control, attr_auth_type, TAG_ANY);
			if (auth_type) {
				snprintf(password_buff, sizeof(password_buff), "<via Auth-Type = %s>",
					 fr_dict_enum_alias_by_value(auth_type->da, &auth_type->data));
				password_str = password_buff;
			} else {
				password_str = "<no User-Password attribute>";
			}
		} else if (fr_pair_find_by_da(request->packet->vps, attr_chap_password, TAG_ANY)) {
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
	      logit ? (password_str ? fr_box_strvalue(password_str) : &request->password->data) : fr_box_strvalue(""),
	      auth_name(buf, sizeof(buf), request, 1),
	      extra);

	talloc_free(msg);
}

static fr_io_final_t mod_process(void const *instance, REQUEST *request, fr_io_action_t action)
{
	proto_radius_auth_t const	*inst = instance;
	VALUE_PAIR			*vp, *auth_type;
	rlm_rcode_t			rcode;
	CONF_SECTION			*unlang;
	fr_dict_enum_t const		*dv = NULL;
	fr_cursor_t			cursor;

	REQUEST_VERIFY(request);

	/*
	 *	Pass this through asynchronously to the module which
	 *	is waiting for something to happen.
	 */
	if (action != FR_IO_ACTION_RUN) {
		unlang_signal(request, (fr_state_signal_t) action);
		return FR_IO_DONE;
	}

	switch (request->request_state) {
	case REQUEST_INIT:
		RDEBUG("Received %s ID %i", fr_packet_codes[request->packet->code], request->packet->id);
		log_request_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		unlang = cf_section_find(request->server_cs, "recv", "Access-Request");
		if (!unlang) {
			REDEBUG("Failed to find 'recv Access-Request' section");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Do various setups.
		 */
		request->username = fr_pair_find_by_da(request->packet->vps, attr_user_name, TAG_ANY);
		request->password = fr_pair_find_by_da(request->packet->vps, attr_user_password, TAG_ANY);

		/*
		 *	Grab the VPS and data associated with the State attribute.
		 */
		if (!request->parent) fr_state_to_request(inst->state_tree, request);

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv Access-Request' from file %s", cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_REJECT, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

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
		case RLM_MODULE_USERLOCK:
		default:
			if ((vp = fr_pair_find_by_da(request->packet->vps,
						     attr_module_failure_message, TAG_ANY)) != NULL) {
				auth_message(inst, request, false, "Invalid user (%pV)", &vp->data);
			} else {
				auth_message(inst, request, false, "Invalid user");
			}

			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find Auth-Type, and complain if they have too many.
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
			/*
			 *	Handle Service-Type = Authorize-Only
			 *
			 *	If they want to reject the request,
			 *	the "recv Access-Request" section
			 *	should have returned reject.
			 */
			vp = fr_pair_find_by_da(request->packet->vps, attr_service_type, TAG_ANY);
			if (vp && (vp->vp_uint32 == FR_SERVICE_TYPE_VALUE_AUTHORIZE_ONLY)) {
				RDEBUG("Skipping authenticate as we have found %pP", vp);
				request->reply->code = FR_CODE_ACCESS_ACCEPT;
				goto setup_send;
			}

			/*
			 *	Allow for over-ride of reply code.
			 */
			vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
			if (vp) {
				request->reply->code = vp->vp_uint32;
				goto setup_send;
			}

			REDEBUG2("No Auth-Type available: rejecting the user.");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Handle hard-coded Accept and Reject.
		 */
		if (auth_type->vp_uint32 == FR_AUTH_TYPE_ACCEPT) {
			RDEBUG2("%pP, allowing user", auth_type);
			request->reply->code = FR_CODE_ACCESS_ACCEPT;
			goto setup_send;
		}

		if (auth_type->vp_uint32 == FR_AUTH_TYPE_REJECT) {
			RDEBUG2("%pP, rejecting user", auth_type);
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find the appropriate Auth-Type by name.
		 */
		vp = auth_type;
		dv = fr_dict_enum_by_value(vp->da, &vp->data);
		if (!dv) {
			REDEBUG2("Unknown Auth-Type %d found: rejecting the user", vp->vp_uint32);
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_section_find(request->server_cs, "authenticate", dv->alias);
		if (!unlang) {
			REDEBUG2("No 'authenticate %s' section found: rejecting the user", dv->alias);
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		RDEBUG("Running 'authenticate %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOTFOUND, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_PROCESS;
		/* FALL-THROUGH */

	case REQUEST_PROCESS:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

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
		case RLM_MODULE_USERLOCK:
		default:
			RDEBUG2("Failed to authenticate the user");
			request->reply->code = FR_CODE_ACCESS_REJECT;

			vp = fr_pair_find_by_da(request->packet->vps, attr_module_failure_message, TAG_ANY);
			if (vp) {
				auth_message(inst, request, false, "Login incorrect (%pV)", &vp->data);
			} else {
				auth_message(inst, request, false, "Login incorrect");
			}

			/*
			 *	Maybe the shared secret is wrong?
			 */
			if (request->password) {
				VP_VERIFY(request->password);

				if ((rad_debug_lvl > 1) && (request->password->da == attr_user_password)) {
					uint8_t const *p;

					p = (uint8_t const *) request->password->vp_strvalue;
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
			goto setup_send;

		case RLM_MODULE_OK:
			if (!request->reply->code) request->reply->code = FR_CODE_ACCESS_ACCEPT;
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
		if (vp) request->reply->code = vp->vp_uint32;

		if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
			vp = fr_pair_find_by_da(request->packet->vps, attr_module_success_message, TAG_ANY);
			if (vp){
				auth_message(inst, request, true, "Login OK (%pV)", &vp->data);
			} else {
				auth_message(inst, request, true, "Login OK");
			}
		}

	setup_send:
		if (!request->reply->code) {
			vp = fr_pair_find_by_da(request->reply->vps, attr_packet_type, TAG_ANY);
			if (vp) {
				request->reply->code = vp->vp_uint32;
			} else {
				RDEBUG("No reply code was set.  Forcing to Access-Reject");
				request->reply->code = FR_CODE_ACCESS_REJECT;
			}
		}

		dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) unlang = cf_section_find(request->server_cs, "send", dv->alias);

		if (!unlang) goto send_reply;

	rerun_nak:
		/*
		 *	Access-Challenge packets require a State.  If
		 *	there is none, create one here.  This is so
		 *	that the State attribute is accessible in the
		 *	"send Access-Challenge" section.
		 */
		if ((request->reply->code == FR_CODE_ACCESS_CHALLENGE) &&
		    !(vp = fr_pair_find_by_da(request->reply->vps, attr_state, TAG_ANY))) {
			uint8_t buffer[16];

			fr_rand_buffer(buffer, sizeof(buffer));

			MEM(pair_update_reply(&vp, attr_state) >= 0);
			fr_pair_value_memcpy(vp, buffer, sizeof(buffer));
		}

		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP, UNLANG_TOP_FRAME);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			/*
			 *	If we over-ride an ACK with a NAK, run
			 *	the NAK section.
			 */
			if (request->reply->code != FR_CODE_ACCESS_REJECT) {
				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Access-Reject'", dv->alias);

				request->reply->code = FR_CODE_ACCESS_REJECT;

				dv = fr_dict_enum_by_value(attr_packet_type, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_find(request->server_cs, "send", dv->alias);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->alias);
			}

			/*
			 *	Else it was already an Access-Reject.
			 */
			break;

		case RLM_MODULE_HANDLED:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/* reply code is already set */
			break;
		}

	send_reply:
		gettimeofday(&request->reply->timestamp, NULL);

		/*
		 *	Save session-state list for Access-Challenge from a NAS.
		 *	discard it for everything else.
		 */
		if (!request->parent) {
			if (request->reply->code == FR_CODE_ACCESS_CHALLENGE) {
				/*
				 *	We can't create a valid response
				 */
				if (fr_request_to_state(inst->state_tree, request) < 0) {
					request->reply->code = FR_CODE_DO_NOT_RESPOND;
					return FR_IO_REPLY;
				}
			} else {
				fr_state_discard(inst->state_tree, request);
			}
		}

		/*
		 *	Check for "do not respond".
		 */
		if (request->reply->code == FR_CODE_DO_NOT_RESPOND) {
			RDEBUG("Not sending reply to client.");
			return FR_IO_REPLY;
		}

		/*
		 *	This is an internally generated request.
		 *	Don't print IP addresses.
		 */
		if (request->parent) {
			RDEBUG("Sent %s ID %i", fr_packet_codes[request->reply->code], request->reply->id);
			log_request_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			return FR_IO_REPLY;
		}

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}

static int mod_instantiate(void *instance, CONF_SECTION *process_app_cs)
{
	proto_radius_auth_t	*inst = instance;
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(process_app_cs));
	CONF_SECTION		*server_cs;
	CONF_SECTION		*subcs = NULL;
	vp_tmpl_rules_t		parse_rules;

	memset(&parse_rules, 0, sizeof(parse_rules));
	parse_rules.dict_def = dict_radius;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	while ((subcs = cf_section_find_next(server_cs, subcs, "authenticate", CF_IDENT_ANY))) {
		int rcode;
		char const	*name2;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err(subcs, "Invalid 'authenticate { ... }' section, it must have a name");
			return -1;
		}

		rcode = unlang_compile_subsection(server_cs, "authenticate", name2, MOD_AUTHENTICATE, &parse_rules);
		if (rcode < 0) {
			cf_log_err(subcs, "Failed compiling 'authenticate %s { ... }' section", name2);
			return -1;
		}
	}

	inst->state_tree = fr_state_tree_init(inst, attr_state, main_config->spawn_workers, inst->max_session,
					      inst->session_timeout, inst->state_server_id);

	return 0;
}

static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *process_app_cs)
{
	CONF_SECTION		*listen_cs = cf_item_to_section(cf_parent(process_app_cs));
	CONF_SECTION		*server_cs;

	rad_assert(process_app_cs);
	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	if (virtual_server_section_attribute_define(server_cs, "authenticate", attr_auth_type) < 0) return -1;

	return 0;
}

extern fr_app_worker_t proto_radius_auth;
fr_app_worker_t proto_radius_auth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_auth",
	.config		= proto_radius_auth_config,
	.inst_size	= sizeof(proto_radius_auth_t),

	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.entry_point	= mod_process,
};
