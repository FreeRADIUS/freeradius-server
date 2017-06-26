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
#include <freeradius-devel/dict.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/rad_assert.h>

#ifndef USEC
#define USEC (1000000)
#endif

/*
 *	Make sure user/pass are clean and then create an attribute
 *	which contains the log message.
 */
static void auth_message(char const *msg, REQUEST *request, int goodpass)
{
	int logit;
	char const *extra_msg = NULL;
	char clean_password[1024];
	char clean_username[1024];
	char buf[1024];
	char extra[1024];
	char *p;
	VALUE_PAIR *username = NULL;

	/*
	 * Get the correct username based on the configured value
	 */
	if (!log_stripped_names) {
		username = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_NAME, TAG_ANY);
	} else {
		username = request->username;
	}

	/*
	 *	Clean up the username
	 */
	if (!username) {
		strcpy(clean_username, "<no User-Name attribute>");
	} else {
		fr_snprint(clean_username, sizeof(clean_username), username->vp_strvalue, username->vp_length, '\0');
	}

	/*
	 *	Clean up the password
	 */
	if (request->root->log_auth_badpass || request->root->log_auth_goodpass) {
		if (!request->password) {
			VALUE_PAIR *auth_type;

			auth_type = fr_pair_find_by_num(request->control, 0, FR_AUTH_TYPE, TAG_ANY);
			if (auth_type) {
				snprintf(clean_password, sizeof(clean_password), "<via Auth-Type = %s>",
					 fr_dict_enum_alias_by_value(NULL, auth_type->da, &auth_type->data));
			} else {
				strcpy(clean_password, "<no User-Password attribute>");
			}
		} else if (fr_pair_find_by_num(request->packet->vps, 0, FR_CHAP_PASSWORD, TAG_ANY)) {
			strcpy(clean_password, "<CHAP-Password>");
		} else {
			fr_snprint(clean_password, sizeof(clean_password),
				  request->password->vp_strvalue, request->password->vp_length, '\0');
		}
	}

	if (goodpass) {
		logit = request->root->log_auth_goodpass;
		extra_msg = request->root->auth_goodpass_msg;
	} else {
		logit = request->root->log_auth_badpass;
		extra_msg = request->root->auth_badpass_msg;
	}

	if (extra_msg) {
		extra[0] = ' ';
		p = extra + 1;
		if (xlat_eval(p, sizeof(extra) - 1, request, extra_msg, NULL, NULL) < 0) {
			return;
		}
	} else {
		*extra = '\0';
	}

	RAUTH("%s: [%s%s%s] (%s)%s",
		       msg,
		       clean_username,
		       logit ? "/" : "",
		       logit ? clean_password : "",
		       auth_name(buf, sizeof(buf), request, 1),
		       extra);
}

static fr_io_final_t mod_process(REQUEST *request, UNUSED fr_io_action_t action)
{
	VALUE_PAIR		*vp, *auth_type;
	rlm_rcode_t		rcode;
	CONF_SECTION		*unlang;
	fr_dict_enum_t const	*dv = NULL;
	fr_dict_attr_t const 	*da = NULL;
	vp_cursor_t		cursor;

	switch (request->request_state) {
	case REQUEST_INIT:
		radlog_request(L_DBG, L_DBG_LVL_1, request, "Received %s ID %i",
			       fr_packet_codes[request->packet->code], request->packet->id);
		rdebug_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");

		request->component = "radius";

		da = fr_dict_attr_by_num(NULL, 0, FR_PACKET_TYPE);
		rad_assert(da != NULL);
		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_section_find(request->server_cs, "recv", dv->alias);
		if (!unlang) unlang = cf_section_find(request->server_cs, "recv", "*");
		if (!unlang) {
			REDEBUG("Failed to find 'recv %s' section", dv->alias);
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Do various setups.
		 */
		request->username = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_NAME, TAG_ANY);
		request->password = fr_pair_find_by_num(request->packet->vps, 0, FR_USER_PASSWORD, TAG_ANY);

		/*
		 *	Grab the VPS and data associated with the State attribute.
		 */
		fr_state_to_request(global_state, request, request->packet);

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_REJECT);

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
			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL) {
				char msg[FR_MAX_STRING_LEN + 16];

				snprintf(msg, sizeof(msg), "Invalid user (%s)",
					 vp->vp_strvalue);
				auth_message(msg, request, 0);
			} else {
				auth_message("Invalid user", request, 0);
			}

			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find Auth-Type, and complain if they have too many.
		 */
		fr_pair_cursor_init(&cursor, &request->control);
		auth_type = NULL;
		while ((vp = fr_pair_cursor_next_by_num(&cursor, 0, FR_AUTH_TYPE, TAG_ANY)) != NULL) {
			if (!auth_type) {
				auth_type = vp;
				continue;
			}

			RWDEBUG("Ignoring extra Auth-Type = %s",
				fr_dict_enum_alias_by_value(NULL, auth_type->da, &vp->data));
		}

		/*
		 *	No Auth-Type, force it to reject.
		 */
		if (!auth_type) {
			REDEBUG2("No Auth-Type available: rejecting the user.");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Handle hard-coded Accept and Reject.
		 */
		if (auth_type->vp_uint32 == FR_AUTH_TYPE_ACCEPT) {
			RDEBUG2("Auth-Type = Accept, allowing user");
			request->reply->code = FR_CODE_ACCESS_ACCEPT;
			goto setup_send;
		}

		if (auth_type->vp_uint32 == FR_AUTH_TYPE_REJECT) {
			RDEBUG2("Auth-Type = Reject, rejecting user");
			request->reply->code = FR_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find the appropriate Auth-Type by name.
		 */
		vp = auth_type;
		dv = fr_dict_enum_by_value(NULL, vp->da, &vp->data);
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
		unlang_push_section(request, unlang, RLM_MODULE_NOTFOUND);

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

			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL){
				char msg[FR_MAX_STRING_LEN+19];

				snprintf(msg, sizeof(msg), "Login incorrect (%s)",
					 vp->vp_strvalue);
				auth_message(msg, request, 0);
			} else {
				auth_message("Login incorrect", request, 0);
			}

			/*
			 *	Maybe the shared secret is wrong?
			 */
			if (request->password) {
				VERIFY_VP(request->password);

				if ((rad_debug_lvl > 1) && (request->password->da->attr == FR_USER_PASSWORD)) {
					uint8_t const *p;

					p = (uint8_t const *) request->password->vp_strvalue;
					while (*p) {
						int size;

						size = fr_utf8_char(p, -1);
						if (!size) {
							RWDEBUG("Unprintable characters in the password.  Double-check the "
								"shared secret on the server and the NAS!");
							break;
						}
						p += size;
					}
				}
			}
			goto setup_send;

		case RLM_MODULE_OK:
			request->reply->code = FR_CODE_ACCESS_ACCEPT;
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;
		}

		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 0, FR_PACKET_TYPE, TAG_ANY);
		if (vp) {
			if (vp->vp_uint32 == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_uint32;
			}
		}

		if (request->reply->code == FR_CODE_ACCESS_ACCEPT) {
			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, FR_MODULE_SUCCESS_MESSAGE, TAG_ANY)) != NULL){
				char msg[FR_MAX_STRING_LEN+12];

				snprintf(msg, sizeof(msg), "Login OK (%s)",
					 vp->vp_strvalue);
				auth_message(msg, request, 1);
			} else {
				auth_message("Login OK", request, 1);
			}
		}

	setup_send:
		if (!da) da = fr_dict_attr_by_num(NULL, 0, FR_PACKET_TYPE);
		rad_assert(da != NULL);

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) {
			unlang = cf_section_find(request->server_cs, "send", dv->alias);
		}
		if (!unlang) unlang = cf_section_find(request->server_cs, "send", "*");

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_IO_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_IO_YIELD;

		rad_assert(request->log.unlang_indent == 0);

		switch (rcode) {
			/*
			 *	We need to send CoA-NAK back if Service-Type
			 *	is Authorize-Only.  Rely on the user's policy
			 *	to do that.  We're not a real NAS, so this
			 *	restriction doesn't (ahem) apply to us.
			 */
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
				if (!da) da = fr_dict_attr_by_num(NULL, 0, FR_PACKET_TYPE);
				rad_assert(da != NULL);

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Access-Reject'.", dv->alias);

				request->reply->code = FR_CODE_ACCESS_REJECT;

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
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
		 *	Save session-state list for Access-Challenge,
		 *	discard it for everything else.
		 */
		if (request->reply->code == FR_CODE_ACCESS_CHALLENGE) {
			fr_request_to_state(global_state, request, request->packet, request->reply);

		} else {
			fr_state_discard(global_state, request, request->packet);
		}

		if (!request->reply->code) {
			vp = fr_pair_find_by_num(request->control, 0, FR_AUTH_TYPE, TAG_ANY);
			if (vp) {
				if (vp->vp_uint32 == FR_AUTH_TYPE_ACCEPT) {
					request->reply->code = FR_CODE_ACCESS_ACCEPT;

				} else if (vp->vp_uint32 == FR_AUTH_TYPE_REJECT) {
					request->reply->code = FR_CODE_ACCESS_REJECT;
				}
			}
		}

		/*
		 *	Check for "do not respond".
		 *
		 *	@todo - create fake reply
		 */
		if (!request->reply->code) {
			RDEBUG("Not sending reply to client.");
			return FR_IO_REPLY;
		}

		/*
		 *	This is an internally generated request.
		 *	Don't print IP addresses.
		 */
		if (request->packet->data_len == 0) {
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Sent %s ID %i",
				       fr_packet_codes[request->reply->code], request->reply->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			return FR_IO_REPLY;
		}

#ifdef WITH_UDPFROMTO
		/*
		 *	Overwrite the src ip address on the outbound packet
		 *	with the one specified by the client.
		 *	This is useful to work around broken DSR implementations
		 *	and other routing issues.
		 */
		if (request->client->src_ipaddr.af != AF_UNSPEC) {
			request->reply->src_ipaddr = request->client->src_ipaddr;
		}
#endif

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);
		break;

	default:
		return FR_IO_FAIL;
	}

	return FR_IO_REPLY;
}


/*
 *	Ensure that the "recv Access-Request" etc. sections are compiled.
 */
static int auth_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;
	CONF_SECTION *subcs = NULL;

	rcode = unlang_compile_subsection(server_cs, "recv", "Access-Request", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'recv Access-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "send", "Access-Accept", MOD_POST_AUTH);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'send Access-Accept { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = unlang_compile_subsection(server_cs, "send", "Access-Reject", MOD_POST_AUTH);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err(server_cs, "Failed finding 'send Access-Reject { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	/*
	 *	It's OK to not have an Access-Challenge section.
	 */
	rcode = unlang_compile_subsection(server_cs, "send", "Access-Challenge", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	while ((subcs = cf_section_find_next(server_cs, subcs, "authenticate", NULL))) {
		char const *name2;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err(subcs, "A second name is required for the 'authenticate { ... }' section");
			return -1;
		}

		cf_log_debug(subcs, "Loading authenticate %s {...}", name2);

		if (unlang_compile(subcs, MOD_AUTHENTICATE) < 0) {
			cf_log_err(subcs, "Failed compiling 'authenticate %s { ... }' section", name2);
			return -1;
		}
	}

	return 0;
}

static int mod_bootstrap(UNUSED void *instance, CONF_SECTION *listen_cs)
{
	CONF_SECTION		*server_cs;
	fr_dict_attr_t const	*da;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	da = fr_dict_attr_by_num(NULL, 0, FR_AUTH_TYPE);
	if (!da) {
		cf_log_err(server_cs, "Failed finding dictionary definition for Auth-Type");
		return -1;
	}

	if (virtual_server_section_attribute_define(server_cs, "authenticate", da) < 0) return -1;

	return 0;
}

static int mod_instantiate(UNUSED void *instance, CONF_SECTION *listen_cs)
{
	CONF_SECTION		*subcs = NULL;;
	CONF_SECTION		*server_cs;

	rad_assert(listen_cs);

	server_cs = cf_item_to_section(cf_parent(listen_cs));
	rad_assert(strcmp(cf_section_name1(server_cs), "server") == 0);

	if (auth_listen_compile(server_cs, listen_cs) < 0) return -1;

	while ((subcs = cf_section_find_next(server_cs, subcs, "authenticate", CF_IDENT_ANY))) {
		int rcode;
		char const	*name2;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err(subcs, "Invalid 'authenticate { ... }' section, it must have a name");
			return -1;
		}

		rcode = unlang_compile_subsection(server_cs, "authenticate", name2, MOD_AUTHENTICATE);
		if (rcode < 0) {
			cf_log_err(subcs, "Failed compiling 'authenticate %s { ... }' section", name2);
			return -1;
		}
	}

	return 0;
}

extern fr_app_process_t proto_radius_auth;
fr_app_process_t proto_radius_auth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_auth",
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.process	= mod_process,
};
