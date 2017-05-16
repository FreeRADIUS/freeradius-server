/*
 * proto_radius_auth.c	RADIUS Access-Request processing.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2016 The FreeRADIUS server project
 * Copyright 2016 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/state.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/radius/radius.h>
#include <freeradius-devel/io/transport.h>
#include <freeradius-devel/rad_assert.h>

#define REQUEST_SIMULTANEOUS_USE (REQUEST_OTHER_1)

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
		username = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_NAME, TAG_ANY);
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

			auth_type = fr_pair_find_by_num(request->control, 0, PW_AUTH_TYPE, TAG_ANY);
			if (auth_type) {
				snprintf(clean_password, sizeof(clean_password), "<via Auth-Type = %s>",
					 fr_dict_enum_alias_by_value(NULL, auth_type->da, &auth_type->data));
			} else {
				strcpy(clean_password, "<no User-Password attribute>");
			}
		} else if (fr_pair_find_by_num(request->packet->vps, 0, PW_CHAP_PASSWORD, TAG_ANY)) {
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


static void auth_dup_extract(REQUEST *request)
{
	listen_socket_t *sock = request->listener->data;

	if (!request->in_request_hash) return;

	if (!rbtree_deletebydata(sock->dup_tree, &request->packet)) {
		rad_assert(0 == 1);
	}
	request->in_request_hash = false;
}

/** Sit on a request until it's time to clean it up.
 *
 *  A NAS may not see a response from the server.  When the NAS
 *  retransmits, we want to be able to send a cached reply back.  The
 *  alternative is to re-process the packet, which does bad things for
 *  EAP, among others.
 *
 *  IF we do see a NAS retransmit, we extend the cleanup delay,
 *  because the NAS might miss our cached reply.
 *
 *  Otherwise, once we reach cleanup_delay, we transition to DONE.
 *
 *  \dot
 *	digraph cleanup_delay {
 *		cleanup_delay;
 *		send_reply [ label = "send_reply\nincrease cleanup delay" ];
 *
 *		cleanup_delay -> send_reply [ label = "DUP" ];
 *		send_reply -> cleanup_delay;
 *		cleanup_delay -> proxy_reply_too_late [ label = "PROXY_REPLY", arrowhead = "none" ];
 *		cleanup_delay -> cleanup_delay [ label = "TIMER < timeout" ];
 *		cleanup_delay -> done [ label = "TIMER >= timeout" ];
 *	}
 *  \enddot
 */
static void auth_cleanup_delay(REQUEST *request, fr_state_action_t action)
{
	struct timeval when;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_DUP:
		if (request->reply->code != 0) {
			gettimeofday(&request->reply->timestamp, NULL);

			if (fr_radius_packet_send(request->reply, request->packet, request->client->secret) < 0) {
				RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
				goto done;
			}
		} else {
			RDEBUG("No reply.  Ignoring retransmit");
		}

		/*
		 *	Increase the cleanup_delay to catch retransmits.
		 */
		when.tv_sec = request->root->cleanup_delay;
		when.tv_usec = 0;

		fr_timeval_add(&when, &request->reply->timestamp, &when);
		if (unlang_delay(request, &when, auth_cleanup_delay) < 0) goto done;
		break;


	case FR_ACTION_TIMER:
		/* FALL-THROUGH */
	done:
	case FR_ACTION_DONE:
		(void) fr_heap_extract(request->backlog, request);
		auth_dup_extract(request);
		request_thread_done(request);
		request_delete(request);
		break;

	default:
		break;
	}
}


/** Sit on a request until it's time to respond to it.
 *
 *  For security reasons, rejects (and maybe some other) packets are
 *  delayed for a while before we respond.  This delay means that
 *  badly behaved NASes don't hammer the server with authentication
 *  attempts.
 *
 *  Otherwise, once we reach reject_delay, we send the reply, and
 *  transition to cleanup_delay.
 *
 *  \dot
 *	digraph reject_delay {
 *		reject_delay -> response_delay [ label = "DUP, TIMER < timeout" ];
 *		reject_delay -> send_reply [ label = "TIMER >= timeout" ];
 *		send_reply -> cleanup_delay;
 *	}
 *  \enddot
 */
static void auth_reject_delay(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);
	TRACE_STATE_MACHINE;

	if (request->master_state == REQUEST_STOP_PROCESSING) action = FR_ACTION_DONE;

	switch (action) {
	case FR_ACTION_DUP:
		ERROR("(%" PRIu64 ") Discarding duplicate request from "
		      "client %s port %d - ID: %u due to delayed response",
		      request->number, request->client->shortname,
		      request->packet->src_port, request->packet->id);
		break;

	case FR_ACTION_TIMER:
		RDEBUG2("Sending delayed reject");
		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);

		gettimeofday(&request->reply->timestamp, NULL);
		if (fr_radius_packet_send(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
			goto done;
		}

		/*
		 *	Set up cleanup_delay
		 */
		if (request->root->cleanup_delay) {
			struct timeval when;

			when.tv_sec = request->root->cleanup_delay;
			when.tv_usec = 0;

			if (unlang_delay(request, &when, auth_cleanup_delay) < 0) goto done;
			return;
		}
		break;

	done:
	case FR_ACTION_DONE:
		(void) fr_heap_extract(request->backlog, request);
		auth_dup_extract(request);
		request_thread_done(request);
		request_delete(request);
		break;

		/*
		 *	Ignore other actions.
		 */
	default:
		break;
	}
}


static fr_transport_final_t auth_process(REQUEST *request)
{
	VALUE_PAIR *vp, *auth_type;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv = NULL;
	fr_dict_attr_t const *da = NULL;
	vp_cursor_t cursor;

	VERIFY_REQUEST(request);

	switch (request->request_state) {
	case REQUEST_INIT:
		if (request->packet->data_len != 0) {
			if (fr_radius_packet_decode(request->packet, NULL, request->client->secret) < 0) {
				RDEBUG("Failed decoding RADIUS packet: %s", fr_strerror());
				return FR_TRANSPORT_FAIL;
			}

			if (RDEBUG_ENABLED) common_packet_debug(request, request->packet, true);
		} else {
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Received %s ID %i",
				       fr_packet_codes[request->packet->code], request->packet->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
		}

		request->component = "radius";

		da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);
		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_subsection_find_name2(request->server_cs, "recv", dv->alias);
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "recv", "*");
		if (!unlang) {
			REDEBUG("Failed to find 'recv' section");
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Do various setups.
		 */
		request->username = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_NAME, TAG_ANY);
		request->password = fr_pair_find_by_num(request->packet->vps, 0, PW_USER_PASSWORD, TAG_ANY);

		/*
		 *	Grab the VPS and data associated with the State attribute.
		 */
		fr_state_to_request(global_state, request, request->packet);

		/*
		 *	Push the conf section into the unlang stack.
		 */
		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_REJECT);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_TRANSPORT_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_TRANSPORT_YIELD;

		request->log.unlang_indent = 0;

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
			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL) {
				char msg[FR_MAX_STRING_LEN + 16];

				snprintf(msg, sizeof(msg), "Invalid user (%s)",
					 vp->vp_strvalue);
				auth_message(msg, request, 0);
			} else {
				auth_message("Invalid user", request, 0);
			}

			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find Auth-Type, and complain if they have too many.
		 */
		fr_pair_cursor_init(&cursor, &request->control);
		auth_type = NULL;
		while ((vp = fr_pair_cursor_next_by_num(&cursor, 0, PW_AUTH_TYPE, TAG_ANY)) != NULL) {
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
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Handle hard-coded Accept and Reject.
		 */
		if (auth_type->vp_uint32 == PW_AUTH_TYPE_ACCEPT) {
			RDEBUG2("Auth-Type = Accept, allowing user");
			request->reply->code = PW_CODE_ACCESS_ACCEPT;
			goto setup_send;
		}

		if (auth_type->vp_uint32 == PW_AUTH_TYPE_REJECT) {
			RDEBUG2("Auth-Type = Reject, rejecting user");
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find the appropriate Auth-Type by name.
		 */
		vp = auth_type;
		dv = fr_dict_enum_by_value(NULL, vp->da, &vp->data);
		if (!dv) {
			REDEBUG2("Unknown Auth-Type %d found: rejecting the user", vp->vp_uint32);
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_subsection_find_name2(request->server_cs, "process", dv->alias);
		if (!unlang) {
			REDEBUG2("No 'process %s' section found: rejecting the user", dv->alias);
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		RDEBUG("Running 'process %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOTFOUND);

		request->request_state = REQUEST_PROCESS;
		/* FALL-THROUGH */

	case REQUEST_PROCESS:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_TRANSPORT_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_TRANSPORT_YIELD;

		request->log.unlang_indent = 0;

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
			request->reply->code = PW_CODE_ACCESS_REJECT;

			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL){
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

				if ((rad_debug_lvl > 1) && (request->password->da->attr == PW_USER_PASSWORD)) {
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
			request->reply->code = PW_CODE_ACCESS_ACCEPT;
			break;

		case RLM_MODULE_HANDLED:
			goto setup_send;
		}

		/*
		 *	When the user has been successfully
		 *	authenticated, ook for Simultaneous-Use.  But
		 *	only if we have a User-Name.
		 */
		vp = fr_pair_find_by_num(request->control, 0, PW_SIMULTANEOUS_USE, TAG_ANY);
		if (vp && request->username) {
			unlang = cf_subsection_find_name2(request->server_cs, "process", "Simultaneous-Use");
			if (!unlang) {
				REDEBUG2("No 'process Simultaneous' section found.");
				goto post_simul;
			}

			RDEBUG("Running 'process %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
			unlang_push_section(request, unlang, RLM_MODULE_NOTFOUND);

			request->request_state = REQUEST_SIMULTANEOUS_USE;
			/* FALL-THROUGH */

		case REQUEST_SIMULTANEOUS_USE:
			rcode = unlang_interpret_continue(request);

			if (request->master_state == REQUEST_STOP_PROCESSING) return FR_TRANSPORT_DONE;

			if (rcode == RLM_MODULE_YIELD) return FR_TRANSPORT_YIELD;

			request->log.unlang_indent = 0;

			switch (rcode) {
			default:
				RDEBUG2("Simultaneous-Use checks failed.");
				request->reply->code = PW_CODE_ACCESS_REJECT;

				if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL){
					char msg[FR_MAX_STRING_LEN+19];

					snprintf(msg, sizeof(msg), "Login limit exceeded (%s)",
						 vp->vp_strvalue);
					auth_message(msg, request, 0);
				} else {
					auth_message("Login limit exceeded", request, 0);
				}
				goto setup_send;

			case RLM_MODULE_NOOP:
			case RLM_MODULE_OK:
			case RLM_MODULE_UPDATED:
			case RLM_MODULE_HANDLED:
				break;
			}
		} /* else there's no Simultaneous-Use checking */

	post_simul:
		/*
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 0, PW_PACKET_TYPE, TAG_ANY);
		if (vp) {
			if (vp->vp_uint32 == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_uint32;
			}
		}

		if (request->reply->code == PW_CODE_ACCESS_ACCEPT) {
			if ((vp = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_SUCCESS_MESSAGE, TAG_ANY)) != NULL){
				char msg[FR_MAX_STRING_LEN+12];

				snprintf(msg, sizeof(msg), "Login OK (%s)",
					 vp->vp_strvalue);
				auth_message(msg, request, 1);
			} else {
				auth_message("Login OK", request, 1);
			}
		}

	setup_send:
		if (!da) da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) {
			unlang = cf_subsection_find_name2(request->server_cs, "send", dv->alias);
		}
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "send", "*");

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) return FR_TRANSPORT_DONE;

		if (rcode == RLM_MODULE_YIELD) return FR_TRANSPORT_YIELD;

		request->log.unlang_indent = 0;

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
			if (request->reply->code != PW_CODE_ACCESS_REJECT) {
				if (!da) da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
				rad_assert(da != NULL);

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying 'send Access-Reject'.", dv->alias);

				request->reply->code = PW_CODE_ACCESS_REJECT;

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_subsection_find_name2(request->server_cs, "send", dv->alias);
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
		if (request->reply->code == PW_CODE_ACCESS_CHALLENGE) {
			fr_request_to_state(global_state, request, request->packet, request->reply);

		} else {
			fr_state_discard(global_state, request, request->packet);
		}

		if (!request->reply->code) {
			vp = fr_pair_find_by_num(request->control, 0, PW_AUTH_TYPE, TAG_ANY);
			if (vp) {
				if (vp->vp_uint32 == PW_AUTH_TYPE_ACCEPT) {
					request->reply->code = PW_CODE_ACCESS_ACCEPT;

				} else if (vp->vp_uint32 == PW_AUTH_TYPE_REJECT) {
					request->reply->code = PW_CODE_ACCESS_REJECT;
				}
			}
		}

		/*
		 *	Check for "do not respond".
		 *
		 *	Not that we return REPLY here, specifically for cleanup_delay!
		 */
		if (!request->reply->code) {
			RDEBUG("Not sending reply to client.");
			return FR_TRANSPORT_REPLY;
		}

		/*
		 *	This is an internally generated request.
		 *	Don't print IP addresses, and don't do cleanup
		 *	/ reject delay.
		 */
		if (request->packet->data_len == 0) {
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Sent %s ID %i",
				       fr_packet_codes[request->reply->code], request->reply->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			return FR_TRANSPORT_REPLY;
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

		if (fr_radius_packet_encode(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed encoding RADIUS reply: %s", fr_strerror());
			return FR_TRANSPORT_FAIL;
		}

		if (fr_radius_packet_sign(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed signing RADIUS reply: %s", fr_strerror());
			return FR_TRANSPORT_FAIL;
		}
		break;

	default:
		return FR_TRANSPORT_FAIL;
	}

	return FR_TRANSPORT_REPLY;
}


static void auth_running(REQUEST *request, fr_state_action_t action)
{
	fr_transport_final_t rcode;

	TRACE_STATE_MACHINE;

	/*
	 *	Async (in the same thread, tho) signal to be done.
	 */
	if (action == FR_ACTION_DONE) goto done;

	/*
	 *	We ignore all other actions.
	 */
	if (action != FR_ACTION_RUN) return;

	switch (request->request_state) {
	case REQUEST_INIT:
		request->server = request->listener->server;
		request->server_cs = request->listener->server_cs;
		/* FALL-THROUGH */

	case REQUEST_RECV:
	case REQUEST_SEND:
		rcode = auth_process(request);
		if (rcode == FR_TRANSPORT_YIELD) return;

		/*
		 *	We can't do anything with the packet.
		 *	Mark it as "no reply", discard any
		 *	state we have, and clean up the packet
		 *	immediately.
		 */
		if (rcode == FR_TRANSPORT_FAIL) {
			request->reply->code = 0;
			fr_state_discard(global_state, request, request->packet);
			goto done;
		}

		/*
		 *	Forcibly done, don't do anything else.
		 */
		if (rcode == FR_TRANSPORT_DONE) {
			request->reply->code = 0;
			fr_state_discard(global_state, request, request->packet);
			goto done;
		}

		rad_assert(rcode == FR_TRANSPORT_REPLY);

		/*
		 *	Internally generated request: clean it
		 *	up now.
		 */
		if (request->packet->data_len == 0) goto done;

		/*
		 *	If we're not replying, we still have cleanup_delay.
		 */
		if (request->reply->code == 0) goto cleanup_delay;

		/*
		 *	If we delay rejects, then calculate the
		 *	correct delay.
		 */
		if ((request->reply->code == PW_CODE_ACCESS_REJECT) &&
		    ((request->root->reject_delay.tv_sec > 0) ||
		     (request->root->reject_delay.tv_usec > 0))) {
			struct timeval when, delay;
			VALUE_PAIR *vp;

			delay = request->root->reject_delay;

			vp = fr_pair_find_by_num(request->reply->vps, 0, PW_FREERADIUS_RESPONSE_DELAY, TAG_ANY);
			if (vp) {
				if (vp->vp_uint32 <= 10) {
					delay.tv_sec = vp->vp_uint32;
				} else {
					delay.tv_sec = 10;
				}
				delay.tv_usec = 0;
			} else {
				vp = fr_pair_find_by_num(request->reply->vps, 0, PW_FREERADIUS_RESPONSE_DELAY_USEC, TAG_ANY);
				if (vp) {
					if (vp->vp_uint32 <= 10 * USEC) {
						delay.tv_sec = vp->vp_uint32 / USEC;
						delay.tv_usec = vp->vp_uint32 % USEC;
					} else {
						delay.tv_sec = 10;
						delay.tv_usec = 0;
					}
				}
			}

			/*
			 *	Delay it from when we received the
			 *	request, not from when we're sending
			 *	the reply.
			 */
			fr_timeval_add(&when, &request->packet->timestamp, &delay);
			if (fr_timeval_cmp(&when, &request->reply->timestamp) > 0) {
				fr_timeval_subtract(&delay, &when, &request->reply->timestamp);

				RDEBUG2("Delaying Access-Reject for %d.%06d seconds",
					(int) delay.tv_sec, (int) delay.tv_usec);

				if (unlang_delay(request, &delay, auth_reject_delay) == 0) {
					return;
				}
			}
		} /* else send the response immediately */

		if (fr_radius_packet_send(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
		}

		/*
		 *	And do any necessary cleanup delay.
		 */
		if (request->root->cleanup_delay) {
			struct timeval when;

cleanup_delay:
			when.tv_sec = request->root->cleanup_delay;
			when.tv_usec = 0;

			if (unlang_delay(request, &when, auth_cleanup_delay) < 0) goto done;
			return;
		}
		/* FALL-THROUGH */

	default:
	done:
		(void) fr_heap_extract(request->backlog, request);
		auth_dup_extract(request);
		request_thread_done(request);
		request_delete(request);
		break;
	}
}


/** Process events while the request is queued.
 *
 *  We give different messages on DUP, and on DONE,
 *  remove the request from the queue
 *
 *  \dot
 *	digraph auth_queued {
 *		auth_queued -> done [ label = "TIMER >= max_request_time" ];
 *		auth_queued -> auth_running [ label = "RUNNING" ];
 *	}
 *  \enddot
 */
static void auth_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_RUN:
		request->process = auth_running;
		request->process(request, action);
		break;

	case FR_ACTION_DONE:
		request_delete(request);
		break;

	default:
		break;
	}
}


/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int auth_socket_recv(rad_listen_t *listener)
{
	RADIUS_PACKET	*packet;
	RADCLIENT	*client;
	TALLOC_CTX	*ctx;
	REQUEST		*request;
	listen_socket_t *sock = listener->data;

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		(void) udp_recv_discard(listener->fd);
		return 0;
	}
	talloc_set_name_const(ctx, "auth_listener_pool");

	packet = fr_radius_packet_recv(ctx, listener->fd, 0, false);
	if (!packet) {
		ERROR("%s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if (packet->code != PW_CODE_ACCESS_REQUEST) {
		if (packet->code < FR_MAX_PACKET_CODE) {
			DEBUG2("Invalid packet code %s sent to authentication port", fr_packet_codes[packet->code]);
		} else {
			DEBUG2("Invalid packet code %d sent to authentication port", packet->code);
		}

		talloc_free(ctx);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr,
					   packet->src_port)) == NULL) {
		talloc_free(ctx);
		return 0;
	}

	if (request_dup_received(listener, sock->dup_tree, client, packet)) {
		talloc_free(ctx);
		return 0;
	}

	if (request_limit(listener, client, packet)) {
		talloc_free(ctx);
		return 0;
	}

	request = request_setup(ctx, listener, packet, client, NULL);
	if (!request) {
		talloc_free(ctx);
		return 0;
	}

	if (!rbtree_insert(sock->dup_tree, &request->packet)) {
		RERROR("Failed to insert request in the list of live requests: discarding it");
		request_free(request);
		return 1;
	}
	request->in_request_hash = true;

	request->process = auth_queued;
	request_enqueue(request);

	return 1;
}


static int auth_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2, rlm_components_t component)
{
	CONF_SECTION *cs;

	cs = cf_subsection_find_name2(server_cs, name1, name2);
	if (!cs) return 0;

	cf_log_module(cs, "Loading %s %s {...}", name1, name2);

	if (unlang_compile(cs, component) < 0) {
		cf_log_err_cs(cs, "Failed compiling '%s %s { ... }' section", name1, name2);
		return -1;
	}

	return 1;
}


/*
 *	Ensure that the "radius" section is compiled.
 */
static int auth_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;
	CONF_SECTION *subcs;

	rcode = auth_compile_section(server_cs, "recv", "Access-Request", MOD_AUTHORIZE);
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		cf_log_err_cs(server_cs, "Failed finding 'recv Access-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = auth_compile_section(server_cs, "send", "Access-Accept", MOD_POST_AUTH);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err_cs(server_cs, "Failed finding 'send Access-Accept { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = auth_compile_section(server_cs, "send", "Access-Reject", MOD_POST_AUTH);
	if (rcode < 0) return rcode;
	if (rcode == 0) {
		cf_log_err_cs(server_cs, "Failed finding 'send Access-Reject { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	/*
	 *	It's OK to not have an Access-Challenge section.
	 */
	rcode = auth_compile_section(server_cs, "send", "Access-Challenge", MOD_POST_AUTH);
	if (rcode < 0) return rcode;

	for (subcs = cf_subsection_find_next(server_cs, NULL, "process");
	     subcs != NULL;
	     subcs = cf_subsection_find_next(server_cs, subcs, "process")) {
		char const *name2;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err_cs(subcs, "Cannot compile 'process { ... }' section");
			return -1;
		}

		cf_log_module(subcs, "Loading process %s {...}", name2);

		/*
		 *	Simultaneous-Use is special.
		 */
		if (strcmp(name2, "Simultaneous-Use") == 0) {
			if (unlang_compile(subcs, MOD_SESSION) < 0) {
				cf_log_err_cs(subcs, "Failed compiling 'process %s { ... }' section", name2);
				return -1;
			}
			continue;
		}

		if (unlang_compile(subcs, MOD_AUTHENTICATE) < 0) {
			cf_log_err_cs(subcs, "Failed compiling 'process %s { ... }' section", name2);
			return -1;
		}
	}

	return 0;
}

static int auth_listen_bootstrap(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *subcs;
	fr_dict_attr_t const *da;

	da = fr_dict_attr_by_num(NULL, 0, PW_AUTH_TYPE);
	if (!da) {
		cf_log_err_cs(server_cs, "Failed finding dictionary definition for Auth-Type");
		return -1;
	}

	for (subcs = cf_subsection_find_next(server_cs, NULL, "process");
	     subcs != NULL;
	     subcs = cf_subsection_find_next(server_cs, subcs, "process")) {
		char const	*name2;
		fr_value_box_t	value = { .type = FR_TYPE_UINT32 };
		fr_dict_enum_t	*dv;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err_cs(subcs, "Invalid 'process { ... }' section, it must have a name");
			return -1;
		}

		/*
		 *	No Auth-Type for this.
		 */
		if (strcmp(name2, "Simultaneous-Use") == 0) continue;

		/*
		 *	If the value already exists, don't
		 *	create it again.
		 */
		dv = fr_dict_enum_by_alias(NULL, da, name2);
		if (dv) continue;

		/*
		 *	Create a new unique value with a meaningless
		 *	number.  You can't look at it from outside of
		 *	this code, so it doesn't matter.  The only
		 *	requirement is that it's unique.
		 */
		do {
			value.datum.uint32 = (fr_rand() & 0x00ffffff) + 1;
		} while (fr_dict_enum_by_value(NULL, da, &value));

		cf_log_module(subcs, "Creating %s = %s", da->name, name2);
		if (fr_dict_enum_add_alias(da, name2, &value, true, false) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
		}
	}

	return 0;
}

static int packet_entry_cmp(void const *one, void const *two)
{
	RADIUS_PACKET const * const *a = one;
	RADIUS_PACKET const * const *b = two;

	return fr_packet_cmp(*a, *b);
}

static int auth_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	listen_socket_t *sock = this->data;

	if (common_socket_parse(cs, this) < 0) return -1;

	if (!sock->my_port) sock->my_port = PW_AUTH_UDP_PORT;

	sock->dup_tree = rbtree_create(NULL, packet_entry_cmp, NULL, 0);

	return 0;
}


extern rad_protocol_t proto_radius_auth;
rad_protocol_t proto_radius_auth = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_auth",
	.inst_size	= sizeof(listen_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,
	.bootstrap	= auth_listen_bootstrap,
	.compile	= auth_listen_compile,
	.parse		= auth_socket_parse,
	.open		= common_socket_open,
	.recv		= auth_socket_recv,
	.send		= NULL,
	.print		= common_socket_print,
	.debug = common_packet_debug,
	.encode		= NULL,
	.decode		= NULL,
};
