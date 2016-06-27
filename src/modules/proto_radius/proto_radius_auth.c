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
#include <freeradius-devel/rad_assert.h>

static void auth_running(REQUEST *request, fr_state_action_t action)
{
	VALUE_PAIR *vp, *auth_type;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;
	vp_cursor_t cursor;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	/*
	 *	We ignore all other actions.
	 */
	if (action != FR_ACTION_RUN) return;

	switch (request->request_state) {
	case REQUEST_INIT:
		if (request->packet->data_len != 0) {
			if (fr_radius_decode(request->packet, NULL, request->client->secret) < 0) {
				RDEBUG("Failed decoding RADIUS packet: %s", fr_strerror());
				goto done; /* don't reject it, Message-Authenticator might be wrong */
			}

			common_packet_debug(request, request->packet, true);
		} else {
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Received %s ID %i",
				       fr_packet_codes[request->packet->code], request->packet->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->packet->vps, "");
		}

		request->server = request->listener->server;
		request->server_cs = request->listener->server_cs;
		request->component = "radius";

		da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);
		dv = fr_dict_enum_by_da(NULL, da, request->packet->code);
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_section_sub_find_name2(request->server_cs, "recv", dv->name);
		if (!unlang) unlang = cf_section_sub_find_name2(request->server_cs, "recv", "*");
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

		if (request->master_state == REQUEST_STOP_PROCESSING) goto stop_processing;

		if (rcode == RLM_MODULE_YIELD) return;

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
#if 0
			if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL) {
				char msg[FR_MAX_STRING_LEN + 16];
				snprintf(msg, sizeof(msg), "Invalid user (%s)",
					 module_msg->vp_strvalue);
				rad_authlog(msg,request,0);
			} else {
				rad_authlog("Invalid user", request, 0);
			}
#endif
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		/*
		 *	Find Auth-Type, and complain if they have too many.
		 */
		fr_cursor_init(&cursor, &request->control);
		auth_type = NULL;
		while ((vp = fr_cursor_next_by_num(&cursor, 0, PW_AUTH_TYPE, TAG_ANY)) != NULL) {
			if (!auth_type) {
				auth_type = vp;
				continue;
			}

			RWDEBUG("Ignoring extra Auth-Type = %s", fr_dict_enum_name_by_da(NULL, auth_type->da, vp->vp_integer));
		}

		/*
		 *	Handle hard-coded Accept and Reject.
		 */
		if (auth_type->vp_integer == PW_AUTH_TYPE_ACCEPT) {
			RDEBUG2("Auth-Type = Accept, allowing user");
			goto setup_send;
		}

		if (auth_type->vp_integer == PW_AUTH_TYPE_REJECT) {
			RDEBUG2("Auth-Type = Reject, rejecting user");
			goto setup_send;
		}

		/*
		 *	Find the appropriate Auth-Type by name.
		 */
		vp = auth_type;
		dv = fr_dict_enum_by_da(NULL, vp->da, vp->vp_integer);
		if (!dv) {
			REDEBUG2("Unknown Auth-Type %d found: rejecting the user.", vp->vp_integer);
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		unlang = cf_section_sub_find_name2(request->server_cs, "process", dv->name);
		if (!unlang) {
			REDEBUG2("No 'process %s' section found: rejecting the user.", dv->name);
			request->reply->code = PW_CODE_ACCESS_REJECT;
			goto setup_send;
		}

		RDEBUG("Running 'process %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOTFOUND);

		request->request_state = REQUEST_PROCESS;
		/* FALL-THROUGH */

	case REQUEST_PROCESS:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto stop_processing;

		if (rcode == RLM_MODULE_YIELD) return;

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

#if 0
			if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_FAILURE_MESSAGE, TAG_ANY)) != NULL){
				char msg[FR_MAX_STRING_LEN+19];

				snprintf(msg, sizeof(msg), "Login incorrect (%s)",
					 module_msg->vp_strvalue);
				rad_authlog(msg, request, 0);
			} else {
				rad_authlog("Login incorrect", request, 0);
			}
#endif

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
		 *	Allow for over-ride of reply code.
		 */
		vp = fr_pair_find_by_num(request->reply->vps, 0, PW_PACKET_TYPE, TAG_ANY);
		if (vp) {
			if (vp->vp_integer == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_integer;
			}
		}

#if 0
		if (request->reply->code == PW_ACCESS_ACCEPT) {
			if ((module_msg = fr_pair_find_by_num(request->packet->vps, 0, PW_MODULE_SUCCESS_MESSAGE, TAG_ANY)) != NULL){
				char msg[FR_MAX_STRING_LEN+12];

				snprintf(msg, sizeof(msg), "Login OK (%s)",
					 module_msg->vp_strvalue);
				rad_authlog(msg, request, 1);
			} else {
				rad_authlog("Login OK", request, 1);
			}
		}
#endif

	setup_send:
		if (!da) da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);

		dv = fr_dict_enum_by_da(NULL, da, request->reply->code);
		unlang = NULL;
		if (dv) {
			unlang = cf_section_sub_find_name2(request->server_cs, "send", dv->name);
		}
		if (!unlang) unlang = cf_section_sub_find_name2(request->server_cs, "send", "*");

		if (!unlang) goto send_reply;

	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto stop_processing;

		if (rcode == RLM_MODULE_YIELD) return;

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

				dv = fr_dict_enum_by_da(NULL, da, request->reply->code);
				RWDEBUG("Failed running 'send %s', trying 'send Access-Reject'.", dv->name);

				request->reply->code = PW_CODE_ACCESS_REJECT;

				dv = fr_dict_enum_by_da(NULL, da, request->reply->code);
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_section_sub_find_name2(request->server_cs, "send", dv->name);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->name);
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
		/*
		 *	Check for "do not respond".
		 */
		if (!request->reply->code) {
			RDEBUG("Not sending reply to client.");

			fr_state_discard(global_state, request, request->packet);

			if (request->packet->data_len == 0) goto done;

			goto cleanup_delay;
		}

		/*
		 *	This is an internally generated request.
		 *	Don't print IP addresses, and don't discard
		 *	the state.
		 */
		if (request->packet->data_len == 0) {
			radlog_request(L_DBG, L_DBG_LVL_1, request, "Sent %s ID %i",
				       fr_packet_codes[request->reply->code], request->reply->id);
			rdebug_proto_pair_list(L_DBG_LVL_1, request, request->reply->vps, "");
			goto done;
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

		if (fr_radius_encode(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed encoding RADIUS reply: %s", fr_strerror());
			goto stop_processing;
		}

		if (fr_radius_sign(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed signing RADIUS reply: %s", fr_strerror());

			/*
			 *	We can't do anything with the packet.
			 *	Mark it as "no reply", discard any
			 *	state we have, and clean up the packet
			 *	immediately.
			 */
		stop_processing:
			request->reply->code = 0;
			fr_state_discard(global_state, request, request->packet);
			goto done;
		}

		/*
		 *	@fixme: on Access-Reject, set up reject_delay, and associated states.
		 */

		common_packet_debug(request, request->reply, false);

		/*
		 *	Save session-state list for Access-Challenge,
		 *	discard it for everything else.
		 */
		if (request->reply->code == PW_CODE_ACCESS_CHALLENGE) {
			fr_request_to_state(global_state, request, request->packet, request->reply);

		} else {
			fr_state_discard(global_state, request, request->packet);
		}

		if (fr_radius_send(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
		}

	default:
	done:
	cleanup_delay:
		request_thread_done(request);
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->packet->timestamp.tv_sec - fr_start_time));
		request_free(request);
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
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->packet->timestamp.tv_sec - fr_start_time));
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

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		udp_recv_discard(listener->fd);
		return 0;
	}
	talloc_set_name_const(ctx, "auth_listener_pool");

	packet = fr_radius_recv(ctx, listener->fd, 0, false);
	if (!packet) {
		ERROR("%s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if (packet->code != PW_CODE_ACCESS_REQUEST) {
		DEBUG2("Invalid packet code %d", packet->code);
		talloc_free(ctx);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr,
					   packet->src_port)) == NULL) {
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

	request->process = auth_queued;
	request_enqueue(request);

	return 1;
}


static int auth_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2, rlm_components_t component)
{
	CONF_SECTION *cs;

	cs = cf_section_sub_find_name2(server_cs, name1, name2);
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
		char const *name2;
		uint32_t value;
		fr_dict_enum_t *dv;

		name2 = cf_section_name2(subcs);
		if (!name2) {
			cf_log_err_cs(subcs, "Invalid 'process { ... }' section, it must have a name");
			return -1;
		}

		/*
		 *	If the value already exists, don't
		 *	create it again.
		 */
		dv = fr_dict_enum_by_name(NULL, da, name2);
		if (dv) continue;

		/*
		 *	Create a new unique value with a meaningless
		 *	number.  You can't look at it from outside of
		 *	this code, so it doesn't matter.  The only
		 *	requirement is that it's unique.
		 */
		do {
			value = (fr_rand() & 0x00ffffff) + 1;
		} while (fr_dict_enum_by_da(NULL, da, value));

		cf_log_module(subcs, "Creating %s = %s", da->name, name2);
		if (fr_dict_enum_add(NULL, da->name, name2, value) < 0) {
			ERROR("%s", fr_strerror());
			return -1;
		}
	}

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
	.parse		= common_socket_parse,
	.open		= common_socket_open,
	.recv		= auth_socket_recv,
	.send		= NULL,
	.print		= common_socket_print,
	.debug = common_packet_debug,
	.encode		= NULL,
	.decode		= NULL,
};
