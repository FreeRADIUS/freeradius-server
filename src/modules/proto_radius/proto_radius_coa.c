/*
 * proto_radius_coa.c	RADIUS CoA processing.
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
#include <freeradius-devel/udp.h>
#include <freeradius-devel/rad_assert.h>

static void coa_running(REQUEST *request, fr_state_action_t action)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;

	VERIFY_REQUEST(request);

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
		if (request->packet->data_len != 0) {
			if (fr_radius_packet_decode(request->packet, NULL, request->client->secret) < 0) {
				RDEBUG("Failed decoding RADIUS packet: %s", fr_strerror());
				goto done;
			}

			if (RDEBUG_ENABLED) common_packet_debug(request, request->packet, true);
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
		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->packet->code));
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			goto done;
		}

		unlang = cf_subsection_find_name2(request->server_cs, "recv", dv->alias);
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "recv", "*");
		if (!unlang) {
			REDEBUG("Failed to find 'recv' section");
			goto done;
		}

		RDEBUG("Running 'recv %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);

		request->request_state = REQUEST_RECV;
		/* FALL-THROUGH */

	case REQUEST_RECV:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

		if (rcode == RLM_MODULE_YIELD) return;

		request->log.unlang_indent = 0;

		switch (rcode) {
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = request->packet->code + 1; /* ACK */
			break;

		case RLM_MODULE_HANDLED:
			break;


		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = request->packet->code + 2; /* NAK */
			break;
		}

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

		if (!da) da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);

		dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
		unlang = NULL;
		if (dv) {
			unlang = cf_subsection_find_name2(request->server_cs, "send", dv->alias);
		}
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "send", "*");

		if (!unlang) goto send_reply;

		/*
		 *	Note that for NAKs, we do NOT use
		 *	reject_delay.  This is because we're acting as
		 *	a NAS, and we want to respond to the RADIUS
		 *	server as quickly as possible.
		 */
	rerun_nak:
		RDEBUG("Running 'send %s' from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		unlang_push_section(request, unlang, RLM_MODULE_NOOP);
		request->log.unlang_indent = 0;

		request->request_state = REQUEST_SEND;
		/* FALL-THROUGH */

	case REQUEST_SEND:
		rcode = unlang_interpret_continue(request);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

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
			if (request->reply->code == request->packet->code + 1) {
				if (!da) da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
				rad_assert(da != NULL);

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
				RWDEBUG("Failed running 'send %s', trying corresponding NAK section.", dv->alias);

				request->reply->code = request->packet->code + 2;

				dv = fr_dict_enum_by_value(NULL, da, fr_box_uint32(request->reply->code));
				unlang = NULL;
				if (!dv) goto send_reply;

				unlang = cf_subsection_find_name2(request->server_cs, "send", dv->alias);
				if (unlang) goto rerun_nak;

				RWDEBUG("Not running 'send %s' section as it does not exist", dv->alias);
			}
			/*
			 *	Else it was already a NAK or something else.
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
			goto done;
		}

		/*
		 *	This is an internally generated request.  Don't print IP addresses.
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

		if (RDEBUG_ENABLED) common_packet_debug(request, request->reply, false);

		if (fr_radius_packet_encode(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed encoding RADIUS reply: %s", fr_strerror());
			goto done;
		}

		if (fr_radius_packet_sign(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed signing RADIUS reply: %s", fr_strerror());
			goto done;
		}

		if (fr_radius_packet_send(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
		}
		/* FALL-THROUGH */

	default:
	done:
		(void) fr_heap_extract(request->backlog, request);
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
 *	digraph coa_queued {
 *		coa_queued -> done [ label = "TIMER >= max_request_time" ];
 *		coa_queued -> coa_running [ label = "RUNNING" ];
 *	}
 *  \enddot
 */
static void coa_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_RUN:
		request->process = coa_running;
		request->process(request, action);
		break;

	case FR_ACTION_DONE:
		(void) fr_heap_extract(request->backlog, request);
		fr_event_timer_delete(request->el, &request->ev);

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
static int coa_socket_recv(rad_listen_t *listener)
{
	RADIUS_PACKET	*packet;
	RADCLIENT	*client;
	TALLOC_CTX	*ctx;
	REQUEST		*request;

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		(void) udp_recv_discard(listener->fd);
		return 0;
	}
	talloc_set_name_const(ctx, "coa_listener_pool");

	packet = fr_radius_packet_recv(ctx, listener->fd, 0, false);
	if (!packet) {
		ERROR("%s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if ((packet->code != PW_CODE_COA_REQUEST) &&
	    (packet->code != PW_CODE_DISCONNECT_REQUEST)) {
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

	request->process = coa_queued;
	request_enqueue(request);

	return 1;
}


static int coa_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2, rlm_components_t component)
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
static int coa_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;
	bool coa_found, dm_found;

	coa_found = dm_found = false;

	rcode = coa_compile_section(server_cs, "recv", "CoA-Request", MOD_RECV_COA);
	if (rcode < 0) return rcode;
	if (rcode == 1) coa_found = true;

	rcode = coa_compile_section(server_cs, "recv", "Disconnect-Request", MOD_RECV_COA);
	if (rcode < 0) return rcode;
	if (rcode == 1) dm_found = true;

	if (!coa_found || !dm_found) {
		rcode = coa_compile_section(server_cs, "recv", "*", MOD_RECV_COA);
		if (rcode < 0) return rcode;
		if (rcode == 1) coa_found = dm_found = true;
	}

	if (rcode == 0) {
		if (!coa_found) {
			cf_log_err_cs(server_cs, "Failed finding 'recv CoA-Request { ... }' section of virtual server %s",
				      cf_section_name2(server_cs));
			return -1;
		}

		cf_log_err_cs(server_cs, "Failed finding 'recv Disconnect-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	if (coa_found) {
		rcode = coa_compile_section(server_cs, "send", "CoA-ACK", MOD_SEND_COA);
		if (rcode < 0) return rcode;

		rcode = coa_compile_section(server_cs, "send", "CoA-NAK", MOD_SEND_COA);
		if (rcode < 0) return rcode;
	}

	if (dm_found) {
		rcode = coa_compile_section(server_cs, "send", "Disconnect-ACK", MOD_SEND_COA);
		if (rcode < 0) return rcode;

		rcode = coa_compile_section(server_cs, "send", "Disconnect-NAK", MOD_SEND_COA);
		if (rcode < 0) return rcode;
	}

	rcode = coa_compile_section(server_cs, "send", "*", MOD_PREACCT);
	if (rcode < 0) return rcode;

	return 0;
}

static int coa_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	listen_socket_t *sock = this->data;

	if (common_socket_parse(cs, this) < 0) return -1;

	if (!sock->my_port) sock->my_port = PW_COA_UDP_PORT;

	return 0;
}

extern rad_protocol_t proto_radius_coa;
rad_protocol_t proto_radius_coa = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_coa",
	.inst_size	= sizeof(listen_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,
	.bootstrap	= NULL,
	.compile	= coa_listen_compile,
	.parse		= coa_socket_parse,
	.open		= common_socket_open,
	.recv		= coa_socket_recv,
	.send		= NULL,
	.print		= common_socket_print,
	.debug = common_packet_debug,
	.encode		= NULL,
	.decode		= NULL,
};
