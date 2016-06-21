/*
 * proto_radius.c	RADIUS processing.
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

static void acct_running(REQUEST *request, fr_state_action_t action)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;
	fr_dict_enum_t const *dv;
	fr_dict_attr_t const *da = NULL;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_RUN:
		if (fr_radius_decode(request->packet, NULL, request->client->secret) < 0) {
			RDEBUG("Failed decoding RADIUS packet: %s", fr_strerror());
			goto done;
		}

		common_packet_debug(request, request->packet, true);

		request->server = request->listener->server;
		request->server_cs = request->listener->server_cs;
		request->component = "radius";

		da = fr_dict_attr_by_num(NULL, 0, PW_PACKET_TYPE);
		rad_assert(da != NULL);
		dv = fr_dict_enum_by_da(NULL, da, request->packet->code);
		if (!dv) {
			REDEBUG("Failed to find value for &request:Packet-Type");
			goto done;
		}

		unlang = cf_section_sub_find_name2(request->server_cs, "recv", dv->name);
		if (!unlang) unlang = cf_section_sub_find_name2(request->server_cs, "recv", "*");
		if (!unlang) {
			REDEBUG("Failed to find 'recv' section");
			goto done;
		}

		RDEBUG("Running recv %s from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		rcode = unlang_interpret(request, unlang, RLM_MODULE_NOOP);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

		switch (rcode) {
		/*
		 *	The module has a number of OK return codes.
		 */
		case RLM_MODULE_NOOP:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			break;
		/*
		 *	The module handled the request, send the reply and don't process "send" section.
		 */
		case RLM_MODULE_HANDLED:
			goto send;

		/*
		 *	The module failed, or said the request is
		 *	invalid, therefore we stop here.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			goto done;
		}

		vp = fr_pair_find_by_num(request->reply->vps, 0, PW_PACKET_TYPE, TAG_ANY);
		if (vp) {
			if (vp->vp_integer == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_integer;
			}

		} else if (rcode != RLM_MODULE_HANDLED) {
			request->reply->code = PW_CODE_ACCOUNTING_RESPONSE;
		}

		dv = fr_dict_enum_by_da(NULL, da, request->reply->code);
		unlang = NULL;
		if (dv) {
			unlang = cf_section_sub_find_name2(request->server_cs, "send", dv->name);
		}
		if (!unlang) unlang = cf_section_sub_find_name2(request->server_cs, "send", "*");

		if (unlang) {
			RDEBUG("Running send %s from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
			rcode = unlang_interpret(request, unlang, RLM_MODULE_NOOP);

			if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

			switch (rcode) {
				/*
				 *	In case the accounting module returns FAIL,
				 *	it's still useful to send the data to the
				 *	proxy.
				 */
			case RLM_MODULE_FAIL:
			case RLM_MODULE_NOOP:
			case RLM_MODULE_OK:
			case RLM_MODULE_UPDATED:
				break;
				/*
				 *	The module handled the request, don't reply.
				 */
			case RLM_MODULE_HANDLED:
				goto done;

				/*
				 *	Neither proxy, nor reply to invalid requests.
				 */
			case RLM_MODULE_INVALID:
			case RLM_MODULE_NOTFOUND:
			case RLM_MODULE_REJECT:
			case RLM_MODULE_USERLOCK:
			default:
				break;
			}
		}

	send:
		/*
		 *	Check for "do not respond".
		 */
		if (!request->reply->code) {
			RDEBUG("Not sending reply to client.");
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
			goto done;
		}
		
		if (fr_radius_sign(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed signing RADIUS reply: %s", fr_strerror());
			goto done;
		}
		
		common_packet_debug(request, request->reply, false);

		if (fr_radius_send(request->reply, request->packet, request->client->secret) < 0) {
			RDEBUG("Failed sending RADIUS reply: %s", fr_strerror());
		}

	done:
		request_thread_done(request);
		RDEBUG2("Cleaning up request packet ID %u with timestamp +%d",
			request->packet->id,
			(unsigned int) (request->packet->timestamp.tv_sec - fr_start_time));
		request_free(request);
		break;

	default:
		break;
	}
}


/** Process events while the request is queued.
 *
 *  We give different messages on DUP, and on DONE,
 *  remove the request from the queue
 *
 *  \dot
 *	digraph acct_queued {
 *		acct_queued -> done [ label = "TIMER >= max_request_time" ];
 *		acct_queued -> acct_running [ label = "RUNNING" ];
 *	}
 *  \enddot
 */
static void acct_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_RUN:
		request->process = acct_running;
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
static int acct_socket_recv(rad_listen_t *listener)
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
	talloc_set_name_const(ctx, "acct_listener_pool");

	packet = fr_radius_recv(ctx, listener->fd, 0, false);
	if (!packet) {
		ERROR("%s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if (packet->code != PW_CODE_ACCOUNTING_REQUEST) {
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

	request->process = acct_queued;
	request_enqueue(request);

	return 1;
}


static int acct_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2, rlm_components_t component)
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
static int acct_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;

	rcode = acct_compile_section(server_cs, "recv", "Accounting-Request", MOD_PREACCT);
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		rcode = acct_compile_section(server_cs, "recv", "*", MOD_PREACCT);
		if (rcode < 0) return rcode;
	}

	if (rcode == 0) {
		cf_log_err_cs(server_cs, "Failed finding 'recv Accounting-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = acct_compile_section(server_cs, "send", "Accounting-Response", MOD_ACCOUNTING);
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		rcode = acct_compile_section(server_cs, "send", "*", MOD_ACCOUNTING);
		if (rcode < 0) return rcode;
	}

	return 0;
}

extern rad_protocol_t proto_radius_acct;
rad_protocol_t proto_radius_acct = {
	.magic		= RLM_MODULE_INIT,
	.name		= "radius_acct",
	.inst_size	= sizeof(listen_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,
	.bootstrap	= NULL,	/* don't do Acct-Type any more */
	.compile	= acct_listen_compile,
	.parse		= common_socket_parse,
	.open		= common_socket_open,
	.recv		= acct_socket_recv,
	.send		= NULL,
	.print		= common_socket_print,
	.debug = common_packet_debug,
	.encode		= NULL,
	.decode		= NULL,
};
