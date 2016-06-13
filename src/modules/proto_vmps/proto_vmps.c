/*
 * proto_vmps.c	Handle VMPS traffic.
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
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/udp.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "vqp.h"

static void vmps_done(REQUEST *request, UNUSED fr_state_action_t action)
{
	TRACE_STATE_MACHINE;

	request->component = NULL;
	request->module = NULL;

	/*
	 *	Wait until the child thread has finished.
	 */
	if (request_thread_active(request)) return;

	request->child_state = REQUEST_DONE;

#ifdef DEBUG_STATE_MACHINE
	if (rad_debug_lvl) printf("(%" PRIu64 ") ********\tSTATE %s C-%s -> C-%s\t********\n",
				  request->number, __FUNCTION__,
				  child_state_names[request->child_state],
				  child_state_names[REQUEST_DONE]);
#endif

	request_delete(request);
}

static void vmps_running(REQUEST *request, fr_state_action_t action)
{
	VALUE_PAIR *vp;
	rlm_rcode_t rcode;
	CONF_SECTION *unlang;

	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	/*
	 *	Stop if signalled/
	 */
	if (request->master_state == REQUEST_STOP_PROCESSING) action = FR_ACTION_DONE;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		if (vqp_decode(request->packet) < 0) {
			RDEBUG("Failed decoding VMPS packet: %s", fr_strerror());
			goto done;
		}

		request->server = request->listener->server;
		request->server_cs = request->listener->server_cs;
		unlang = cf_section_sub_find(request->server_cs, "vmps");
		request->component = "vmps";

		rcode = unlang_interpret(request, unlang, RLM_MODULE_NOOP);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

		vp = fr_pair_find_by_num(request->reply->vps, 0, 0x2b00, TAG_ANY);
		if (vp) {
			if (vp->vp_integer == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_integer;
			}

		} else if (rcode != RLM_MODULE_HANDLED) {
			if (request->packet->code == 1) {
				request->reply->code = 2;

			} else if (request->packet->code == 3) {
				request->reply->code = 4;
			}
		}

		/*
		 *	Check for "do not respond".
		 */
		if (!request->reply->code) {
			RDEBUG("Not sending reply to client.");

		} else if (vqp_encode(request->reply, request->packet) < 0) {
			RDEBUG("Failed encoding VMPS reply: %s", fr_strerror());

		} else if (udp_send(request->reply->sockfd, request->reply->data, request->reply->data_len, 0,
				    &request->reply->src_ipaddr, request->reply->src_port, request->reply->if_index,
				    &request->reply->dst_ipaddr, request->reply->dst_port) < 0) {
			RDEBUG("Failed sending VMPS reply: %s", fr_strerror());
		}
		request_thread_done(request);

		/* FALL-THROUGH */

	case FR_ACTION_DONE:
	done:
		request->process = vmps_done;
		request->process(request, FR_ACTION_DONE);
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
 *	digraph vmps_queued {
 *		vmps_queued -> vmps_queued [ label = "TIMER < max_request_time" ];
 *		vmps_queued -> done [ label = "TIMER >= max_request_time" ];
 *		vmps_queued -> running [ label = "RUNNING" ];
 *		vmps_queued -> dup [ label = "DUP", arrowhead = "none" ];
 *	}
 *  \enddot
 */
static void vmps_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	if (request->master_state == REQUEST_STOP_PROCESSING) action = FR_ACTION_DONE;

	switch (action) {
	case FR_ACTION_TIMER:
		(void) request_max_time(request);
		break;

	case FR_ACTION_RUN:
		request->process = vmps_running;
		request->process(request, action);
		break;

	case FR_ACTION_DONE:
		request_queue_extract(request);
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
static int vqp_socket_recv(rad_listen_t *listener)
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
	talloc_set_name_const(ctx, "vmps_listener_pool");

	packet = vqp_recv(ctx, listener->fd);
	if (!packet) {
		ERROR("%s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if ((packet->code != 1) && (packet->code != 3)) {
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

	request_thread(request, vmps_queued);

	return 1;
}


/*
 *	If there's no "vmps" section, we can't bootstrap anything.
 */
static int vqp_listen_bootstrap(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_sub_find(server_cs, "vmps");
	if (!cs) {
		cf_log_err_cs(server_cs, "No 'vmps' sub-section found");
		return -1;
	}

	return 0;
}

/*
 *	Ensure that the "vmps" section is compiled.
 */
static int vqp_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	CONF_SECTION *cs;

	cs = cf_section_sub_find(server_cs, "vmps");
	if (!cs) {
		cf_log_err_cs(server_cs, "No 'vmps' sub-section found");
		return -1;
	}

	cf_log_module(cs, "Loading vmps {...}");

	if (unlang_compile(cs, MOD_POST_AUTH) < 0) {
		cf_log_err_cs(cs, "Failed compiling 'vmps' section");
		return -1;
	}

	return 0;
}


extern rad_protocol_t proto_vmps;
rad_protocol_t proto_vmps = {
	.magic		= RLM_MODULE_INIT,
	.name		= "vmps",
	.inst_size	= sizeof(listen_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,
	.size		= vqp_packet_size,
	.bootstrap	= vqp_listen_bootstrap,
	.compile	= vqp_listen_compile,
	.parse		= common_socket_parse,
	.open		= common_socket_open,
	.recv		= vqp_socket_recv,
	.print		= common_socket_print,
	.debug		= common_packet_debug,
};
