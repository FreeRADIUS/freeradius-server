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

static void vmps_running(REQUEST *request, fr_state_action_t action)
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
		if (vqp_decode(request->packet) < 0) {
			RDEBUG("Failed decoding VMPS packet: %s", fr_strerror());
			goto done;
		}

		request->server = request->listener->server;
		request->server_cs = request->listener->server_cs;
		request->component = "vmps";

		vp = fr_pair_find_by_num(request->packet->vps, 0, 0x2b00, TAG_ANY);
		if (!vp) {
			REDEBUG("Failed to find &request:VMPS-Packet-Type");
			goto done;
		}

		dv = fr_dict_enum_by_da(NULL, vp->da, vp->vp_uint32);
		if (!dv) {
			REDEBUG("Failed to find value for &request:VMPS-Packet-Type");
			goto done;
		}

		unlang = cf_subsection_find_name2(request->server_cs, "recv", dv->name);
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "recv", "*");
		if (!unlang) {
			RPEDEBUG("Failed to find 'recv' section");
			goto done;
		}

		RDEBUG("Running recv %s from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
		rcode = unlang_interpret(request, unlang, RLM_MODULE_NOOP);

		if (request->master_state == REQUEST_STOP_PROCESSING) goto done;

		vp = fr_pair_find_by_num(request->reply->vps, 0, 0x2b00, TAG_ANY);
		if (vp) {
			da = vp->da;

			if (vp->vp_uint32 == 256) {
				request->reply->code = 0;
			} else {
				request->reply->code = vp->vp_uint32;
			}

		} else if (rcode != RLM_MODULE_HANDLED) {
			da = fr_dict_attr_by_num(NULL, 0, 0x2b00);
			rad_assert(da != NULL);

			if (request->packet->code == 1) {
				request->reply->code = 2;

			} else if (request->packet->code == 3) {
				request->reply->code = 4;
			}
		}

		dv = fr_dict_enum_by_da(NULL, da, request->reply->code);
		unlang = NULL;
		if (dv) {
			unlang = cf_subsection_find_name2(request->server_cs, "send", dv->name);
		}
		if (!unlang) unlang = cf_subsection_find_name2(request->server_cs, "send", "*");

		if (unlang) {
			RDEBUG("Running send %s from file %s", cf_section_name2(unlang), cf_section_filename(unlang));
			(void) unlang_interpret(request, unlang, RLM_MODULE_NOOP);

			if (request->master_state == REQUEST_STOP_PROCESSING) goto done;
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
 *	digraph vmps_queued {
 *		vmps_queued -> done [ label = "TIMER >= max_request_time" ];
 *		vmps_queued -> running [ label = "RUNNING" ];
 *	}
 *  \enddot
 */
static void vmps_queued(REQUEST *request, fr_state_action_t action)
{
	VERIFY_REQUEST(request);

	TRACE_STATE_MACHINE;

	switch (action) {
	case FR_ACTION_RUN:
		request->process = vmps_running;
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
static int vqp_socket_recv(rad_listen_t *listener)
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

	request->process = vmps_queued;
	request_enqueue(request);

	return 1;
}


static int vqp_compile_section(CONF_SECTION *server_cs, char const *name1, char const *name2)
{
	CONF_SECTION *cs;

	cs = cf_subsection_find_name2(server_cs, name1, name2);
	if (!cs) return 0;

	cf_log_module(cs, "Loading %s %s {...}", name1, name2);

	if (unlang_compile(cs, MOD_POST_AUTH) < 0) {
		cf_log_err_cs(cs, "Failed compiling '%s %s { ... }' section", name1, name2);
		return -1;
	}

	return 1;
}


/*
 *	Ensure that the "vmps" section is compiled.
 */
static int vqp_listen_compile(CONF_SECTION *server_cs, UNUSED CONF_SECTION *listen_cs)
{
	int rcode;

	rcode = vqp_compile_section(server_cs, "recv", "VMPS-Join-Request");
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		rcode = vqp_compile_section(server_cs, "recv", "*");
		if (rcode < 0) return rcode;
	}

	if (rcode == 0) {
		cf_log_err_cs(server_cs, "Failed finding 'recv VMPS-Join-Request { ... }' section of virtual server %s",
			      cf_section_name2(server_cs));
		return -1;
	}

	rcode = vqp_compile_section(server_cs, "recv", "VMPS-Reconfirm-Request");
	if (rcode < 0) return rcode;

	rcode = vqp_compile_section(server_cs, "send", "VMPS-Join-Response");
	if (rcode < 0) return rcode;

	if (rcode == 0) {
		rcode = vqp_compile_section(server_cs, "send", "*");
		if (rcode < 0) return rcode;
	} else {
		rcode = vqp_compile_section(server_cs, "send", "VMPS-Reconfirm-Response");
		if (rcode < 0) return rcode;
	}

	return 0;
}

static int vmps_load(void)
{
	return fr_dict_read(main_config.dict, main_config.dictionary_dir, "dictionary.vqp");
}


extern rad_protocol_t proto_vmps;
rad_protocol_t proto_vmps = {
	.magic		= RLM_MODULE_INIT,
	.name		= "vmps",
	.inst_size	= sizeof(listen_socket_t),
	.transports	= TRANSPORT_UDP,
	.tls		= false,

	.load		= vmps_load,
	.compile	= vqp_listen_compile,
	.parse		= common_socket_parse,
	.open		= common_socket_open,
	.recv		= vqp_socket_recv,
	.print		= common_socket_print,
	.debug		= common_packet_debug,
};
