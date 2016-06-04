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
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include "vqp.h"

static int vmps_process(REQUEST *request)
{
	DEBUG2("Doing VMPS");
	process_post_auth(0, request);
	DEBUG2("Done VMPS");

	request->reply->code = PW_CODE_ACCESS_ACCEPT;

	return 0;
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
	RAD_REQUEST_FUNP fun = NULL;
	RADCLIENT	*client;

	packet = vqp_recv(listener->fd);
	if (!packet) {
		ERROR("%s", fr_strerror());
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr,
					   packet->src_port)) == NULL) {
		fr_radius_free(&packet);
		return 0;
	}

	/*
	 *	Do new stuff.
	 */
	fun = vmps_process;

	if (!request_receive(NULL, listener, packet, client, fun)) {
		fr_radius_free(&packet);
		return 0;
	}

	return 1;
}


/*
 *	Send an authentication response packet
 */
static int vqp_socket_send(NDEBUG_UNUSED rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == vqp_socket_send);

	if (vqp_encode(request->reply, request->packet) < 0) {
		DEBUG2("Failed encoding packet: %s\n", fr_strerror());
		return -1;
	}

	return vqp_send(request->reply);
}


static int vqp_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return vqp_encode(request->reply, request->packet);
}


static int vqp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return vqp_decode(request->packet);
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

	if (unlang_compile(cs, MOD_POST_AUTH) < 0) {
		cf_log_err_cs(cs, "Failed compiling 'vmps' section");
		return -1;
	}

	return 0;
}


extern fr_protocol_t proto_vmps;
fr_protocol_t proto_vmps = {
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
	.send		= vqp_socket_send,
	.print		= common_socket_print,
	.debug		= common_packet_debug,
	.encode		= vqp_socket_encode,
	.decode		= vqp_socket_decode
};
