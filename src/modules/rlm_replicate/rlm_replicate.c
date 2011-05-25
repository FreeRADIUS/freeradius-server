/*
 * rlm_replicate.c
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  your name <your address>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>


static void cleanup(RADIUS_PACKET *packet)
{
	if (!packet) return;
	if (packet->sockfd >= 0) close(packet->sockfd);
	rad_free(&packet);
}

/*
 *	Write accounting information to this modules database.
 */
static int replicate_packet(void *instance, REQUEST *request)
{
	int rcode = RLM_MODULE_NOOP;
	VALUE_PAIR *vp;
	home_server *home;
	REALM *realm;
	home_pool_t *pool;
	RADIUS_PACKET *packet;

	instance = instance;	/* -Wunused */

	/*
	 *	Send as many packets as necessary to different
	 *	destinations.
	 */
	while (1) {
		vp = pairfind(request->config_items, PW_REPLICATE_TO_REALM);
		if (!vp) break;

		realm = realm_find2(vp->vp_strvalue);
		if (!realm) {
			RDEBUG2("ERROR: Cannot Replicate to unknown realm %s", realm);
			continue;
		}
		
		/*
		 *	We shouldn't really do this on every loop.
		 */
		switch (request->packet->code) {
		default:
			RDEBUG2("ERROR: Cannot replicate unknown packet code %d",
				request->packet->code);
			cleanup(packet);
			return RLM_MODULE_FAIL;
		
		case PW_AUTHENTICATION_REQUEST:
			pool = realm->auth_pool;
			break;
			
#ifdef WITH_ACCOUNTING
			
		case PW_ACCOUNTING_REQUEST:
			pool = realm->acct_pool;
			break;
#endif
			
#ifdef WITH_COA
		case PW_COA_REQUEST:
		case PW_DISCONNECT_REQUEST:
			pool = realm->acct_pool;
			break;
#endif
		}
		
		if (!pool) {
			RDEBUG2(" WARNING: Cancelling replication to Realm %s, as the realm is local.", realm->name);
			continue;
		}
		
		home = home_server_ldb(realm->name, pool, request);
		if (!home) {
			RDEBUG2("ERROR: Failed to find live home server for realm %s",
				realm->name);
			continue;
		}
		
		if (!packet) {
			packet = rad_alloc(1);
			if (!packet) return RLM_MODULE_FAIL;
			packet->sockfd = -1;
			packet->code = request->packet->code;
			packet->id = fr_rand() & 0xff;
			packet->vps = paircopy(request->packet->vps);

			packet->sockfd = fr_socket(&home->src_ipaddr, 0);
			if (packet->sockfd < 0) {
				RDEBUG("ERROR: Failed opening socket: %s", fr_strerror());
				cleanup(packet);
				return RLM_MODULE_FAIL;
			}
		} else {
			int i;

			for (i = 0; i < sizeof(packet->vector)) {
				packet->vector[i] = fr_rand() & 0xff;
			}

			packet->id++;
			free(packet->data);
			packet->data = NULL;
			packet->data_len = 0;
		}

		/*
		 *	(Re)-Write these.
		 */
		packet->dst_ipaddr = home->ipaddr;
		packet->dst_port = home->port;
		memset(&packet->src_ipaddr, 0, sizeof(packet->src_ipaddr));
		packet->src_port = 0;
		
		/*
		 *	Encode, sign and then send the packet.
		 */
		if (rad_send(packet, NULL, home->secret) < 0) {
			RDEBUG("ERROR: Failed replicating packet: %s",
			       fr_strerror());
			cleanup(packet);
			return RLM_MODULE_FAIL;
		}

		/*
		 *	We've sent it to at least one destination.
		 */
		rcode = RLM_MODULE_OK;
	}

	cleanup(packet);
	return rcode;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
module_t rlm_replicate = {
	RLM_MODULE_INIT,
	"replicate",
	RLM_TYPE_THREAD_SAFE,		/* type */
	NULL,				/* instantiation */
	NULL,				/* detach */
	{
		NULL,			/* authentication */
		replicate_packet,	/* authorization */
		NULL,			/* preaccounting */
		replicate_packet,	/* accounting */
		NULL,			/* checksimul */
		NULL,			/* pre-proxy */
		NULL,			/* post-proxy */
		NULL			/* post-auth */
#ifdef WITH_COA
		, replicate_packet,
		NULL
#endif
	},
};
