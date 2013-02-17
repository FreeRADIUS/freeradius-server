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
#include <freeradius-devel/rad_assert.h>


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
	VALUE_PAIR *vp, *last;
	home_server *home;
	REALM *realm;
	home_pool_t *pool;
	RADIUS_PACKET *packet = NULL;

	instance = instance;	/* -Wunused */
	last = request->config_items;
	rad_assert(request->proxy == NULL);

	/*
	 *	Send as many packets as necessary to different
	 *	destinations.
	 */
	while (1) {
		vp = pairfind(last, PW_REPLICATE_TO_REALM);
		if (!vp) break;

		last = vp->next;

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
			pool = NULL;
			RDEBUG2("ERROR: Cannot replicate unknown packet code %d",
				request->packet->code);
			cleanup(packet);
			rcode = RLM_MODULE_FAIL;
			break;
		
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
			if (!packet) {
				rcode = RLM_MODULE_FAIL;
				break;
			}
			packet->sockfd = -1;
			packet->code = request->packet->code;
			packet->id = fr_rand() & 0xff;

			packet->sockfd = fr_socket(&home->src_ipaddr, 0);
			if (packet->sockfd < 0) {
				RDEBUG("ERROR: Failed opening socket: %s", fr_strerror());
				cleanup(packet);
				rcode = RLM_MODULE_FAIL;
				break;
			}

			packet->vps = paircopy(request->packet->vps);
			if (!packet->vps) {
				RDEBUG("ERROR: Out of memory!");
				cleanup(packet);
				rcode = RLM_MODULE_FAIL;
				break;
			}

			/*
			 *	For CHAP, create the CHAP-Challenge if
			 *	it doesn't exist.
			 */
			if ((request->packet->code == PW_AUTHENTICATION_REQUEST) &&
			    (pairfind(request->packet->vps, PW_CHAP_PASSWORD) != NULL) &&
			    (pairfind(request->packet->vps, PW_CHAP_CHALLENGE) == NULL)) {
				vp = radius_paircreate(request, &packet->vps,
						       PW_CHAP_CHALLENGE,
						       PW_TYPE_OCTETS);
				vp->length = AUTH_VECTOR_LEN;
				memcpy(vp->vp_strvalue, request->packet->vector,
				       AUTH_VECTOR_LEN);
			}
		} else {
			size_t i;

			for (i = 0; i < sizeof(packet->vector); i++) {
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
		RDEBUG("Replicating packet to Realm %s", realm->name);
		if (rad_send(packet, NULL, home->secret) < 0) {
			RDEBUG("ERROR: Failed replicating packet: %s",
			       fr_strerror());
			cleanup(packet);
			rcode = RLM_MODULE_FAIL;
			break;
		}

		/*
		 *	We've sent it to at least one destination.
		 */
		rcode = RLM_MODULE_OK;
	}

	cleanup(packet);
	rad_free(&request->proxy);

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
