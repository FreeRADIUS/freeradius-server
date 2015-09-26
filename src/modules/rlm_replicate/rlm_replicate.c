/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_replicate.c
 * @brief Duplicate RADIUS requests.
 *
 * @copyright 2011-2013  The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>

#ifdef WITH_PROXY

/** Allocate a request packet
 *
 * This is done once per request with the same packet being sent to multiple realms.
 */
static rlm_rcode_t rlm_replicate_alloc(RADIUS_PACKET **out, REQUEST *request, pair_lists_t list, PW_CODE code)
{
	rlm_rcode_t rcode = RLM_MODULE_OK;
	RADIUS_PACKET *packet = NULL;
	VALUE_PAIR *vp, **vps;

	*out = NULL;

	packet = rad_alloc(request, true);
	if (!packet) {
		return RLM_MODULE_FAIL;
	}
	packet->code = code;

	/*
	 *	Figure out which list in the request were replicating
	 */
	vps = radius_list(request, list);
	if (!vps) {
		RWDEBUG("List '%s' doesn't exist for this packet", fr_int2str(pair_lists, list, "<INVALID>"));
		rcode = RLM_MODULE_INVALID;
		goto error;
	}

	/*
	 *	Don't assume the list actually contains any attributes.
	 */
	if (*vps) {
		packet->vps = fr_pair_list_copy(packet, *vps);
		if (!packet->vps) {
			rcode = RLM_MODULE_FAIL;
			goto error;
		}
	}

	/*
	 *	For CHAP, create the CHAP-Challenge if it doesn't exist.
	 */
	if ((code == PW_CODE_ACCESS_REQUEST) &&
	    (fr_pair_find_by_num(request->packet->vps, PW_CHAP_PASSWORD, 0, TAG_ANY) != NULL) &&
	    (fr_pair_find_by_num(request->packet->vps, PW_CHAP_CHALLENGE, 0, TAG_ANY) == NULL)) {
		vp = radius_pair_create(packet, &packet->vps, PW_CHAP_CHALLENGE, 0);
		fr_pair_value_memcpy(vp, request->packet->vector, AUTH_VECTOR_LEN);
	}

	*out = packet;
	return rcode;

error:
	talloc_free(packet);
	return rcode;
}

/** Copy packet to multiple servers
 *
 * Create a duplicate of the packet and send it to a list of realms
 * defined by the presence of the Replicate-To-Realm VP in the control
 * list of the current request.
 *
 * This is pretty hacky and is 100% fire and forget. If you're looking
 * to forward authentication requests to multiple realms and process
 * the responses, this function will not allow you to do that.
 *
 * @param[in] instance 	of this module.
 * @param[in] request 	The current request.
 * @param[in] list	of attributes to copy to the duplicate packet.
 * @param[in] code	to write into the code field of the duplicate packet.
 * @return
 *	- #RLM_MODULE_FAIL on error.
 *	- #RLM_MODULE_INVALID if list does not exist.
 *	- #RLM_MODULE_NOOP if no replications succeeded.
 *	- #RLM_MODULE_OK if successful.
 */
static rlm_rcode_t replicate_packet(UNUSED void *instance, REQUEST *request, pair_lists_t list, PW_CODE code)
{
	int rcode;
	bool pass1 = true;

	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	RADIUS_PACKET *packet = NULL;

	rcode = rlm_replicate_alloc(&packet, request, list, code);
	if (rcode != RLM_MODULE_OK) {
		return rcode;
	}

	/*
	 *	Send as many packets as necessary to different destinations.
	 */
	fr_cursor_init(&cursor, &request->config);
	while ((vp = fr_cursor_next_by_num(&cursor, PW_REPLICATE_TO_REALM, 0, TAG_ANY))) {
		home_server_t *home;
		REALM *realm;
		home_pool_t *pool;

		realm = realm_find2(vp->vp_strvalue);
		if (!realm) {
			REDEBUG2("Cannot Replicate to unknown realm \"%s\"", vp->vp_strvalue);
			continue;
		}

		/*
		 *	We shouldn't really do this on every loop.
		 */
		switch (request->packet->code) {
		default:
			REDEBUG2("Cannot replicate unknown packet code %d", request->packet->code);
			rcode = RLM_MODULE_FAIL;
			goto done;

		case PW_CODE_ACCESS_REQUEST:
			pool = realm->auth_pool;
			break;

#ifdef WITH_ACCOUNTING

		case PW_CODE_ACCOUNTING_REQUEST:
			pool = realm->acct_pool;
			break;
#endif

#ifdef WITH_COA
		case PW_CODE_COA_REQUEST:
		case PW_CODE_DISCONNECT_REQUEST:
			pool = realm->coa_pool;
			break;
#endif
		}

		if (!pool) {
			RWDEBUG2("Cancelling replication to Realm %s, as the realm is local", realm->name);
			continue;
		}

		home = home_server_ldb(realm->name, pool, request);
		if (!home) {
			REDEBUG2("Failed to find live home server for realm %s", realm->name);
			continue;
		}

		/*
		 *	For replication to multiple servers we re-use the packet
		 *	we built here.
		 */
		if (pass1) {
			packet->id = fr_rand() & 0xff;
			packet->sockfd = fr_socket(&home->src_ipaddr, 0);
			if (packet->sockfd < 0) {
				REDEBUG("Failed opening socket: %s", fr_strerror());
				rcode = RLM_MODULE_FAIL;
				goto done;
			}
			pass1 = false;
		} else {
			size_t i;

			for (i = 0; i < sizeof(packet->vector); i++) {
				packet->vector[i] = fr_rand() & 0xff;
			}

			packet->id++;
			TALLOC_FREE(packet->data);
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
		RDEBUG("Replicating list '%s' to Realm '%s'", fr_int2str(pair_lists, list, "<INVALID>"), realm->name);
		if (rad_send(packet, NULL, home->secret) < 0) {
			REDEBUG("Failed replicating packet: %s", fr_strerror());
			rcode = RLM_MODULE_FAIL;
			goto done;
		}

		/*
		 *	We've sent it to at least one destination.
		 */
		rcode = RLM_MODULE_OK;
	}

	done:

	talloc_free(packet);
	return rcode;
}
#else
static rlm_rcode_t replicate_packet(UNUSED void *instance,
				    UNUSED REQUEST *request,
				    UNUSED pair_lists_t list,
				    UNUSED unsigned int code)
{
	RDEBUG("Replication is unsupported in this build");
	return RLM_MODULE_FAIL;
}
#endif

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(void *instance, REQUEST *request)
{
	return replicate_packet(instance, request, PAIR_LIST_REQUEST, request->packet->code);
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(void *instance, REQUEST *request)
{
	return replicate_packet(instance, request, PAIR_LIST_REQUEST, request->packet->code);
}

static rlm_rcode_t CC_HINT(nonnull) mod_preaccounting(void *instance, REQUEST *request)
{
	return replicate_packet(instance, request, PAIR_LIST_REQUEST, request->packet->code);
}

#ifdef WITH_PROXY
static rlm_rcode_t CC_HINT(nonnull) mod_pre_proxy(void *instance, REQUEST *request)
{
	return replicate_packet(instance, request, PAIR_LIST_PROXY_REQUEST, request->proxy->code);
}
#endif

#ifdef WITH_COA
static rlm_rcode_t CC_HINT(nonnull) mod_recv_coa(void *instance, REQUEST *request)
{
	return replicate_packet(instance, request, PAIR_LIST_REQUEST, request->packet->code);
}
#endif

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_t rlm_replicate;
module_t rlm_replicate = {
	.magic		= RLM_MODULE_INIT,
	.name		= "replicate",
	.type		= RLM_TYPE_THREAD_SAFE,
	.methods = {
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_PREACCT]		= mod_preaccounting,
#ifdef WITH_PROXY
		[MOD_PRE_PROXY]		= mod_pre_proxy,
#endif
#ifdef WITH_COA
		[MOD_RECV_COA]		= mod_recv_coa
#endif
	},
};
