/*
 * stats.c	Internal statistics handling.
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
 * @copyright 2008 The FreeRADIUS server project
 * @copyright 2008 Alan DeKok (aland@deployingradius.com)
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>

#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/time.h>
#include <freeradius-devel/radius/defs.h>


#ifdef WITH_STATS

#define EMA_SCALE (100)
#define F_EMA_SCALE (1000000)

static fr_time_t start_time;
static fr_time_t hup_time;

#define FR_STATS_INIT { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 	\
				 { 0, 0, 0, 0, 0, 0, 0, 0 }}

fr_stats_t radius_auth_stats = FR_STATS_INIT;
#ifdef WITH_ACCOUNTING
fr_stats_t radius_acct_stats = FR_STATS_INIT;
#endif
#ifdef WITH_COA
fr_stats_t radius_coa_stats = FR_STATS_INIT;
fr_stats_t radius_dsc_stats = FR_STATS_INIT;
#endif

#ifdef WITH_PROXY
fr_stats_t proxy_auth_stats = FR_STATS_INIT;
#ifdef WITH_ACCOUNTING
fr_stats_t proxy_acct_stats = FR_STATS_INIT;
#endif
#ifdef WITH_COA
fr_stats_t proxy_coa_stats = FR_STATS_INIT;
fr_stats_t proxy_dsc_stats = FR_STATS_INIT;
#endif
#endif

void request_stats_final(REQUEST *request)
{
	if (request->master_state == REQUEST_COUNTED) return;

	if (!request->listener) return;
	if (!request->client) return;
	if (!request->packet) return;

	if ((request->listener->type != RAD_LISTEN_NONE) &&
#ifdef WITH_ACCOUNTING
	    (request->listener->type != RAD_LISTEN_ACCT) &&
#endif
#ifdef WITH_COA
	    (request->listener->type != RAD_LISTEN_COA) &&
#endif
	    (request->listener->type != RAD_LISTEN_AUTH)) return;

	/* don't count statistic requests */
	if (request->packet->code == FR_CODE_STATUS_SERVER)
		return;

#undef INC_AUTH
#define INC_AUTH(_x) radius_auth_stats._x++;request->listener->stats._x++;request->client->auth._x++;

#undef INC_ACCT
#ifdef WITH_ACCOUNTING
#define INC_ACCT(_x) radius_acct_stats._x++;request->listener->stats._x++;request->client->acct._x++
#else
#define INC_ACCT(_x)
#endif

#undef INC_COA
#ifdef WITH_COA
#define INC_COA(_x) radius_coa_stats._x++;request->listener->stats._x++;request->client->coa._x++
#else
#define INC_COA(_x)
#endif

#undef INC_DSC
#ifdef WITH_DSC
#define INC_DSC(_x) radius_dsc_stats._x++;request->listener->stats._x++;request->client->dsc._x++
#else
#define INC_DSC(_x)
#endif

	/*
	 *	Update the statistics.
	 *
	 *	Note that we do NOT do this in a child thread.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function, which makes it thread-safe.
	 */
	if (request->reply && (request->packet->code != FR_CODE_STATUS_SERVER)) switch (request->reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
		INC_AUTH(total_access_accepts);

		auth_stats:
		INC_AUTH(total_responses);

		/*
		 *	FIXME: Do the time calculations once...
		 */
		fr_stats_bins(&radius_auth_stats,
			      request->packet->timestamp,
			      request->reply->timestamp);
		fr_stats_bins(&request->client->auth,
			      request->packet->timestamp,
			      request->reply->timestamp);
		fr_stats_bins(&request->listener->stats,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;

	case FR_CODE_ACCESS_REJECT:
		INC_AUTH(total_access_rejects);
		goto auth_stats;

	case FR_CODE_ACCESS_CHALLENGE:
		INC_AUTH(total_access_challenges);
		goto auth_stats;

#ifdef WITH_ACCOUNTING
	case FR_CODE_ACCOUNTING_RESPONSE:
		INC_ACCT(total_responses);
		fr_stats_bins(&radius_acct_stats,
			      request->packet->timestamp,
			      request->reply->timestamp);
		fr_stats_bins(&request->client->acct,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;
#endif

#ifdef WITH_COA
	case FR_CODE_COA_ACK:
		INC_COA(total_access_accepts);
	  coa_stats:
		INC_COA(total_responses);
		fr_stats_bins(&request->client->coa,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;

	case FR_CODE_COA_NAK:
		INC_COA(total_access_rejects);
		goto coa_stats;

	case FR_CODE_DISCONNECT_ACK:
		INC_DSC(total_access_accepts);
	  dsc_stats:
		INC_DSC(total_responses);
		fr_stats_bins(&request->client->dsc,
			      request->packet->timestamp,
			      request->reply->timestamp);
		break;

	case FR_CODE_DISCONNECT_NAK:
		INC_DSC(total_access_rejects);
		goto dsc_stats;
#endif

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		switch (request->packet->code) {
		case FR_CODE_ACCESS_REQUEST:
			if (request->reply->id == -1) {
				INC_AUTH(total_bad_authenticators);
			} else {
				INC_AUTH(total_packets_dropped);
			}
			break;


#ifdef WITH_ACCOUNTING
		case FR_CODE_ACCOUNTING_REQUEST:
			if (request->reply->id == -1) {
				INC_ACCT(total_bad_authenticators);
			} else {
				INC_ACCT(total_packets_dropped);
			}
			break;
#endif

#ifdef WITH_COA
		case FR_CODE_COA_REQUEST:
			if (request->reply->id == -1) {
				INC_COA(total_bad_authenticators);
			} else {
				INC_COA(total_packets_dropped);
			}
			break;

		case FR_CODE_DISCONNECT_REQUEST:
			if (request->reply->id == -1) {
				INC_DSC(total_bad_authenticators);
			} else {
				INC_DSC(total_packets_dropped);
			}
			break;
#endif

			default:
				break;
		}
		break;

	default:
		break;
	}

#ifdef WITH_PROXY
#if 0
	if (!request->proxy || !request->proxy->home_server) goto done;	/* simplifies formatting */
#endif
	switch (request->proxy->packet->code) {
	case FR_CODE_ACCESS_REQUEST:
#if 0
		proxy_auth_stats.total_requests += request->proxy->packet->count;
		request->proxy->home_server->stats.total_requests += request->proxy->packet->count;
#endif
		break;

#ifdef WITH_ACCOUNTING
	case FR_CODE_ACCOUNTING_REQUEST:
#if 0
		proxy_acct_stats.total_requests += request->proxy->packet->count;
		request->proxy->home_server->stats.total_requests += request->proxy->packet->count;
#endif
		break;
#endif

#ifdef WITH_COA
	case FR_CODE_COA_REQUEST:
#if 0
		proxy_coa_stats.total_requests += request->proxy->packet->count;
		request->proxy->home_server->stats.total_requests += request->proxy->packet->count;
#endif
		break;

	case FR_CODE_DISCONNECT_REQUEST:
#if 0
		proxy_dsc_stats.total_requests += request->proxy->packet->count;
		request->proxy->home_server->stats.total_requests += request->proxy->packet->count;
#endif
		break;
#endif

	default:
		break;
	}

	if (!request->proxy->reply) goto done;	/* simplifies formatting */

#undef INC
#if 0
#define INC(_x) proxy_auth_stats._x += request->proxy->reply->count; request->proxy->home_server->stats._x += request->proxy->reply->count;
#endif
	switch (request->proxy->reply->code) {
	case FR_CODE_ACCESS_ACCEPT:
#if 0
		INC(total_access_accepts);
#endif
	proxy_stats:
#if 0
		INC(total_responses);

		fr_stats_bins(&proxy_auth_stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
		fr_stats_bins(&request->proxy->home_server->stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
#endif
		break;

	case FR_CODE_ACCESS_REJECT:
#if 0
		INC(total_access_rejects);
#endif
		goto proxy_stats;

	case FR_CODE_ACCESS_CHALLENGE:
#if 0
		INC(total_access_challenges);
#endif
		goto proxy_stats;

#ifdef WITH_ACCOUNTING
	case FR_CODE_ACCOUNTING_RESPONSE:
#if 0
		proxy_acct_stats.total_responses++;
		request->proxy->home_server->stats.total_responses++;
		fr_stats_bins(&proxy_acct_stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
		fr_stats_bins(&request->proxy->home_server->stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
#endif
		break;
#endif

#ifdef WITH_COA
	case FR_CODE_COA_ACK:
	case FR_CODE_COA_NAK:
#if 0
		proxy_coa_stats.total_responses++;
		request->proxy->home_server->stats.total_responses++;
		fr_stats_bins(&proxy_coa_stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
		fr_stats_bins(&request->proxy->home_server->stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
#endif
		break;

	case FR_CODE_DISCONNECT_ACK:
	case FR_CODE_DISCONNECT_NAK:
#if 0
		proxy_dsc_stats.total_responses++;
		request->proxy->home_server->stats.total_responses++;
		fr_stats_bins(&proxy_dsc_stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
		fr_stats_bins(&request->proxy->home_server->stats,
			      &request->proxy->packet->timestamp,
			      &request->proxy->reply->timestamp);
#endif
		break;
#endif

	default:
#if 0
		proxy_auth_stats.total_unknown_types++;
		request->proxy->home_server->stats.total_unknown_types++;
#endif
		break;
	}

 done:
#endif /* WITH_PROXY */

	request->master_state = REQUEST_COUNTED;
}

#if 0				/* OLD LISTENERS */
typedef struct {
	int	attribute;
	size_t	offset;
} fr_stats2vp;

/*
 *	Authentication
 */
static fr_stats2vp authvp[] = {
	{ FR_FREERADIUS_TOTAL_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ FR_FREERADIUS_TOTAL_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ FR_FREERADIUS_TOTAL_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ FR_FREERADIUS_TOTAL_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};


#ifdef WITH_PROXY
/*
 *	Proxied authentication requests.
 */
static fr_stats2vp proxy_authvp[] = {
	{ FR_FREERADIUS_TOTAL_PROXY_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_PROXY_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif


#ifdef WITH_ACCOUNTING
/*
 *	Accounting
 */
static fr_stats2vp acctvp[] = {
	{ FR_FREERADIUS_TOTAL_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_PROXY
static fr_stats2vp proxy_acctvp[] = {
	{ FR_FREERADIUS_TOTAL_PROXY_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_PROXY_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif
#endif

static fr_stats2vp client_authvp[] = {
	{ FR_FREERADIUS_TOTAL_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ FR_FREERADIUS_TOTAL_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ FR_FREERADIUS_TOTAL_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ FR_FREERADIUS_TOTAL_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_ACCOUNTING
static fr_stats2vp client_acctvp[] = {
	{ FR_FREERADIUS_TOTAL_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ FR_FREERADIUS_TOTAL_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ FR_FREERADIUS_TOTAL_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ FR_FREERADIUS_TOTAL_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ FR_FREERADIUS_TOTAL_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ FR_FREERADIUS_TOTAL_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ FR_FREERADIUS_TOTAL_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif

#define ADD_TO_REPLY(_attr, _vendor) \
do { \
	MEM(vp = fr_pair_afrom_num(request->reply, _vendor, _attr)); \
	fr_pair_add(&request->reply->vps, vp); \
} while (0)

static fr_dict_attr_t const *freeradius_vendor_root;

static void request_stats_addvp(REQUEST *request,
				fr_stats2vp *table, fr_stats_t *stats)
{
	int i;
	fr_uint_t counter;
	VALUE_PAIR *vp;

	for (i = 0; table[i].attribute != 0; i++) {
		vp = ADD_TO_REPLY(table[i].attribute, VENDORPEC_FREERADIUS);
		if (!vp) continue;

		counter = *(fr_uint_t *) (((uint8_t *) stats) + table[i].offset);
		vp->vp_uint32 = counter;
	}
}

void request_stats_reply(REQUEST *request)
{
	VALUE_PAIR *flag, *vp;

	/*
	 *	Statistics are available ONLY on a "status" port.
	 */
	fr_assert(request->packet->code == FR_CODE_STATUS_SERVER);
	fr_assert(request->listener->type == RAD_LISTEN_NONE);

	flag = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS, FR_FREERADIUS_STATISTICS_TYPE, TAG_ANY);
	if (!flag || (flag->vp_uint32 == 0)) return;

	/*
	 *	Authentication.
	 */
	if (((flag->vp_uint32 & 0x01) != 0) &&
	    ((flag->vp_uint32 & 0xc0) == 0)) {
		request_stats_addvp(request, authvp, &radius_auth_stats);
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	Accounting
	 */
	if (((flag->vp_uint32 & 0x02) != 0) &&
	    ((flag->vp_uint32 & 0xc0) == 0)) {
		request_stats_addvp(request, acctvp, &radius_acct_stats);
	}
#endif

#ifdef WITH_PROXY
	/*
	 *	Proxied authentication requests.
	 */
	if (((flag->vp_uint32 & 0x04) != 0) &&
	    ((flag->vp_uint32 & 0x20) == 0)) {
		request_stats_addvp(request, proxy_authvp, &proxy_auth_stats);
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	Proxied accounting requests.
	 */
	if (((flag->vp_uint32 & 0x08) != 0) &&
	    ((flag->vp_uint32 & 0x20) == 0)) {
		request_stats_addvp(request, proxy_acctvp, &proxy_acct_stats);
	}
#endif
#endif

	/*
	 *	Internal server statistics
	 */
	if ((flag->vp_uint32 & 0x10) != 0) {
		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_START_TIME, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = start_time;
		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_HUP_TIME, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = hup_time;
	}

	/*
	 *	For a particular client.
	 */
	if ((flag->vp_uint32 & 0x20) != 0) {
		fr_ipaddr_t ipaddr;
		VALUE_PAIR *server_ip, *server_port = NULL;
		RADCLIENT *client = NULL;
		RADCLIENT_LIST *cl = NULL;

		/*
		 *	See if we need to look up the client by server
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						FR_FREERADIUS_STATS_SERVER_IP_ADDRESS, TAG_ANY);
		if (server_ip) {
			server_port = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
							  FR_FREERADIUS_STATS_SERVER_PORT, TAG_ANY);

			if (server_port) {
				ipaddr.af = AF_INET;
				ipaddr.addr.v4.s_addr = server_ip->vp_ipv4addr;
				cl = listener_find_client_list(&ipaddr, server_port->vp_uint32, IPPROTO_UDP);

				/*
				 *	Not found: don't do anything
				 */
				if (!cl) return;
			}
		}


		vp = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
					 FR_FREERADIUS_STATS_CLIENT_IP_ADDRESS, TAG_ANY);
		if (vp) {
			memset(&ipaddr, 0, sizeof(ipaddr));
			ipaddr.af = AF_INET;
			ipaddr.addr.v4.s_addr = vp->vp_ipv4addr;
			client = client_find(cl, &ipaddr, IPPROTO_UDP);
			if (!client) {
				client = client_find(cl, &ipaddr, IPPROTO_TCP);
			}

			/*
			 *	Else look it up by number.
			 */
		} else if ((vp = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						     FR_FREERADIUS_STATS_CLIENT_NUMBER, TAG_ANY)) != NULL) {
			client = client_findbynumber(cl, vp->vp_uint32);
		}

		if (client) {
			/*
			 *	If found, echo it back, along with
			 *	the requested statistics.
			 */
			fr_pair_add(&request->reply->vps, fr_pair_copy(request->reply, vp));

			/*
			 *	When retrieving client by number, also
			 *	echo back it's IP address.
			 */
			if ((vp->vp_type == FR_TYPE_UINT32) &&
			    (client->ipaddr.af == AF_INET)) {
				vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_CLIENT_IP_ADDRESS, VENDORPEC_FREERADIUS);
				if (vp) {
					vp->vp_ipv4addr = client->ipaddr.addr.v4.s_addr;
				}

				if (client->ipaddr.prefix != 32) {
					vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_CLIENT_NETMASK, VENDORPEC_FREERADIUS);
					if (vp) {
						vp->vp_uint32 = client->ipaddr.prefix;
					}
				}
			}

			if (server_ip) {
				fr_pair_add(&request->reply->vps,
					fr_pair_copy(request->reply, server_ip));
			}
			if (server_port) {
				fr_pair_add(&request->reply->vps,
					fr_pair_copy(request->reply, server_port));
			}

			if ((flag->vp_uint32 & 0x01) != 0) {
				request_stats_addvp(request, client_authvp,
						    &client->auth);
			}
#ifdef WITH_ACCOUNTING
			if ((flag->vp_uint32 & 0x02) != 0) {
				request_stats_addvp(request, client_acctvp,
						    &client->acct);
			}
#endif
		} /* else client wasn't found, don't echo it back */
	}

	/*
	 *	For a particular "listen" socket.
	 */
	if (((flag->vp_uint32 & 0x40) != 0) &&
	    ((flag->vp_uint32 & 0x03) != 0)) {
		rad_listen_t *this;
		VALUE_PAIR *server_ip, *server_port;
		fr_ipaddr_t ipaddr;

		/*
		 *	See if we need to look up the server by socket
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						FR_FREERADIUS_STATS_SERVER_IP_ADDRESS, TAG_ANY);
		if (!server_ip) return;

		server_port = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						  FR_FREERADIUS_STATS_SERVER_PORT, TAG_ANY);
		if (!server_port) return;

		ipaddr.af = AF_INET;
		ipaddr.addr.v4.s_addr = server_ip->vp_ipv4addr;
		this = listener_find_byipaddr(&ipaddr,
					      server_port->vp_uint32,
					      IPPROTO_UDP);

		/*
		 *	Not found: don't do anything
		 */
		if (!this) return;

		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_ip));
		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_port));

		if (((flag->vp_uint32 & 0x01) != 0) &&
		    ((request->listener->type == RAD_LISTEN_AUTH) ||
		     (request->listener->type == RAD_LISTEN_NONE))) {
			request_stats_addvp(request, authvp, &this->stats);
		}

#ifdef WITH_ACCOUNTING
		if (((flag->vp_uint32 & 0x02) != 0) &&
		    ((request->listener->type == RAD_LISTEN_ACCT) ||
		     (request->listener->type == RAD_LISTEN_NONE))) {
			request_stats_addvp(request, acctvp, &this->stats);
		}
#endif
	}

#ifdef WITH_PROXY
	/*
	 *	Home servers.
	 */
	if (((flag->vp_uint32 & 0x80) != 0) &&
	    ((flag->vp_uint32 & 0x03) != 0)) {
		home_server_t *home;
		VALUE_PAIR *server_ip, *server_port;

		/*
		 *	See if we need to look up the server by socket
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						FR_FREERADIUS_STATS_SERVER_IP_ADDRESS, TAG_ANY);
		if (!server_ip) return;

		server_port = fr_pair_find_by_num(request->packet->vps, VENDORPEC_FREERADIUS,
						  FR_FREERADIUS_STATS_SERVER_PORT, TAG_ANY);
		if (!server_port) return;

		/*
		 *	Not found: don't do anything
		 */
		home = NULL;
		if (!home) return;

		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_ip));
		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_port));

		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_SERVER_OUTSTANDING_REQUESTS, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_uint32 = home->currently_outstanding;

		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_SERVER_STATE, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_uint32 = home->state;

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->revive_time.tv_sec != 0)) {
			vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_SERVER_TIME_OF_LIFE, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_date = fr_time_from_timeval(&home->revive_time);
		}

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->ema.window > 0)) {
				vp = ADD_TO_REPLY(FR_FREERADIUS_SERVER_EMA_WINDOW, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_uint32 = home->ema.window;
				vp = ADD_TO_REPLY(FR_FREERADIUS_SERVER_EMA_USEC_WINDOW_1, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_uint32 = home->ema.ema1 / EMA_SCALE;
				vp = ADD_TO_REPLY(FR_FREERADIUS_SERVER_EMA_USEC_WINDOW_10, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_uint32 = home->ema.ema10 / EMA_SCALE;

		}

		if (home->state == HOME_STATE_IS_DEAD) {
			vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_SERVER_TIME_OF_DEATH, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_date = fr_time_from_timeval(&(struct timeval) {.tv_sec = home->zombie_period_start.tv_sec + home->zombie_period});
		}

		/*
		 *	Show more information...
		 *
		 *	FIXME: do this for clients, too!
		 */
		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_LAST_PACKET_RECV, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = fr_time_from_timeval(&(struct timeval) {.tv_sec = home->last_packet_recv});

		vp = ADD_TO_REPLY(FR_FREERADIUS_STATS_LAST_PACKET_SENT, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = fr_time_from_timeval(&(struct timeval) {.tv_sec = home->last_packet_sent});

		if (((flag->vp_uint32 & 0x01) != 0) &&
		    (home->type == HOME_TYPE_AUTH)) {
			request_stats_addvp(request, proxy_authvp,
					    &home->stats);
		}

#ifdef WITH_ACCOUNTING
		if (((flag->vp_uint32 & 0x02) != 0) &&
		    (home->type == HOME_TYPE_ACCT)) {
			request_stats_addvp(request, proxy_acctvp,
					    &home->stats);
		}
#endif
	}
#endif	/* WITH_PROXY */
}
#endif	/* OLD LISTENERS */

void radius_stats_init(int flag)
{
	if (!flag) {
		start_time = fr_time();
		hup_time = start_time; /* it's just nicer this way */
	} else {
		hup_time = fr_time();
	}
}

void radius_stats_ema(fr_stats_ema_t *ema, fr_time_t start, fr_time_t end)
{
	uint64_t	tdiff;
#ifdef WITH_STATS_DEBUG
	static int	n = 0;
#endif
	if (ema->window == 0) return;

	fr_assert(start <= end);

	/*
	 *	Initialize it.
	 */
	if (ema->f1 == 0) {
		if (ema->window > 10000) ema->window = 10000;

		ema->f1 =  (2 * F_EMA_SCALE) / (ema->window + 1);
		ema->f10 = (2 * F_EMA_SCALE) / ((10 * ema->window) + 1);
	}

	tdiff = fr_time_delta_to_usec(start);
	tdiff -= fr_time_delta_to_usec(end);
	tdiff *= EMA_SCALE;

	if (ema->ema1 == 0) {
		ema->ema1 = tdiff;
		ema->ema10 = tdiff;
	} else {
		int diff;

		diff = ema->f1 * (tdiff - ema->ema1);
		ema->ema1 += (diff / 1000000);

		diff = ema->f10 * (tdiff - ema->ema10);
		ema->ema10 += (diff / 1000000);
	}


#ifdef WITH_STATS_DEBUG
	DEBUG("time %d %d.%06d\t%d.%06d\t%d.%06d\n",
	      n, tdiff / PREC, (tdiff / EMA_SCALE) % USEC,
	      ema->ema1 / PREC, (ema->ema1 / EMA_SCALE) % USEC,
	      ema->ema10 / PREC, (ema->ema10 / EMA_SCALE) % USEC);
	n++;
#endif
}

/** Sort latency times into bins
 *
 * This solves the problem of attempting to keep min/max/avg latencies, whilst
 * not knowing what the polling frequency will be.
 *
 * @param[out] stats Holding monotonically increasing stats bins.
 * @param[in] start of the request.
 * @param[in] end of the request.
 */
void fr_stats_bins(fr_stats_t *stats, fr_time_t start, fr_time_t end)
{
	fr_time_t	diff;
	uint32_t	delay;

	if (end < start) return;	/* bad data */
	diff = end - start;

	if (diff >= fr_time_delta_from_sec(10)) {
		stats->elapsed[7]++;
	} else {
		int i;
		uint32_t cmp;

		delay = fr_time_delta_to_usec(diff);

		cmp = 10;
		for (i = 0; i < 7; i++) {
			if (delay < cmp) {
				stats->elapsed[i]++;
				break;
			}
			cmp *= 10;
		}
	}
}

#endif /* WITH_STATS */
