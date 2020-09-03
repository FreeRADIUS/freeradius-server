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
 * Copyright 2008  The FreeRADIUS server project
 * Copyright 2008  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef WITH_STATS

#define USEC (1000000)
#define EMA_SCALE (100)
#define F_EMA_SCALE (1000000)

static struct timeval	start_time;
static struct timeval	hup_time;

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

static void stats_time(fr_stats_t *stats, struct timeval *start,
		       struct timeval *end)
{
	struct timeval diff;
	uint32_t delay;

	if ((start->tv_sec == 0) || (end->tv_sec == 0) ||
	    (end->tv_sec < start->tv_sec)) return;

	rad_tv_sub(end, start, &diff);

	if (diff.tv_sec >= 10) {
		stats->elapsed[7]++;
	} else {
		int i;
		uint32_t cmp;

		delay = (diff.tv_sec * USEC) + diff.tv_usec;

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

void request_stats_final(REQUEST *request)
{
	if (request->master_state == REQUEST_COUNTED) return;

	if (!request->listener) return;
	if (!request->client) return;

	if ((request->listener->type != RAD_LISTEN_NONE) &&
#ifdef WITH_ACCOUNTING
	    (request->listener->type != RAD_LISTEN_ACCT) &&
#endif
#ifdef WITH_COA
	    (request->listener->type != RAD_LISTEN_COA) &&
#endif
	    (request->listener->type != RAD_LISTEN_AUTH)) return;

	/* don't count statistic requests */
	if (request->packet->code == PW_CODE_STATUS_SERVER)
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
	if (request->reply && (request->packet->code != PW_CODE_STATUS_SERVER)) switch (request->reply->code) {
	case PW_CODE_ACCESS_ACCEPT:
		INC_AUTH(total_access_accepts);

		auth_stats:
		INC_AUTH(total_responses);

		/*
		 *	FIXME: Do the time calculations once...
		 */
		stats_time(&radius_auth_stats,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		stats_time(&request->client->auth,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		stats_time(&request->listener->stats,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		break;

	case PW_CODE_ACCESS_REJECT:
		INC_AUTH(total_access_rejects);
		goto auth_stats;

	case PW_CODE_ACCESS_CHALLENGE:
		INC_AUTH(total_access_challenges);
		goto auth_stats;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
		INC_ACCT(total_responses);
		stats_time(&radius_acct_stats,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		stats_time(&request->client->acct,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_ACK:
		INC_COA(total_access_accepts);
	  coa_stats:
		INC_COA(total_responses);
		stats_time(&request->client->coa,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		break;

	case PW_CODE_COA_NAK:
		INC_COA(total_access_rejects);
		goto coa_stats;

	case PW_CODE_DISCONNECT_ACK:
		INC_DSC(total_access_accepts);
	  dsc_stats:
		INC_DSC(total_responses);
		stats_time(&request->client->dsc,
			   &request->packet->timestamp,
			   &request->reply->timestamp);
		break;

	case PW_CODE_DISCONNECT_NAK:
		INC_DSC(total_access_rejects);
		goto dsc_stats;
#endif

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
			if (request->reply->offset == -2) {
				INC_AUTH(total_bad_authenticators);
			} else {
				INC_AUTH(total_packets_dropped);
			}
		} else if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
			if (request->reply->offset == -2) {
				INC_ACCT(total_bad_authenticators);
			} else {
				INC_ACCT(total_packets_dropped);
			}
		}
		break;

	default:
		break;
	}

#ifdef WITH_PROXY
	if (!request->proxy || !request->home_server) goto done;	/* simplifies formatting */

	switch (request->proxy->code) {
	case PW_CODE_ACCESS_REQUEST:
		proxy_auth_stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		proxy_acct_stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_REQUEST:
		proxy_coa_stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		proxy_dsc_stats.total_requests += request->num_proxied_requests;
		request->home_server->stats.total_requests += request->num_proxied_requests;
		break;
#endif

	default:
		break;
	}

	if (!request->proxy_reply) goto done;	/* simplifies formatting */

#undef INC
#define INC(_x) proxy_auth_stats._x += request->num_proxied_responses; request->home_server->stats._x += request->num_proxied_responses;

	switch (request->proxy_reply->code) {
	case PW_CODE_ACCESS_ACCEPT:
		INC(total_access_accepts);
	proxy_stats:
		INC(total_responses);
		stats_time(&proxy_auth_stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		stats_time(&request->home_server->stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		break;

	case PW_CODE_ACCESS_REJECT:
		INC(total_access_rejects);
		goto proxy_stats;

	case PW_CODE_ACCESS_CHALLENGE:
		INC(total_access_challenges);
		goto proxy_stats;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
		proxy_acct_stats.total_responses++;
		request->home_server->stats.total_responses++;
		stats_time(&proxy_acct_stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		stats_time(&request->home_server->stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
		proxy_coa_stats.total_responses++;
		request->home_server->stats.total_responses++;
		stats_time(&proxy_coa_stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		stats_time(&request->home_server->stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		break;

	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
		proxy_dsc_stats.total_responses++;
		request->home_server->stats.total_responses++;
		stats_time(&proxy_dsc_stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		stats_time(&request->home_server->stats,
			   &request->proxy->timestamp,
			   &request->proxy_reply->timestamp);
		break;
#endif

	default:
		proxy_auth_stats.total_unknown_types++;
		request->home_server->stats.total_unknown_types++;
		break;
	}

 done:
#endif /* WITH_PROXY */

	request->master_state = REQUEST_COUNTED;
}

typedef struct fr_stats2vp {
	int	attribute;
	size_t	offset;
} fr_stats2vp;

/*
 *	Authentication
 */
static fr_stats2vp authvp[] = {
	{ PW_FREERADIUS_TOTAL_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ PW_FREERADIUS_TOTAL_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ PW_FREERADIUS_TOTAL_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ PW_FREERADIUS_TOTAL_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};


#ifdef WITH_PROXY
/*
 *	Proxied authentication requests.
 */
static fr_stats2vp proxy_authvp[] = {
	{ PW_FREERADIUS_TOTAL_PROXY_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_PROXY_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif


#ifdef WITH_ACCOUNTING
/*
 *	Accounting
 */
static fr_stats2vp acctvp[] = {
	{ PW_FREERADIUS_TOTAL_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_PROXY
static fr_stats2vp proxy_acctvp[] = {
	{ PW_FREERADIUS_TOTAL_PROXY_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_PROXY_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif
#endif

static fr_stats2vp client_authvp[] = {
	{ PW_FREERADIUS_TOTAL_ACCESS_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_ACCESS_ACCEPTS, offsetof(fr_stats_t, total_access_accepts) },
	{ PW_FREERADIUS_TOTAL_ACCESS_REJECTS, offsetof(fr_stats_t, total_access_rejects) },
	{ PW_FREERADIUS_TOTAL_ACCESS_CHALLENGES, offsetof(fr_stats_t, total_access_challenges) },
	{ PW_FREERADIUS_TOTAL_AUTH_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_AUTH_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_AUTH_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_AUTH_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_AUTH_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_AUTH_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_ACCOUNTING
static fr_stats2vp client_acctvp[] = {
	{ PW_FREERADIUS_TOTAL_ACCOUNTING_REQUESTS, offsetof(fr_stats_t, total_requests) },
	{ PW_FREERADIUS_TOTAL_ACCOUNTING_RESPONSES, offsetof(fr_stats_t, total_responses) },
	{ PW_FREERADIUS_TOTAL_ACCT_DUPLICATE_REQUESTS, offsetof(fr_stats_t, total_dup_requests) },
	{ PW_FREERADIUS_TOTAL_ACCT_MALFORMED_REQUESTS, offsetof(fr_stats_t, total_malformed_requests) },
	{ PW_FREERADIUS_TOTAL_ACCT_INVALID_REQUESTS, offsetof(fr_stats_t, total_bad_authenticators) },
	{ PW_FREERADIUS_TOTAL_ACCT_DROPPED_REQUESTS, offsetof(fr_stats_t, total_packets_dropped) },
	{ PW_FREERADIUS_TOTAL_ACCT_UNKNOWN_TYPES, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif

static void request_stats_addvp(REQUEST *request,
				fr_stats2vp *table, fr_stats_t *stats)
{
	int i;
	uint64_t counter;
	VALUE_PAIR *vp;

	for (i = 0; table[i].attribute != 0; i++) {
		vp = radius_pair_create(request->reply, &request->reply->vps,
				       table[i].attribute, VENDORPEC_FREERADIUS);
		if (!vp) continue;

		counter = *(uint64_t *) (((uint8_t *) stats) + table[i].offset);
		vp->vp_integer = counter;
	}
}

static void stats_error(REQUEST *request, char const *msg)
{
	VALUE_PAIR *vp;

	vp = radius_pair_create(request->reply, &request->reply->vps,
				PW_FREERADIUS_STATS_ERROR, VENDORPEC_FREERADIUS);
	if (!vp) return;

	fr_pair_value_strcpy(vp, msg);
}


void request_stats_reply(REQUEST *request)
{
	VALUE_PAIR *flag, *vp;

	/*
	 *	Statistics are available ONLY on a "status" port.
	 */
	rad_assert(request->packet->code == PW_CODE_STATUS_SERVER);
	rad_assert(request->listener->type == RAD_LISTEN_NONE);

	flag = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATISTICS_TYPE, VENDORPEC_FREERADIUS, TAG_ANY);
	if (!flag || (flag->vp_integer == 0)) return;

	/*
	 *	Authentication.
	 */
	if (((flag->vp_integer & 0x01) != 0) &&
	    ((flag->vp_integer & 0xc0) == 0)) {
		request_stats_addvp(request, authvp, &radius_auth_stats);
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	Accounting
	 */
	if (((flag->vp_integer & 0x02) != 0) &&
	    ((flag->vp_integer & 0xc0) == 0)) {
		request_stats_addvp(request, acctvp, &radius_acct_stats);
	}
#endif

#ifdef WITH_PROXY
	/*
	 *	Proxied authentication requests.
	 */
	if (((flag->vp_integer & 0x04) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, proxy_authvp, &proxy_auth_stats);
	}

#ifdef WITH_ACCOUNTING
	/*
	 *	Proxied accounting requests.
	 */
	if (((flag->vp_integer & 0x08) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, proxy_acctvp, &proxy_acct_stats);
	}
#endif
#endif

	/*
	 *	Internal server statistics
	 */
	if ((flag->vp_integer & 0x10) != 0) {
		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_START_TIME, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = start_time.tv_sec;
		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_HUP_TIME, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = hup_time.tv_sec;

#ifdef HAVE_PTHREAD_H
		int i, array[RAD_LISTEN_MAX], pps[2];

		thread_pool_queue_stats(array, pps);

		for (i = 0; i <= 4; i++) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       PW_FREERADIUS_QUEUE_LEN_INTERNAL + i, VENDORPEC_FREERADIUS);

			if (!vp) continue;
			vp->vp_integer = array[i];
		}

		for (i = 0; i < 2; i++) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       PW_FREERADIUS_QUEUE_PPS_IN + i, VENDORPEC_FREERADIUS);

			if (!vp) continue;
			vp->vp_integer = pps[i];
		}
#endif
	}

	/*
	 *	For a particular client.
	 */
	if ((flag->vp_integer & 0x20) != 0) {
		fr_ipaddr_t ipaddr;
		VALUE_PAIR *server_ip, *server_port = NULL;
		RADCLIENT *client = NULL;
		RADCLIENT_LIST *cl = NULL;

		/*
		 *	See if we need to look up the client by server
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_IP_ADDRESS, VENDORPEC_FREERADIUS, TAG_ANY);
		if (server_ip) {
			server_port = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_PORT, VENDORPEC_FREERADIUS, TAG_ANY);

			if (server_port) {
				ipaddr.af = AF_INET;
				ipaddr.ipaddr.ip4addr.s_addr = server_ip->vp_ipaddr;
				cl = listener_find_client_list(&ipaddr, server_port->vp_integer, IPPROTO_UDP);

				/*
				 *	Not found: don't do anything
				 */
				if (!cl) return;
			}
		}


		vp = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_CLIENT_IP_ADDRESS, VENDORPEC_FREERADIUS, TAG_ANY);
		if (vp) {
			memset(&ipaddr, 0, sizeof(ipaddr));
			ipaddr.af = AF_INET;
			ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			client = client_find(cl, &ipaddr, IPPROTO_UDP);
#ifdef WITH_TCP
			if (!client) {
				client = client_find(cl, &ipaddr, IPPROTO_TCP);
			}
#endif

			/*
			 *	Else look it up by number.
			 */
		} else if ((vp = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_CLIENT_NUMBER, VENDORPEC_FREERADIUS, TAG_ANY)) != NULL) {
			client = client_findbynumber(cl, vp->vp_integer);
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
			if ((vp->da->type == PW_TYPE_INTEGER) &&
			    (client->ipaddr.af == AF_INET)) {
				vp = radius_pair_create(request->reply,
						       &request->reply->vps,
						       PW_FREERADIUS_STATS_CLIENT_IP_ADDRESS, VENDORPEC_FREERADIUS);
				if (vp) {
					vp->vp_ipaddr = client->ipaddr.ipaddr.ip4addr.s_addr;
				}

				if (client->ipaddr.prefix != 32) {
					vp = radius_pair_create(request->reply,
							       &request->reply->vps,
							       PW_FREERADIUS_STATS_CLIENT_NETMASK, VENDORPEC_FREERADIUS);
					if (vp) {
						vp->vp_integer = client->ipaddr.prefix;
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

			if ((flag->vp_integer & 0x01) != 0) {
				request_stats_addvp(request, client_authvp,
						    &client->auth);
			}
#ifdef WITH_ACCOUNTING
			if ((flag->vp_integer & 0x02) != 0) {
				request_stats_addvp(request, client_acctvp,
						    &client->acct);
			}
#endif
		} else {
			/*
			 *	No such client.
			 */
			stats_error(request, "No such client");
		}
	}

	/*
	 *	For a particular "listen" socket.
	 */
	if (((flag->vp_integer & 0x40) != 0) &&
	    ((flag->vp_integer & 0x03) != 0)) {
		rad_listen_t *this;
		VALUE_PAIR *server_ip, *server_port;
		fr_ipaddr_t ipaddr;

		/*
		 *	See if we need to look up the server by socket
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_IP_ADDRESS, VENDORPEC_FREERADIUS, TAG_ANY);
		if (!server_ip) return;

		server_port = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_PORT, VENDORPEC_FREERADIUS, TAG_ANY);
		if (!server_port) return;

		ipaddr.af = AF_INET;
		ipaddr.ipaddr.ip4addr.s_addr = server_ip->vp_ipaddr;
		this = listener_find_byipaddr(&ipaddr,
					      server_port->vp_integer,
					      IPPROTO_UDP);

		/*
		 *	Not found: don't do anything
		 */
		if (!this) {
			stats_error(request, "No such listener");
			return;
		}

		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_ip));
		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_port));

		if ((flag->vp_integer & 0x01) != 0) {
			if ((request->listener->type == RAD_LISTEN_AUTH) ||
			    (request->listener->type == RAD_LISTEN_NONE)) {
				request_stats_addvp(request, authvp, &this->stats);
			} else {
				stats_error(request, "Listener is not auth");
			}
		}

#ifdef WITH_ACCOUNTING
		if ((flag->vp_integer & 0x02) != 0) {
			if ((request->listener->type == RAD_LISTEN_ACCT) ||
			    (request->listener->type == RAD_LISTEN_NONE)) {
				request_stats_addvp(request, acctvp, &this->stats);
			} else {
				stats_error(request, "Listener is not acct");
			}
		}
#endif
	}

#ifdef WITH_PROXY
	/*
	 *	Home servers.
	 */
	if (((flag->vp_integer & 0x80) != 0) &&
	    ((flag->vp_integer & 0x03) != 0)) {
		home_server_t *home;
		VALUE_PAIR *server_ip, *server_port;
		fr_ipaddr_t ipaddr;

		/*
		 *	See if we need to look up the server by socket
		 *	socket.
		 */
		server_ip = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_IP_ADDRESS, VENDORPEC_FREERADIUS, TAG_ANY);
		if (!server_ip) {
			stats_error(request, "No home server IP supplied");
			return;
		}

		server_port = fr_pair_find_by_num(request->packet->vps, PW_FREERADIUS_STATS_SERVER_PORT, VENDORPEC_FREERADIUS, TAG_ANY);
		if (!server_port) {
			stats_error(request, "No home server port supplied");
			return;
		}

#ifndef NDEBUG
		memset(&ipaddr, 0, sizeof(ipaddr));
#endif
		ipaddr.af = AF_INET;
		ipaddr.prefix = 32;
		ipaddr.ipaddr.ip4addr.s_addr = server_ip->vp_ipaddr;
		home = home_server_find(&ipaddr, server_port->vp_integer,
					IPPROTO_UDP);

		/*
		 *	Not found: don't do anything
		 */
		if (!home) {
			stats_error(request, "Failed to find home server IP");
			return;
		}

		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_ip));
		fr_pair_add(&request->reply->vps,
			fr_pair_copy(request->reply, server_port));

		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_SERVER_OUTSTANDING_REQUESTS, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_integer = home->currently_outstanding;

		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_SERVER_STATE, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_integer = home->state;

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->revive_time.tv_sec != 0)) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       PW_FREERADIUS_STATS_SERVER_TIME_OF_LIFE, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_date = home->revive_time.tv_sec;
		}

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->ema.window > 0)) {
				vp = radius_pair_create(request->reply,
						       &request->reply->vps,
						       PW_FREERADIUS_SERVER_EMA_WINDOW, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_integer = home->ema.window;
				vp = radius_pair_create(request->reply,
						       &request->reply->vps,
						       PW_FREERADIUS_SERVER_EMA_USEC_WINDOW_1, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_integer = home->ema.ema1 / EMA_SCALE;
				vp = radius_pair_create(request->reply,
						       &request->reply->vps,
						       PW_FREERADIUS_SERVER_EMA_USEC_WINDOW_10, VENDORPEC_FREERADIUS);
				if (vp) vp->vp_integer = home->ema.ema10 / EMA_SCALE;

		}

		if (home->state == HOME_STATE_IS_DEAD) {
			vp = radius_pair_create(request->reply, &request->reply->vps,
					       PW_FREERADIUS_STATS_SERVER_TIME_OF_DEATH, VENDORPEC_FREERADIUS);
			if (vp) vp->vp_date = home->zombie_period_start.tv_sec + home->zombie_period;
		}

		/*
		 *	Show more information...
		 *
		 *	FIXME: do this for clients, too!
		 */
		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_LAST_PACKET_RECV, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = home->last_packet_recv;

		vp = radius_pair_create(request->reply, &request->reply->vps,
				       PW_FREERADIUS_STATS_LAST_PACKET_SENT, VENDORPEC_FREERADIUS);
		if (vp) vp->vp_date = home->last_packet_sent;

		if ((flag->vp_integer & 0x01) != 0) {
			if (home->type == HOME_TYPE_AUTH) {
				request_stats_addvp(request, proxy_authvp,
						    &home->stats);
			} else {
				stats_error(request, "Home server is not auth");
			}
		}

#ifdef WITH_ACCOUNTING
		if ((flag->vp_integer & 0x02) != 0) {
			if (home->type == HOME_TYPE_ACCT) {
				request_stats_addvp(request, proxy_acctvp,
						    &home->stats);
			} else {
				stats_error(request, "Home server is not acct");
			}
		}
#endif
	}
#endif	/* WITH_PROXY */
}

void radius_stats_init(int flag)
{
	if (!flag) {
		gettimeofday(&start_time, NULL);
		hup_time = start_time; /* it's just nicer this way */
	} else {
		gettimeofday(&hup_time, NULL);
	}
}

void radius_stats_ema(fr_stats_ema_t *ema,
		      struct timeval *start, struct timeval *end)
{
	int micro;
	time_t tdiff;
#ifdef WITH_STATS_DEBUG
	static int n = 0;
#endif
	if (ema->window == 0) return;

	rad_assert(start->tv_sec <= end->tv_sec);

	/*
	 *	Initialize it.
	 */
	if (ema->f1 == 0) {
		if (ema->window > 10000) ema->window = 10000;

		ema->f1 =  (2 * F_EMA_SCALE) / (ema->window + 1);
		ema->f10 = (2 * F_EMA_SCALE) / ((10 * ema->window) + 1);
	}


	tdiff = start->tv_sec;
	tdiff -= end->tv_sec;

	micro = (int) tdiff;
	if (micro > 40) micro = 40; /* don't overflow 32-bit ints */
	micro *= USEC;
	micro += start->tv_usec;
	micro -= end->tv_usec;

	micro *= EMA_SCALE;

	if (ema->ema1 == 0) {
		ema->ema1 = micro;
		ema->ema10 = micro;
	} else {
		int diff;

		diff = ema->f1 * (micro - ema->ema1);
		ema->ema1 += (diff / 1000000);

		diff = ema->f10 * (micro - ema->ema10);
		ema->ema10 += (diff / 1000000);
	}


#ifdef WITH_STATS_DEBUG
	DEBUG("time %d %d.%06d\t%d.%06d\t%d.%06d\n",
	      n, micro / PREC, (micro / EMA_SCALE) % USEC,
	      ema->ema1 / PREC, (ema->ema1 / EMA_SCALE) % USEC,
	      ema->ema10 / PREC, (ema->ema10 / EMA_SCALE) % USEC);
	n++;
#endif
}

#endif /* WITH_STATS */
