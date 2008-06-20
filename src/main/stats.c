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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#ifdef WITH_STATS

fr_stats_t radius_auth_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#ifdef WITH_ACCOUNTING
fr_stats_t radius_acct_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif

#ifdef WITH_PROXY
fr_stats_t proxy_auth_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#ifdef WITH_ACCOUNTING
fr_stats_t proxy_acct_stats = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#endif
#endif

void request_stats_final(REQUEST *request)
{
	if (request->master_state == REQUEST_COUNTED) return;

	if ((request->listener->type != RAD_LISTEN_AUTH) &&
	    (request->listener->type != RAD_LISTEN_ACCT)) return;

	/*
	 *	Update the statistics.
	 *
	 *	Note that we do NOT do this in a child thread.
	 *	Instead, we update the stats when a request is
	 *	deleted, because only the main server thread calls
	 *	this function, which makes it thread-safe.
	 */
	switch (request->reply->code) {
	case PW_AUTHENTICATION_ACK:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_accepts++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_accepts++;
		if (request->client && request->client->auth) {
			request->client->auth->accepts++;
		}
		break;

	case PW_AUTHENTICATION_REJECT:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_rejects++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_rejects++;
		if (request->client && request->client->auth) {
			request->client->auth->rejects++;
		}
		break;

	case PW_ACCESS_CHALLENGE:
		radius_auth_stats.total_responses++;
		radius_auth_stats.total_access_challenges++;
		request->listener->stats.total_responses++;
		request->listener->stats.total_access_challenges++;
		if (request->client && request->client->auth) {
			request->client->auth->challenges++;
		}
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_RESPONSE:
		radius_acct_stats.total_responses++;
		request->listener->stats.total_responses++;
		if (request->client && request->client->acct) {
			request->client->acct->responses++;
		}
		break;
#endif

		/*
		 *	No response, it must have been a bad
		 *	authenticator.
		 */
	case 0:
		if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
			radius_auth_stats.total_bad_authenticators++;
			request->listener->stats.total_bad_authenticators++;
			if (request->client && request->client->auth) {
				request->client->auth->bad_authenticators++;
			}
		}
		break;

	default:
		break;
	}

#ifdef WITH_PROXY
	if (!request->proxy) goto done;	/* simplifies formatting */
		
	switch (request->proxy_reply->code) {
	case PW_AUTHENTICATION_REQUEST:
		proxy_auth_stats.total_requests += request->num_proxied_requests;
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_REQUEST:
		proxy_acct_stats.total_requests++;
		break;
#endif

	default:
		break;
	}

	if (!request->proxy_reply) goto done;	/* simplifies formatting */

	switch (request->proxy_reply->code) {
	case PW_AUTHENTICATION_ACK:
		proxy_auth_stats.total_responses += request->num_proxied_responses;
		proxy_auth_stats.total_access_accepts += request->num_proxied_responses;
		break;

	case PW_AUTHENTICATION_REJECT:
		proxy_auth_stats.total_responses += request->num_proxied_responses;
		proxy_auth_stats.total_access_rejects += request->num_proxied_responses;
		break;

	case PW_ACCESS_CHALLENGE:
		proxy_auth_stats.total_responses += request->num_proxied_responses;
		proxy_auth_stats.total_access_challenges += request->num_proxied_responses;
		break;

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_RESPONSE:
		radius_acct_stats.total_responses++;
		break;
#endif

	default:
		proxy_auth_stats.total_unknown_types++;
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
	{ 128, offsetof(fr_stats_t, total_requests) },
	{ 129, offsetof(fr_stats_t, total_access_accepts) },
	{ 130, offsetof(fr_stats_t, total_access_rejects) },
	{ 131, offsetof(fr_stats_t, total_access_challenges) },
	{ 132, offsetof(fr_stats_t, total_responses) },
	{ 133, offsetof(fr_stats_t, total_dup_requests) },
	{ 134, offsetof(fr_stats_t, total_malformed_requests) },
	{ 135, offsetof(fr_stats_t, total_bad_authenticators) },
	{ 136, offsetof(fr_stats_t, total_packets_dropped) },
	{ 137, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};


#ifdef WITH_PROXY
/*
 *	Proxied authentication requests.
 */
static fr_stats2vp proxy_authvp[] = {
	{ 138, offsetof(fr_stats_t, total_requests) },
	{ 139, offsetof(fr_stats_t, total_access_accepts) },
	{ 140, offsetof(fr_stats_t, total_access_rejects) },
	{ 141, offsetof(fr_stats_t, total_access_challenges) },
	{ 142, offsetof(fr_stats_t, total_responses) },
	{ 143, offsetof(fr_stats_t, total_dup_requests) },
	{ 144, offsetof(fr_stats_t, total_malformed_requests) },
	{ 145, offsetof(fr_stats_t, total_bad_authenticators) },
	{ 146, offsetof(fr_stats_t, total_packets_dropped) },
	{ 147, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif


#ifdef WITH_ACCOUNTING
/*
 *	Accounting
 */
static fr_stats2vp acctvp[] = {
	{ 148, offsetof(fr_stats_t, total_requests) },
	{ 149, offsetof(fr_stats_t, total_responses) },
	{ 150, offsetof(fr_stats_t, total_dup_requests) },
	{ 151, offsetof(fr_stats_t, total_malformed_requests) },
	{ 152, offsetof(fr_stats_t, total_bad_authenticators) },
	{ 153, offsetof(fr_stats_t, total_packets_dropped) },
	{ 154, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_PROXY
static fr_stats2vp proxy_acctvp[] = {
	{ 155, offsetof(fr_stats_t, total_requests) },
	{ 156, offsetof(fr_stats_t, total_responses) },
	{ 157, offsetof(fr_stats_t, total_dup_requests) },
	{ 158, offsetof(fr_stats_t, total_malformed_requests) },
	{ 159, offsetof(fr_stats_t, total_bad_authenticators) },
	{ 160, offsetof(fr_stats_t, total_packets_dropped) },
	{ 161, offsetof(fr_stats_t, total_unknown_types) },
	{ 0, 0 }
};
#endif
#endif

static fr_stats2vp client_authvp[] = {
	{ 128, offsetof(fr_client_stats_t, requests) },
	{ 129, offsetof(fr_client_stats_t, accepts) },
	{ 130, offsetof(fr_client_stats_t, rejects) },
	{ 131, offsetof(fr_client_stats_t, challenges) },
	{ 132, offsetof(fr_client_stats_t, responses) },
	{ 133, offsetof(fr_client_stats_t, dup_requests) },
	{ 134, offsetof(fr_client_stats_t, malformed_requests) },
	{ 135, offsetof(fr_client_stats_t, bad_authenticators) },
	{ 136, offsetof(fr_client_stats_t, packets_dropped) },
	{ 137, offsetof(fr_client_stats_t, unknown_types) },
	{ 0, 0 }
};

#ifdef WITH_ACCOUNTING
static fr_stats2vp client_acctvp[] = {
	{ 155, offsetof(fr_client_stats_t, requests) },
	{ 156, offsetof(fr_client_stats_t, responses) },
	{ 157, offsetof(fr_client_stats_t, dup_requests) },
	{ 158, offsetof(fr_client_stats_t, malformed_requests) },
	{ 159, offsetof(fr_client_stats_t, bad_authenticators) },
	{ 160, offsetof(fr_client_stats_t, packets_dropped) },
	{ 161, offsetof(fr_client_stats_t, unknown_types) },
	{ 0, 0 }
};
#endif

#define FR2ATTR(x) ((11344 << 16) | (x))

static void request_stats_addvp(REQUEST *request,
				fr_stats2vp *table, void *stats)
{
	int i;
	VALUE_PAIR *vp;

	for (i = 0; table[i].attribute != 0; i++) {
		vp = radius_paircreate(request, &request->reply->vps,
				       FR2ATTR(table[i].attribute),
				       PW_TYPE_INTEGER);
		if (!vp) continue;

		vp->vp_integer = *(int *)(((char *) stats) + table[i].offset);
	}
}


void request_stats_reply(REQUEST *request)
{
	VALUE_PAIR *flag, *vp;

	if (request->packet->code != PW_STATUS_SERVER) return;

	if ((request->packet->src_ipaddr.af != AF_INET) ||
	    (request->packet->src_ipaddr.ipaddr.ip4addr.s_addr != htonl(INADDR_LOOPBACK))) return;

	flag = pairfind(request->packet->vps, FR2ATTR(127));
	if (!flag || (flag->vp_integer == 0)) return;


	if (((flag->vp_integer & 0x01) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, authvp, &radius_auth_stats);
	}
		
#ifdef WITH_ACCOUNTING
	if (((flag->vp_integer & 0x02) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, acctvp, &radius_acct_stats);
	}
#endif

#ifdef WITH_PROXY
	if (((flag->vp_integer & 0x04) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, proxy_authvp, &proxy_auth_stats);
	}

#ifdef WITH_ACCOUNTING
	if (((flag->vp_integer & 0x08) != 0) &&
	    ((flag->vp_integer & 0x20) == 0)) {
		request_stats_addvp(request, proxy_acctvp, &proxy_acct_stats);
	}
#endif
#endif

#ifdef HAVE_PTHREAD_H
	if ((flag->vp_integer & 0x10) != 0) {
		int i, array[RAD_LISTEN_MAX];

		thread_pool_queue_stats(array);

		for (i = 0; i <= RAD_LISTEN_DETAIL; i++) {
			vp = radius_paircreate(request, &request->reply->vps,
					       FR2ATTR(162 + i),
					       PW_TYPE_INTEGER);
			
			if (!vp) continue;
			vp->vp_integer = array[i];
		}
	}
#endif

	if ((flag->vp_integer & 0x20) != 0) {
		fr_ipaddr_t ipaddr;
		VALUE_PAIR *server_ip, *server_port;
		RADCLIENT *client = NULL;
		RADCLIENT_LIST *cl = NULL;

		/*
		 *	See if we need to look up the client by server
		 *	socket.
		 */
		server_ip = pairfind(request->packet->vps, FR2ATTR(170));
		if (server_ip) {
			server_port = pairfind(request->packet->vps,
					       FR2ATTR(171));

			if (server_port) {
				ipaddr.af = AF_INET;
				ipaddr.ipaddr.ip4addr.s_addr = server_ip->vp_ipaddr;
				cl = listener_find_client_list(&ipaddr, server_port->vp_integer);
							       
				/*
				 *	Not found: don't do anything
				 */
				if (!cl) return;
			}
		}


		vp = pairfind(request->packet->vps, FR2ATTR(167));
		if (vp) {
			ipaddr.af = AF_INET;
			ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			client = client_find(cl, &ipaddr);

			/*
			 *	Else look it up by number.
			 */
		} else if ((vp = pairfind(request->packet->vps,
					   FR2ATTR(168))) != NULL) {
			client = client_findbynumber(cl, vp->vp_integer);
		}

		if (client) {
			/*
			 *	If found, echo it back, along with
			 *	the requested statistics.
			 */
			pairadd(&request->reply->vps, paircopyvp(vp));

			/*
			 *	When retrieving client by number, also
			 *	echo back it's IP address.
			 */
			if ((vp->type == PW_TYPE_INTEGER) &&
			    (client->ipaddr.af == AF_INET)) {
				vp = radius_paircreate(request,
						       &request->reply->vps,
						       FR2ATTR(167),
						       PW_TYPE_IPADDR);
				if (vp) {
					vp->vp_ipaddr = client->ipaddr.ipaddr.ip4addr.s_addr;
				}

				if (client->prefix != 32) {
					vp = radius_paircreate(request,
							       &request->reply->vps,
							       FR2ATTR(169),
							       PW_TYPE_INTEGER);
					if (vp) {
						vp->vp_integer = client->prefix;
					}
				}
			}
			
			if (server_ip) {
				pairadd(&request->reply->vps,
					paircopyvp(server_ip));
				pairadd(&request->reply->vps,
					paircopyvp(server_port));
			}

			if (client->auth &&
			    ((flag->vp_integer & 0x01) != 0)) {
				request_stats_addvp(request, client_authvp,
						    client->auth);
			}
#ifdef WITH_ACCOUNTING
			if (client->acct &&
			    ((flag->vp_integer & 0x01) != 0)) {
				request_stats_addvp(request, client_acctvp,
						    client->acct);
			}
#endif
		} /* else client wasn't found, don't echo it back */
	}

	if (((flag->vp_integer && 0x40) != 0) &&
	    ((flag->vp_integer && 0x03) != 0)) {
		rad_listen_t *this;
		VALUE_PAIR *server_ip, *server_port;
		fr_ipaddr_t ipaddr;

		/*
		 *	See if we need to look up the server by socket
		 *	socket.
		 */
		server_ip = pairfind(request->packet->vps, FR2ATTR(170));
		if (!server_ip) return;

		server_port = pairfind(request->packet->vps,
				       FR2ATTR(171));
		if (!server_port) return;
		
		ipaddr.af = AF_INET;
		ipaddr.ipaddr.ip4addr.s_addr = server_ip->vp_ipaddr;
		this = listener_find_byipaddr(&ipaddr,
					      server_port->vp_integer);
		
		/*
		 *	Not found: don't do anything
		 */
		if (!this) return;
		
		pairadd(&request->reply->vps,
			paircopyvp(server_ip));
		pairadd(&request->reply->vps,
			paircopyvp(server_port));

		if (((flag->vp_integer & 0x01) != 0) &&
		    (request->listener->type == RAD_LISTEN_AUTH)) {
			request_stats_addvp(request, authvp, &this->stats);
		}
		
#ifdef WITH_ACCOUNTING
		if (((flag->vp_integer & 0x02) != 0) &&
		    (request->listener->type == RAD_LISTEN_ACCT)) {
			request_stats_addvp(request, acctvp, &this->stats);
		}
#endif
	}
}

#endif /* WITH_STATS */
