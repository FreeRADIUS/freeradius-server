/*
 * status.c	Statistics processing
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
 * Copyright 2008 The FreeRADIUS server project
 * Copyright 2008 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/stats.h>

#ifdef WITH_STATS
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

#ifdef WITH_ACCOUNTING
static fr_stats2vp client_acctvp[] = {
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

#define FR2ATTR(x) ((11344 << 16) | (x))

static void request_stats_addvp(REQUEST *request,
				fr_stats2vp *table, fr_stats_t *stats)
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


/*
 *	Find a listener by IP address && port.
 */
static rad_listen_t *listener_find_byipaddr(const fr_ipaddr_t *ipaddr,
					    int port)
{
	rad_listen_t *this;

	for (this = mainconfig.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		if ((this->type != RAD_LISTEN_AUTH) &&
		    (this->type != RAD_LISTEN_ACCT)) continue;
		
		sock = this->data;

		if ((sock->port == port) &&
		    (fr_ipaddr_cmp(ipaddr, &sock->ipaddr) == 0)) {
			return this;
		}
	}

	return NULL;
}


/*
 *	Find a RADCLIENT_LIST based on listening IP address && port
 */
static RADCLIENT_LIST *listener_find_client_list(const fr_ipaddr_t *ipaddr,
						 int port)
{
	listen_socket_t *sock;
	rad_listen_t *this;

	this = listener_find_byipaddr(ipaddr, port);
	if (!this) return NULL;

	sock = this->data;
	return sock->clients;
}

static void request_stats_reply(REQUEST *request)
{
	VALUE_PAIR *flag, *vp;

	/*
	 *	Statistics are available ONLY on a "status" port.
	 */
	rad_assert(request->packet->code == PW_STATUS_SERVER);
	rad_assert(request->listener->type == RAD_LISTEN_NONE);
		
	flag = pairfind(request->packet->vps, FR2ATTR(127));
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
		vp = radius_paircreate(request, &request->reply->vps,
				       FR2ATTR(176), PW_TYPE_DATE);
		if (vp) vp->vp_date = radius_start_time.tv_sec;
		vp = radius_paircreate(request, &request->reply->vps,
				       FR2ATTR(177), PW_TYPE_DATE);
		if (vp) vp->vp_date = radius_hup_time.tv_sec;
		
#ifdef HAVE_PTHREAD_H
		int i, array[RAD_LISTEN_MAX];

		thread_pool_queue_stats(array);

		for (i = 0; i <= RAD_LISTEN_DETAIL; i++) {
			vp = radius_paircreate(request, &request->reply->vps,
					       FR2ATTR(162 + i),
					       PW_TYPE_INTEGER);
			
			if (!vp) continue;
			vp->vp_integer = array[i];
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
		    ((request->listener->type == RAD_LISTEN_AUTH) ||
		     (request->listener->type == RAD_LISTEN_NONE))) {
			request_stats_addvp(request, authvp, &this->stats);
		}
		
#ifdef WITH_ACCOUNTING
		if (((flag->vp_integer & 0x02) != 0) &&
		    ((request->listener->type == RAD_LISTEN_ACCT) ||
		     (request->listener->type == RAD_LISTEN_NONE))) {
			request_stats_addvp(request, acctvp, &this->stats);
		}
#endif
	}

	/*
	 *	Home servers.
	 */
	if (((flag->vp_integer & 0x80) != 0) &&
	    ((flag->vp_integer & 0x03) != 0)) {
		home_server *home;
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
		home = home_server_find(&ipaddr, server_port->vp_integer);

		/*
		 *	Not found: don't do anything
		 */
		if (!home) return;
		
		pairadd(&request->reply->vps,
			paircopyvp(server_ip));
		pairadd(&request->reply->vps,
			paircopyvp(server_port));

		vp = radius_paircreate(request, &request->reply->vps,
				       FR2ATTR(172), PW_TYPE_INTEGER);
		if (vp) vp->vp_integer = home->currently_outstanding;

		vp = radius_paircreate(request, &request->reply->vps,
				       FR2ATTR(173), PW_TYPE_INTEGER);
		if (vp) vp->vp_integer = home->state;

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->revive_time.tv_sec != 0)) {
			vp = radius_paircreate(request, &request->reply->vps,
					       FR2ATTR(175), PW_TYPE_DATE);
			if (vp) vp->vp_date = home->revive_time.tv_sec;
		}

		if ((home->state == HOME_STATE_ALIVE) &&
		    (home->ema.window > 0)) {
				vp = radius_paircreate(request,
						       &request->reply->vps,
						       FR2ATTR(178),
						       PW_TYPE_INTEGER);
				if (vp) vp->vp_integer = home->ema.window;
				vp = radius_paircreate(request,
						       &request->reply->vps,
						       FR2ATTR(179),
						       PW_TYPE_INTEGER);
				if (vp) vp->vp_integer = home->ema.ema1 / EMA_SCALE;
				vp = radius_paircreate(request,
						       &request->reply->vps,
						       FR2ATTR(180),
						       PW_TYPE_INTEGER);
				if (vp) vp->vp_integer = home->ema.ema10 / EMA_SCALE;

		}

		if (home->state == HOME_STATE_IS_DEAD) {
			vp = radius_paircreate(request, &request->reply->vps,
					       FR2ATTR(174), PW_TYPE_DATE);
			if (vp) vp->vp_date = home->zombie_period_start.tv_sec + home->zombie_period;
		}

		if (((flag->vp_integer & 0x01) != 0) &&
		    (home->type == HOME_TYPE_AUTH)) {
			request_stats_addvp(request, proxy_authvp,
					    &home->stats);
		}

#ifdef WITH_ACCOUNTING
		if (((flag->vp_integer & 0x02) != 0) &&
		    (home->type == HOME_TYPE_ACCT)) {
			request_stats_addvp(request, proxy_acctvp,
					    &home->stats);
		}
#endif
	}
}

static int status_process(REQUEST *request)
{
	rad_status_server(request);

	request_stats_reply(request);

	return 0;
}

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int status_socket_recv(rad_listen_t *listener,
			    RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	ssize_t		rcode;
	int		code, src_port;
	RADIUS_PACKET	*packet;
	RADCLIENT	*client;
	fr_ipaddr_t	src_ipaddr;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	RAD_STATS_TYPE_INC(listener, total_requests);

	if (rcode < 20) {	/* AUTH_HDR_LEN */
		RAD_STATS_TYPE_INC(listener, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		RAD_STATS_TYPE_INC(listener, total_invalid_requests);
		return 0;
	}

	/*
	 *	We only understand Status-Server on this socket.
	 */
	if (code != PW_STATUS_SERVER) {
		DEBUG("Ignoring packet code %d sent to Status-Server port",
		      code);
		rad_recv_discard(listener->fd);
		RAD_STATS_TYPE_INC(listener, total_unknown_types);
		RAD_STATS_CLIENT_INC(listener, client, total_unknown_types);
		return 0;
	}

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(listener->fd, 1); /* require message authenticator */
	if (!packet) {
		RAD_STATS_TYPE_INC(listener, total_malformed_requests);
		DEBUG("%s", fr_strerror());
		return 0;
	}

	if (!received_request(listener, packet, prequest, client)) {
		RAD_STATS_TYPE_INC(listener, total_packets_dropped);
		RAD_STATS_CLIENT_INC(listener, client, total_packets_dropped);
		rad_free(&packet);
		return 0;
	}

	*pfun = status_process;
	return 1;
}


/*
 *	Send an authentication response packet
 */
static int status_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == status_socket_send);

	return rad_send(request->reply, request->packet,
			request->client->secret);
}


static int status_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (!request->reply->code) return 0;

	rad_encode(request->reply, request->packet,
		   request->client->secret);
	rad_sign(request->reply, request->packet,
		 request->client->secret);

	return 0;
}


static int status_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (rad_verify(request->packet, NULL,
		       request->client->secret) < 0) {
		return -1;
	}

	return rad_decode(request->packet, NULL,
			  request->client->secret);
}


frs_module_t frs_status = {
	FRS_MODULE_INIT, RAD_LISTEN_NONE,
	"status", listen_socket_parse, NULL,
	status_socket_recv, status_socket_send,
	listen_socket_print, status_socket_encode, status_socket_decode
};
#endif
