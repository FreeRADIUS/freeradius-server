/*
 * acct.c	Accounting routines.
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
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 * Copyright 2000  Alan Curry <pacman@world.std.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/modules.h>


/*
 *	Process and reply to a server-status request.
 */
static int acct_status_server(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	DICT_VALUE *dval;

	dval = dict_valbyname(PW_ACCT_TYPE, "Status-Server");
	if (dval) {
		rcode = module_accounting(dval->value, request);
	} else {
		rcode = RLM_MODULE_OK;
	}
	
	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		request->reply->code = PW_ACCOUNTING_RESPONSE;
		break;
		
	default:
		request->reply->code = 0; /* don't reply */
		break;
	}

	return 0;
}

/*
 *	rad_accounting: call modules.
 *
 *	The return value of this function isn't actually used right now, so
 *	it's not entirely clear if it is returning the right things. --Pac.
 */
static int rad_accounting(REQUEST *request)
{
	int result = RLM_MODULE_OK;


#ifdef WITH_PROXY
#define WAS_PROXIED (request->proxy)
#else
#define WAS_PROXIED (0)
#endif

	/*
	 *	Run the modules only once, before proxying.
	 */
	if (!WAS_PROXIED) {
		VALUE_PAIR	*vp;
		int		acct_type = 0;

		result = module_preacct(request);
		switch (result) {
			/*
			 *	The module has a number of OK return codes.
			 */
			case RLM_MODULE_NOOP:
			case RLM_MODULE_OK:
			case RLM_MODULE_UPDATED:
				break;
			/*
			 *	The module handled the request, stop here.
			 */
			case RLM_MODULE_HANDLED:
				return result;
			/*
			 *	The module failed, or said the request is
			 *	invalid, therefore we stop here.
			 */
			case RLM_MODULE_FAIL:
			case RLM_MODULE_INVALID:
			case RLM_MODULE_NOTFOUND:
			case RLM_MODULE_REJECT:
			case RLM_MODULE_USERLOCK:
			default:
				return result;
		}

		/*
		 *	Do the data storage before proxying. This is to ensure
		 *	that we log the packet, even if the proxy never does.
		 */
		vp = pairfind(request->config_items, PW_ACCT_TYPE);
		if (vp) {
			DEBUG2("  Found Acct-Type %s", vp->vp_strvalue);
			acct_type = vp->vp_integer;
		}
		result = module_accounting(acct_type, request);
		switch (result) {
			/*
			 *	In case the accounting module returns FAIL,
			 *	it's still useful to send the data to the
			 *	proxy.
			 */
			case RLM_MODULE_FAIL:
			case RLM_MODULE_NOOP:
			case RLM_MODULE_OK:
			case RLM_MODULE_UPDATED:
				break;
			/*
			 *	The module handled the request, don't reply.
			 */
			case RLM_MODULE_HANDLED:
				return result;
			/*
			 *	Neither proxy, nor reply to invalid requests.
			 */
			case RLM_MODULE_INVALID:
			case RLM_MODULE_NOTFOUND:
			case RLM_MODULE_REJECT:
			case RLM_MODULE_USERLOCK:
			default:
				return result;
		}

		/*
		 *	Maybe one of the preacct modules has decided
		 *	that a proxy should be used.
		 */
		if ((vp = pairfind(request->config_items, PW_PROXY_TO_REALM))) {
			REALM *realm;

			/*
			 *	Check whether Proxy-To-Realm is
			 *	a LOCAL realm.
			 */
			realm = realm_find2(vp->vp_strvalue);
			if (realm && !realm->acct_pool) {
				DEBUG("rad_accounting: Cancelling proxy to realm %s, as it is a LOCAL realm.", realm->name);
				pairdelete(&request->config_items, PW_PROXY_TO_REALM);
			} else {
				/*
				 *	Don't reply to the NAS now because
				 *	we have to send the proxied packet
				 *	before that.
				 */
				return result;
			}
		}
	}

	/*
	 *	We get here IF we're not proxying, OR if we've
	 *	received the accounting reply from the end server,
	 *	THEN we can reply to the NAS.
	 *      If the accounting module returns NOOP, the data
	 *      storage did not succeed, so radiusd should not send
	 *      Accounting-Response.
	 */
	switch (result) {
		/*
		 *	Send back an ACK to the NAS.
		 */
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = PW_ACCOUNTING_RESPONSE;
			break;
		/*
		 *	The module handled the request, don't reply.
		 */
		case RLM_MODULE_HANDLED:
			break;
		/*
		 *	Failed to log or to proxy the accounting data,
		 *	therefore don't reply to the NAS.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			break;
	}
	return result;
}


/*
 *	Receive packets from an accounting socket
 */
static int acct_socket_recv(rad_listen_t *listener,
			    RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	ssize_t		rcode;
	int		code, src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
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
	 *	Some sanity checks, based on the packet code.
	 */
	switch(code) {
	case PW_ACCOUNTING_REQUEST:
		RAD_STATS_CLIENT_INC(listener, client, total_requests);
		fun = rad_accounting;
		break;

	case PW_STATUS_SERVER:
		if (!mainconfig.status_server) {
			rad_recv_discard(listener->fd);
			RAD_STATS_TYPE_INC(listener, total_packets_dropped);
			RAD_STATS_CLIENT_INC(listener, client, total_unknown_types);

			DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = acct_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		RAD_STATS_TYPE_INC(listener, total_unknown_types);
		RAD_STATS_CLIENT_INC(listener, client, total_unknown_types);

		DEBUG("Invalid packet code %d sent to a accounting port from client %s port %d : IGNORED",
		      code, client->shortname, src_port);
		return 0;
	} /* switch over packet types */

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(listener->fd, 0);
	if (!packet) {
		RAD_STATS_TYPE_INC(listener, total_malformed_requests);
		radlog(L_ERR, "%s", fr_strerror());
		return 0;
	}

	/*
	 *	There can be no duplicate accounting packets.
	 */
	if (!received_request(listener, packet, prequest, client)) {
		RAD_STATS_TYPE_INC(listener, total_packets_dropped);
		RAD_STATS_CLIENT_INC(listener, client, total_packets_dropped);
		rad_free(&packet);
		return 0;
	}

	*pfun = fun;
	return 1;
}


/*
 *	Send an accounting response packet (or not)
 */
static int acct_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == acct_socket_send);

	/*
	 *	Accounting reject's are silently dropped.
	 *
	 *	We do it here to avoid polluting the rest of the
	 *	code with this knowledge
	 */
	if (request->reply->code == 0) return 0;

	return rad_send(request->reply, request->packet,
			request->client->secret);
}


static int acct_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (!request->reply->code) return 0;

	rad_encode(request->reply, request->packet,
		   request->client->secret);
	rad_sign(request->reply, request->packet,
		 request->client->secret);

	return 0;
}


static int acct_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (rad_verify(request->packet, NULL,
		       request->client->secret) < 0) {
		return -1;
	}

	return rad_decode(request->packet, NULL,
			  request->client->secret);
}


frs_module_t frs_acct = {
  FRS_MODULE_INIT, RAD_LISTEN_ACCT, "acct",
  listen_socket_parse, NULL,
  acct_socket_recv, acct_socket_send,
  listen_socket_print, acct_socket_encode, acct_socket_decode
};
