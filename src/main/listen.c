/*
 * listen.c	Handle socket stuff
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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2005  The FreeRADIUS server project
 * Copyright 2005  Alan DeKok <aland@ox.org>
 */

#include "autoconf.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sys/resource.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WITH_UDPFROMTO
#include "udpfromto.h"
#endif

#include <fcntl.h>

#include "radiusd.h"
#include "rad_assert.h"
#include "conffile.h"
#include "token.h"

#include "radius_snmp.h"
#include "request_list.h"

static time_t start_time = 0;

/*
 *	FIXME: Delete this crap!
 */
extern time_t time_now;

/*
 *	We'll use this below.
 */
typedef int (*rad_listen_parse_t)(const char *, int, const CONF_SECTION *, rad_listen_t *);
typedef void (*rad_listen_free_t)(rad_listen_t *);

typedef struct rad_listen_master_t {
	rad_listen_parse_t	parse;
	rad_listen_free_t	free;
	rad_listen_recv_t	recv;
	rad_listen_send_t	send;
	rad_listen_update_t	update;
	rad_listen_print_t	print;
} rad_listen_master_t;

typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	lrad_ipaddr_t	ipaddr;
	int		port;
	RADCLIENT_LIST	*clients;
} listen_socket_t;

typedef struct listen_detail_t {
	const char	*detail;
	VALUE_PAIR	*vps;
	FILE		*fp;
	int		state;
	time_t		timestamp;
	lrad_ipaddr_t	client_ip;
	int		max_outstanding;
	int		*outstanding;
} listen_detail_t;
			       

/*
 *	Find a per-socket client.
 */
static RADCLIENT *client_listener_find(const rad_listen_t *listener,
				       const lrad_ipaddr_t *ipaddr)
{
	const RADCLIENT_LIST *clients;

	rad_assert(listener != NULL);
	rad_assert(ipaddr != NULL);

	rad_assert((listener->type == RAD_LISTEN_AUTH) ||
		   (listener->type == RAD_LISTEN_ACCT));

	clients = ((listen_socket_t *)listener->data)->clients;
	if (!clients) clients = mainconfig.clients;

	rad_assert(clients != NULL);
	
	return client_find(clients, ipaddr);
}

static int listen_bind(rad_listen_t *this);

/*
 *	FIXME: have the detail reader use another config "exit when done",
 *	so that it can be used as a one-off tool to update stuff.
 */

/*
 *	Process and reply to a server-status request.
 *	Like rad_authenticate and rad_accounting this should
 *	live in it's own file but it's so small we don't bother.
 */
static int rad_status_server(REQUEST *request)
{
	char		reply_msg[64];
	time_t		t;
	VALUE_PAIR	*vp;

	/*
	 *	Reply with an ACK. We might want to add some more
	 *	interesting reply attributes, such as server uptime.
	 */
	t = request->timestamp - start_time;
	sprintf(reply_msg, "FreeRADIUS up %d day%s, %02d:%02d",
		(int)(t / 86400), (t / 86400) == 1 ? "" : "s",
		(int)((t / 3600) % 24), (int)(t / 60) % 60);
	request->reply->code = PW_AUTHENTICATION_ACK;

	vp = pairmake("Reply-Message", reply_msg, T_OP_SET);
	pairadd(&request->reply->vps, vp); /* don't need to check if !vp */

	return 0;
}

static int request_num_counter = 0;

/*
 *	Check for dups, etc.  Common to Access-Request &&
 *	Accounting-Request packets.
 */
static int common_checks(rad_listen_t *listener,
			 RADIUS_PACKET *packet, REQUEST **prequest,
			 const RADCLIENT *client)
{
	REQUEST	*curreq;
	char buffer[128];

	rad_assert(listener->rl != NULL);

	/*
	 *	If there is no existing request of id, code, etc.,
	 *	then we can return, and let it be processed.
	 */
	if ((curreq = rl_find(listener->rl, packet)) == NULL) {
		/*
		 *	Count the total number of requests, to see if
		 *	there are too many.  If so, return with an
		 *	error.
		 */
		if (mainconfig.max_requests) {
			/*
			 *	FIXME: This is now per-socket,
			 *	when it should really be global
			 *	to the server!
			 */
			int request_count = rl_num_requests(listener->rl);

			/*
			 *	This is a new request.  Let's see if
			 *	it makes us go over our configured
			 *	bounds.
			 */
			if (request_count > mainconfig.max_requests) {
				radlog(L_ERR, "Dropping request (%d is too many): "
				       "from client %s port %d - ID: %d", request_count,
				       client->shortname,
				       packet->src_port, packet->id);
				radlog(L_INFO, "WARNING: Please check the %s file.\n"
				       "\tThe value for 'max_requests' is probably set too low.\n", mainconfig.radiusd_conf);
				return 0;
			} /* else there were a small number of requests */
		} /* else there was no configured limit for requests */

		/*
		 *	FIXME: Add checks for system load.  If the
		 *	system is busy, start dropping requests...
		 *
		 *	We can probably keep some statistics
		 *	ourselves...  if there are more requests
		 *	coming in than we can handle, start dropping
		 *	some.
		 */

	/*
	 *	The current request isn't finished, which
	 *	means that the NAS sent us a new packet, while
	 *	we are still processing the old request.
	 */
	} else if (!curreq->finished) {
		/*
		 *	If the authentication vectors are identical,
		 *	then the NAS is re-transmitting it, trying to
		 *	kick us into responding to the request.
		 */
		if (memcmp(curreq->packet->vector, packet->vector,
			   sizeof(packet->vector)) == 0) {
			RAD_SNMP_INC(rad_snmp.auth.total_dup_requests);

			/*
			 *	It's not finished because the request
			 *	was proxied, but there was no reply
			 *	from the home server.
			 *
			 *	This code will never get hit for
			 *	accounting packets, as they're always
			 *	updated, and never re-transmitted.
			 */
			if (curreq->proxy && !curreq->proxy_reply) {
				DEBUG2("Sending duplicate proxied request to home server %s port %d - ID: %d",
				       inet_ntop(curreq->proxy->dst_ipaddr.af,
						 &curreq->proxy->dst_ipaddr.ipaddr,
						 buffer, sizeof(buffer)),					       curreq->proxy->dst_port,
				       
				       curreq->proxy->id);
				listener->send(curreq->proxy_listener, curreq);
				return 0;
			} /* else the packet was not proxied */

			/*
			 *	Someone's still working on it, so we
			 *	ignore the duplicate request.
			 */
			radlog(L_ERR, "Discarding duplicate request from "
			       "client %s port %d - ID: %d due to unfinished request %d",
			       client->shortname,
			       packet->src_port, packet->id,
			       curreq->number);
			return 0;
		} /* else the authentication vectors were different */

		/*
		 *	The authentication vectors are different, so
		 *	the NAS has given up on us, as we've taken too
		 *	long to process the request.  This is a
		 *	SERIOUS problem!
		 */
		RAD_SNMP_TYPE_INC(listener, total_packets_dropped);

		radlog(L_ERR, "Dropping conflicting packet from "
		       "client %s port %d - ID: %d due to unfinished request %d",
		       client->shortname,
		       packet->src_port, packet->id,
		       curreq->number);
		return 0;
		
		/*
		 *	The old request is finished.  We now check the
		 *	authentication vectors.  If the client has sent us a
		 *	request with identical code && ID, but different
		 *	vector, then they MUST have gotten our response, so we
		 *	can delete the original request, and process the new
		 *	one.
		 *
		 *	If the vectors are the same, then it's a duplicate
		 *	request, and we can send a duplicate reply.
		 */
	} else if (memcmp(curreq->packet->vector, packet->vector,
			  sizeof(packet->vector)) == 0) {
		RAD_SNMP_INC(rad_snmp.auth.total_dup_requests);

		/*
		 *	If the packet has been delayed, then silently
		 *	send a response, and clear the delayed flag.
		 *
		 *	Note that this means if the NAS kicks us while
		 *	we're delaying a reject, then the reject may
		 *	be sent sooner than otherwise.
		 *
		 *	This COULD be construed as a bug.  Maybe what
		 *	we want to do is to ignore the duplicate
		 *	packet, and send the reject later.
		 */
		if (curreq->options & RAD_REQUEST_OPTION_DELAYED_REJECT) {
			curreq->options &= ~RAD_REQUEST_OPTION_DELAYED_REJECT;
			rad_assert(curreq->listener == listener);
			listener->send(listener, curreq);
			return 0;
		}

		/*
		 *	Maybe we've saved a reply packet.  If so,
		 *	re-send it.  Otherwise, just complain.
		 */
		if (curreq->reply->code != 0) {
			DEBUG2("Sending duplicate reply "
			       "to client %s port %d - ID: %d",
			       client->shortname,
			       packet->src_port, packet->id);
			rad_assert(curreq->listener == listener);
			listener->send(listener, curreq);
			return 0;
		}

		/*
		 *	Else we never sent a reply to the NAS,
		 *	as we decided somehow we didn't like the request.
		 *
		 *	This shouldn't happen, in general...
		 */
		DEBUG2("Discarding duplicate request from client %s port %d - ID: %d",
		       client->shortname, packet->src_port, packet->id);
		return 0;
	} /* else the vectors were different, so we discard the old request. */

	/*
	 *	'packet' has the same source IP, source port, code,
	 *	and Id as 'curreq', but a different authentication
	 *	vector.  We can therefore delete 'curreq', as we were
	 *	only keeping it around to send out duplicate replies,
	 *	if the first reply got lost in the network.
	 */
	if (curreq) rl_delete(listener->rl, curreq);

	/*
	 *	A unique per-request counter.
	 */
	
	curreq = request_alloc(); /* never fails */
	curreq->listener = listener;
	curreq->packet = packet;
	curreq->number = request_num_counter++;
	strNcpy(curreq->secret, client->secret, sizeof(curreq->secret));
	
	/*
	 *	Remember the request in the list.
	 */
	rl_add(listener->rl, curreq);
	
	/*
	 *	ADD IN "server identifier" from "listen"
	 *	directive!
	 */
	
	/*
	 *	The request passes many of our sanity checks.
	 *	From here on in, if anything goes wrong, we
	 *	send a reject message, instead of dropping the
	 *	packet.
	 *
	 *	Build the reply template from the request
	 *	template.
		 */
	rad_assert(curreq->reply == NULL);
	if ((curreq->reply = rad_alloc(0)) == NULL) {
		radlog(L_ERR, "No memory");
		exit(1);
	}

	curreq->reply->sockfd = curreq->packet->sockfd;
	curreq->reply->dst_ipaddr = curreq->packet->src_ipaddr;
	curreq->reply->src_ipaddr = curreq->packet->dst_ipaddr;
	curreq->reply->dst_port = curreq->packet->src_port;
	curreq->reply->src_port = curreq->packet->dst_port;
	curreq->reply->id = curreq->packet->id;
	curreq->reply->code = 0; /* UNKNOWN code */
	memcpy(curreq->reply->vector, curreq->packet->vector,
	       sizeof(curreq->reply->vector));
	curreq->reply->vps = NULL;
	curreq->reply->data = NULL;
	curreq->reply->data_len = 0;

	*prequest = curreq;
	return 1;
}


static int socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	size_t len;
	listen_socket_t *sock = this->data;

	if ((sock->ipaddr.af == AF_INET) &&
	    (sock->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strcpy(buffer, "*");
	} else {
		ip_ntoh(&sock->ipaddr, buffer, bufsize);
	}

	len = strlen(buffer);

	return len + snprintf(buffer + len, bufsize - len, " port %d",
			      sock->port);
}


/*
 *	Parse an authentication or accounting socket.
 */
static int common_socket_parse(const char *filename, int lineno,
			     const CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	int		listen_port;
	lrad_ipaddr_t	ipaddr;
	listen_socket_t *sock;
	const char	*section_name = NULL;
	CONF_SECTION	*client_cs;

	this->data = sock = rad_malloc(sizeof(*sock));

	/*
	 *	Try IPv4 first
	 */
	ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(cs, "ipaddr", PW_TYPE_IPADDR,
			      &ipaddr.ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1;
	
	if (rcode == 0) { /* successfully parsed IPv4 */
		ipaddr.af = AF_INET;
		
	} else {	/* maybe IPv6? */
		rcode = cf_item_parse(cs, "ipv6addr", PW_TYPE_IPV6ADDR,
				      &ipaddr.ipaddr.ip6addr, NULL);
		if (rcode < 0) return -1;
		
		if (rcode == 1) {
			radlog(L_ERR, "%s[%d]: No address specified in listen section",
			       filename, lineno);
			return -1;
		}
		ipaddr.af = AF_INET6;
	}
	
	rcode = cf_item_parse(cs, "port", PW_TYPE_INTEGER,
			      &listen_port, "0");
	if (rcode < 0) return -1;
	
	sock->ipaddr = ipaddr;
	sock->port = listen_port;

	/*
	 *	And bind it to the port.
	 */
	if (listen_bind(this) < 0) {
		char buffer[128];
		radlog(L_CONS|L_ERR, "%s[%d]: Error binding to port for %s port %d",
		       filename, cf_section_lineno(cs),
		       ip_ntoh(&sock->ipaddr, buffer, sizeof(buffer)),
		       sock->port);
		return -1;
	}

	/*
	 *	If we can bind to interfaces, do so,
	 *	else don't.
	 */
	if (cf_pair_find(cs, "interface")) {
#ifndef SO_BINDTODEVICE
		radlog(L_CONS|L_ERR, "%s[%d]: System does not support binding to interfaces, delete this line from the configuration file.",
		       filename, cf_section_lineno(cs));
		return -1;
#else
		const char *value;
		const CONF_PAIR *cp = cf_pair_find(cs, "interface");
		struct ifreq ifreq;

		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		rad_assert(value != NULL);
		
		strcpy(ifreq.ifr_name, value);
	
		if (setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
			       (char *)&ifreq, sizeof(ifreq)) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed binding to interface %s: %s",
			       filename, cf_section_lineno(cs),
			       value, strerror(errno));
			return -1;
		} /* else it worked. */
#endif
	}

	/*
	 *	Look for the name of a section that holds a list
	 *	of clients.
	 */
	rcode = cf_item_parse(cs, "clients", PW_TYPE_STRING_PTR,
			      &section_name, NULL);
	if (rcode < 0) return -1; /* bad string */
	if (rcode > 0) return 0; /* non-existent is OK. */

	client_cs = cf_section_find(section_name);
	if (!client_cs) {
		radlog(L_CONS|L_ERR, "%s[%d]: Failed to find client section %s",
		       filename, cf_section_lineno(cs), section_name);
		return -1;
	}

	sock->clients = clients_parse_section(filename, client_cs);
	if (!sock->clients) {
		return -1;
	}

	return 0;
}

/*
 *	Send an authentication response packet
 */
static int auth_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == auth_socket_send);

	/*
	 *	Ensure that the reply is sane
	 */
	if (request->reply->code == 0) {
		DEBUG2("There was no response configured: rejecting request %d", request->number);
		request->reply->code = PW_AUTHENTICATION_REJECT;
	}

	/*
	 *	If we're delaying authentication rejects, then
	 *	mark the request as delayed, and do NOT send a
	 *	response right now.
	 *
	 *	However, if it's already marked as delayed, then
	 *	send it now.
	 */
	if ((request->reply->code == PW_AUTHENTICATION_REJECT) &&
	    ((request->options & RAD_REQUEST_OPTION_DELAYED_REJECT) == 0) &&
	    (mainconfig.reject_delay > 0) &&
	    ((request->options & RAD_REQUEST_OPTION_FAKE_REQUEST) == 0)) {
		DEBUG2("Delaying request %d for %d seconds",
		       request->number, mainconfig.reject_delay);
		request->options |= RAD_REQUEST_OPTION_DELAYED_REJECT;
		return 0;
	}

	return rad_send(request->reply, request->packet, request->secret);
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


	return rad_send(request->reply, request->packet, request->secret);

}


/*
 *	Send a packet to a home server.
 *
 *	FIXME: have different code for proxy auth & acct!
 */
static int proxy_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->proxy_listener == listener);
	rad_assert(listener->send == proxy_socket_send);
	return rad_send(request->proxy, request->packet, request->proxysecret);

}


/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int auth_socket_recv(rad_listen_t *listener,
			    RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;

	packet = rad_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", librad_errstr);
		return 0;
	}

	RAD_SNMP_TYPE_INC(listener, total_requests); /* FIXME: auth specific */

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr)) == NULL) {
		RAD_SNMP_TYPE_INC(listener, total_invalid_requests);
		
		radlog(L_ERR, "Ignoring request from unknown client %s port %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch(packet->code) {
	case PW_AUTHENTICATION_REQUEST:
		fun = rad_authenticate;
		break;
		
	case PW_STATUS_SERVER:
		if (!mainconfig.status_server) {
			DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
			rad_free(&packet);
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		RAD_SNMP_INC(rad_snmp.auth.total_unknown_types);
		
		radlog(L_ERR, "Invalid packet code %d sent to authentication port from client %s port %d "
		       "- ID %d : IGNORED",
		       packet->code, client->shortname,
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
		break;
	} /* switch over packet types */
	
	if (!common_checks(listener, packet, prequest, client)) {
		rad_free(&packet);
		return 0;
	}

	*pfun = fun;
	return 1;
}


/*
 *	Receive packets from an accounting socket
 */
static int acct_socket_recv(rad_listen_t *listener,
	RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;
	
	packet = rad_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", librad_errstr);
		return 0;
	}
	
	RAD_SNMP_TYPE_INC(listener, total_requests); /* FIXME: acct-specific */

	if ((client = client_listener_find(listener,
					   &packet->src_ipaddr)) == NULL) {
		RAD_SNMP_TYPE_INC(listener, total_invalid_requests);
		
		radlog(L_ERR, "Ignoring request from unknown client %s port %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port);
		rad_free(&packet);
		return 0;
	}

	switch(packet->code) {
	case PW_ACCOUNTING_REQUEST:
		fun = rad_accounting;
		break;
		
	default:
		/*
		 *	FIXME: Update MIB for packet types?
		 */
		radlog(L_ERR, "Invalid packet code %d sent to a accounting port "
		       "from client %s port %d - ID %d : IGNORED",
		       packet->code, client->shortname,
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	FIXME: Accounting duplicates should be handled
	 *	differently than authentication duplicates.
	 */
	if (!common_checks(listener, packet, prequest, client)) {
		rad_free(&packet);
		return 0;
	}

	*pfun = fun;
	return 1;
}


/*
 *	Recieve packets from a proxy socket.
 */
static int proxy_socket_recv(rad_listen_t *listener,
			      RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	REALM		*cl;
	REQUEST		*oldreq;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	
	packet = rad_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", librad_errstr);
		return 0;
	}

	/*
	 *	Unsupported stuff
	 */
	if (packet->src_ipaddr.af != AF_INET) {
		rad_assert("PROXY IPV6 NOT SUPPORTED" == NULL);
	}
	
	/*
	 *	FIXME: Add support for home servers!
	 */
	if ((cl = realm_findbyaddr(packet->src_ipaddr.ipaddr.ip4addr.s_addr,
				   packet->src_port)) == NULL) {
		radlog(L_ERR, "Ignoring request from unknown home server %s port %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
			       packet->src_port);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	FIXME: Client MIB updates?
	 */
	switch(packet->code) {
	case PW_AUTHENTICATION_ACK:
	case PW_ACCESS_CHALLENGE:
	case PW_AUTHENTICATION_REJECT:
		fun = rad_authenticate;
		break;
		
	case PW_ACCOUNTING_RESPONSE:
		fun = rad_accounting;
		break;
		
	default:
		/*
		 *	FIXME: Update MIB for packet types?
		 */
		radlog(L_ERR, "Invalid packet code %d sent to a proxy port "
		       "from home server %s port %d - ID %d : IGNORED",
		       packet->code,
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	Find the original request in the request list
	 */
	oldreq = rl_find_proxy(packet);

	/*
	 *	If we haven't found the original request which was
	 *	sent, to get this reply.  Complain, and discard this
	 *	request, as there's no way for us to send it to a NAS.
	 */
	if (!oldreq) {
		radlog(L_PROXY, "No outstanding request was found for proxy reply from home server %s port %d - ID %d",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	The proxy reply has arrived too late, as the original
	 *	(old) request has timed out, been rejected, and marked
	 *	as finished.  The client has already received a
	 *	response, so there is nothing that can be done. Delete
	 *	the tardy reply from the home server, and return nothing.
	 */
	if ((oldreq->reply->code != 0) ||
	    (oldreq->finished)) {
		radlog(L_ERR, "Reply from home server %s port %d  - ID: %d arrived too late for request %d. Try increasing 'retry_delay' or 'max_request_time'",
		       inet_ntop(packet->src_ipaddr.af,
				 &packet->src_ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       packet->src_port, packet->id,
		       oldreq->number);
		rad_free(&packet);
		return 0;
	}

	/*
	 *	If there is already a reply, maybe this one is a
	 *	duplicate?
	 */
	if (oldreq->proxy_reply) {
		if (memcmp(oldreq->proxy_reply->vector,
			   packet->vector,
			   sizeof(oldreq->proxy_reply->vector)) == 0) {
			radlog(L_ERR, "Discarding duplicate reply from home server %s port %d  - ID: %d for request %d",
			       inet_ntop(packet->src_ipaddr.af,
					 &packet->src_ipaddr.ipaddr,
					 buffer, sizeof(buffer)),
			       packet->src_port, packet->id,
			       oldreq->number);
		} else {
			/*
			 *	? The home server gave us a new proxy
			 *	reply, which doesn't match the old
			 *	one.  Delete it.
			 */
			DEBUG2("Ignoring conflicting proxy reply");
		}

		/*
		 *	We've already received a reply, so
		 *	we discard this one, as we don't want
		 *	to do duplicate work.
		 */
		rad_free(&packet);
		return 0;
	} /* else there wasn't a proxy reply yet, so we can process it */

	/*
	 *	 Refresh the old request, and update it with the proxy
	 *	 reply.
	 *
	 *	? Can we delete the proxy request here?  * Is there
	 *	any more need for it?
	 *
	 *	FIXME: we probably shouldn't be updating the time
	 *	stamp here.
	 */
	oldreq->timestamp = time_now;
	oldreq->proxy_reply = packet;

	/*
	 *	FIXME: we should really verify the digest here,
	 *	before marking this packet as a valid response.
	 *
	 *	This is a security problem, I think...
	 */

	/*
	 *	Now that we've verified the packet IS actually from
	 *	that home server, and not forged, we can go mark the
	 *	entries for this home server as active.
	 *
	 *	If we had done this check in the 'find realm by IP address'
	 *	function, then an attacker could force us to use a home
	 *	server which was inactive, by forging reply packets
	 *	which didn't match any request.  We would think that
	 *	the reply meant the home server was active, would
	 *	re-activate the realms, and THEN bounce the packet
	 *	as garbage.
	 */
	for (cl = mainconfig.realms; cl != NULL; cl = cl->next) {
		if (oldreq->proxy_reply->src_ipaddr.af != cl->ipaddr.af) continue;
		if (cl->ipaddr.af != AF_INET) continue; /* FIXME */

		if (oldreq->proxy_reply->src_ipaddr.ipaddr.ip4addr.s_addr == cl->ipaddr.ipaddr.ip4addr.s_addr) {
			if (oldreq->proxy_reply->src_port == cl->auth_port) {
				cl->active = TRUE;
				cl->last_reply = oldreq->timestamp;
			} else if (oldreq->proxy_reply->src_port == cl->acct_port) {
				cl->acct_active = TRUE;
				cl->last_reply = oldreq->timestamp;
			}
		}
	}

	rad_assert(fun != NULL);
	*pfun = fun;
	*prequest = oldreq;

	return 1;
}

#define STATE_UNOPENED	(0)
#define STATE_UNLOCKED	(1)
#define STATE_HEADER	(2)
#define STATE_READING	(3)
#define STATE_DONE	(4)
#define STATE_WAITING	(5)

/*
 *	If we're limiting outstanding packets, then mark the response
 *	as being sent.
 */
static int detail_send(rad_listen_t *listener, REQUEST *request)
{
	listen_detail_t *data = listener->data;

	rad_assert(request->listener == listener);
	rad_assert(listener->send == detail_send);

	if (request->simul_max >= 0) {
		rad_assert(data->outstanding != NULL);
		rad_assert(request->simul_max < data->max_outstanding);

		data->outstanding[request->simul_max] = 0;
	}

	return 0;
}


/*
 *	Open the detail file..
 *
 *	FIXME: create it, if it's not already there, so that the main
 *	server select() will wake us up if there's anything to read.
 */
static int detail_open(rad_listen_t *this)
{
	struct stat st;
	char buffer[2048];
	listen_detail_t *data = this->data;

	rad_assert(data->state == STATE_UNOPENED);
	snprintf(buffer, sizeof(buffer), "%s.work", data->detail);
	
	/*
	 *	FIXME: Have "one-shot" configuration, where it
	 *	will read the detail file, and exit once it's
	 *	done.
	 *
	 *	FIXME: Try harder to open the detail file.
	 *	Maybe sleep for X usecs if it doesn't exist?
	 */

	/*
	 *	Open detail.work first, so we don't lose
	 *	accounting packets.  It's probably better to
	 *	duplicate them than to lose them.
	 *
	 *	Note that we're not writing to the file, but
	 *	we've got to open it for writing in order to
	 *	establish the lock, to prevent rlm_detail from
	 *	writing to it.
	 */
	this->fd = open(buffer, O_RDWR);
	if (this->fd < 0) {
		/*
		 *	Try reading the detail file.  If it
		 *	doesn't exist, we can't do anything.
		 *
		 *	Doing the stat will tell us if the file
		 *	exists, even if we don't have permissions
		 *	to read it.
		 */
		if (stat(data->detail, &st) < 0) {
			return 0;
		}
		
		/*
		 *	Open it BEFORE we rename it, just to
		 *	be safe...
		 */
		this->fd = open(data->detail, O_RDWR);
		if (this->fd < 0) {
			radlog(L_ERR, "Failed to open %s: %s",
			       data->detail, strerror(errno));
			return 0;
		}
		
		/*
		 *	Rename detail to detail.work
		 */
		if (rename(data->detail, buffer) < 0) {
			close(this->fd);
			this->fd = -1;
			return 0;
		}
	} /* else detail.work existed, and we opened it */
	
	rad_assert(data->vps == NULL);
	
	rad_assert(data->fp == NULL);
	data->fp = fdopen(this->fd, "r");
	if (!data->fp) {
		radlog(L_ERR, "Failed to re-open %s: %s",
		       data->detail, strerror(errno));
		return 0;
	}

	data->state = STATE_UNLOCKED;

	data->client_ip.af = AF_UNSPEC;
	data->timestamp = 0;
	
	return 1;
}

/*
 *	This is a bad hack, just so complaints have meaningful text.
 */
static const RADCLIENT detail_client = {
	{		/* ipaddr */
		AF_INET,
		{{ INADDR_NONE }}
	},
	32,
	"<detail-file>",
	"secret",
	"UNKNOWN-CLIENT",
	"other",
	"",
	"",
	-1
};

static int detail_recv(rad_listen_t *listener,
		       RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	int		free_slot = -1;
	char		key[256], value[1024];
	VALUE_PAIR	*vp, **tail;
	RADIUS_PACKET	*packet;
	char		buffer[2048];
	listen_detail_t *data = listener->data;

	if (data->state == STATE_UNOPENED) {
		rad_assert(listener->fd < 0);
		if (!detail_open(listener)) return 0;
	}
	rad_assert(listener->fd >= 0);

	/*
	 *	Try to lock fd.  If we can't, return.  If we can,
	 *	continue.  This means that the server doesn't block
	 *	while waiting for the lock to open...
	 */
	if (data->state == STATE_UNLOCKED) {
		/*
		 *	Note that we do NOT block waiting for the
		 *	lock.  We've re-named the file above, so we've
		 *	already guaranteed that any *new* detail
		 *	writer will not be opening this file.  The
		 *	only purpose of the lock is to catch a race
		 *	condition where the execution "ping-pongs"
		 *	between radiusd & radrelay.
		 */
		if (rad_lockfd_nonblock(listener->fd, 0) < 0) {
			return 0;
		}
		/*
		 *	Look for the header
		 */
		data->state = STATE_HEADER;
	}

	/*
	 *	If we keep track of the outstanding requests, do so
	 *	here.  Note that to minimize potential work, we do
	 *	so only once the file is opened & locked.
	 */
	if (data->max_outstanding) {
		int i;

		for (i = 0; i < data->max_outstanding; i++) {
			if (!data->outstanding[i]) {
				free_slot = i;
				break;
			}
		}

		/*
		 *	All of the slots are full, don't read data.
		 */
		if (free_slot < 0) return 0;
	}

	/*
	 *	Catch an out of memory condition which will most likely
	 *	never be met.
	 */
	if (data->state == STATE_DONE) goto alloc_packet;

	/*
	 *	If we're in another state, then it means that we read
	 *	a partial packet, which is bad.
	 */
	rad_assert(data->state == STATE_HEADER);
	rad_assert(data->vps == NULL);

	/*
	 *	We read the last packet, and returned it for
	 *	processing.  We later come back here to shut
	 *	everything down, and unlink the file.
	 */
	if (feof(data->fp)) {
		rad_assert(data->state == STATE_HEADER);

		/*
		 *	Don't unlink the file until we've received
		 *	all of the responses.
		 */
		if (data->max_outstanding > 0) {
			int i;

			for (i = 0; i < data->max_outstanding; i++) {
				/*
				 *	FIXME: close the file?
				 */
				if (data->outstanding[i]) {
					data->state = STATE_WAITING;
					return 0;
				}
			}
		}

	cleanup:
		rad_assert(data->vps == NULL);

		snprintf(buffer, sizeof(buffer), "%s.work", data->detail);
		unlink(buffer);
		fclose(data->fp); /* closes listener->fd */
		data->fp = NULL;
		listener->fd = -1;
		data->state = STATE_UNOPENED;

		/*
		 *	Try to open "detail" again.  If we're on a
		 *	busy RADIUS server, odds are that it will
		 *	now exist.
		 */
		detail_open(listener);
		return 0;
	}

	tail = &data->vps;

	/*
	 *	Fill the buffer...
	 */
	while (fgets(buffer, sizeof(buffer), data->fp)) {
		/*
		 *	No CR, die.
		 */
		if (!strchr(buffer, '\n')) {
			pairfree(&data->vps);
			goto cleanup;
		}

		/*
		 *	We've read a header, possibly packet contents,
		 *	and are now at the end of the packet.
		 */
		if ((data->state == STATE_READING) &&
		    (buffer[0] == '\n')) {
			data->state = STATE_DONE;
			break;
		}

		/*
		 *	Look for date/time header, and read VP's if
		 *	found.  If not, keep reading lines until we
		 *	find one.
		 */
		if (data->state == STATE_HEADER) {
			int y;
			
			if (sscanf(buffer, "%*s %*s %*d %*d:%*d:%*d %d", &y)) {
				data->state = STATE_READING;
			}
			continue;
		}

		/*
		 *	We have a full "attribute = value" line.
		 *	If it doesn't look reasonable, skip it.
		 */
		if (sscanf(buffer, "%255s = %1023s", key, value) != 2) {
			continue;
		}

		/*
		 *	Skip non-protocol attributes.
		 */
		if (!strcasecmp(key, "Request-Authenticator")) continue;

		/*
		 *	Set the original client IP address, based on
		 *	what's in the detail file.
		 *
		 *	Hmm... we don't set the server IP address.
		 *	or port.  Oh well.
		 */
		if (!strcasecmp(key, "Client-IP-Address")) {
			data->client_ip.af = AF_INET;
			ip_hton(value, AF_INET, &data->client_ip);
			continue;
		}

		/*
		 *	The original time at which we received the
		 *	packet.  We need this to properly calculate
		 *	Acct-Delay-Time.
		 */
		if (!strcasecmp(key, "Timestamp")) {
			data->timestamp = atoi(value);
			continue;
		}

		/*
		 *	Read one VP.
		 *
		 *	FIXME: do we want to check for non-protocol
		 *	attributes like radsqlrelay does?
		 */
		vp = NULL;
		if ((userparse(buffer, &vp) > 0) &&
		    (vp != NULL)) {
			*tail = vp;
			tail = &(vp->next);
		}		
	}

	/*
	 *	We got to EOF,  If we're in STATE_HEADER, it's OK.
	 *	Otherwise it's a problem.  In any case, nuke the file
	 *	and start over from scratch,
	 */
	if (feof(data->fp)) {
		goto cleanup;
	}

	/*
	 *	FIXME: Do load management.
	 */

	/*
	 *	If we're not done, then there's a problem.  The checks
	 *	above for EOF
	 */
	rad_assert(data->state == STATE_DONE);

	/*
	 *	The packet we read was empty, re-set the state to look
	 *	for a header, and don't return anything.
	 */
	if (!data->vps) {
		data->state = STATE_HEADER;
		return 0;
	}

	/*
	 *	Allocate the packet.  If we fail, it's a serious
	 *	problem.
	 */
 alloc_packet:
	packet = rad_alloc(1);
	if (!packet) {
		return 0;	/* maybe memory will magically free up... */
	}

	memset(packet, 0, sizeof(*packet));
	packet->sockfd = -1;
	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	packet->code = PW_ACCOUNTING_REQUEST;
	packet->timestamp = time(NULL);

	/*
	 *	Look for Acct-Delay-Time, and update
	 *	based on Acct-Delay-Time += (time(NULL) - timestamp)
	 */
	vp = pairfind(packet->vps, PW_ACCT_DELAY_TIME);
	if (!vp) {
		vp = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
		rad_assert(vp != NULL);
	}
	if (data->timestamp != 0) {
		vp->lvalue += time(NULL) - data->timestamp;
	}

	/*
	 *	Remember where it came from, so that we don't
	 *	proxy it to the place it came from...
	 */
	if (data->client_ip.af != AF_UNSPEC) {
		packet->src_ipaddr = data->client_ip;
	}

	/*
	 *	We've got to give SOME value for Id & ports, so that
	 *	the packets can be added to the request queue.
	 *	However, we don't want to keep track of used/unused
	 *	id's and ports, as that's a lot of work.  This hack
	 *	ensures that (if we have real random numbers), that
	 *	there will be a collision on every (2^(16+16+2+24))/2
	 *	packets, on average.  That means we can read 2^32 (4G)
	 *	packets before having a collision, which means it's
	 *	effectively impossible.  Having 4G packets currently
	 *	being process is ridiculous.
	 */
	packet->id = lrad_rand() & 0xff;
	packet->src_port = lrad_rand() & 0xffff;
	packet->dst_port = lrad_rand() & 0xffff;

	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl((INADDR_LOOPBACK & ~0xffffff) | (lrad_rand() & 0xffffff));

	packet->vps = data->vps;

	/*
	 *	Re-set the state.
	 */
	data->vps = NULL;
	data->state = STATE_HEADER;

	/*
	 *	FIXME: many of these checks may not be necessary...
	 */
	if (!common_checks(listener, packet, prequest, &detail_client)) {
		rad_free(&packet);
		return 0;
	}

	/*
	 *	Keep track of free slots, as a hack, in an otherwise
	 *	unused 'int'
	 */
	(*prequest)->simul_max = free_slot;
	if (free_slot) data->outstanding[free_slot] = 1;

	*pfun = rad_accounting;

	if (debug_flag) {
		printf("detail_recv: Read packet from %s\n", data->detail);
		for (vp = packet->vps; vp; vp = vp->next) {
			putchar('\t');
			vp_print(stdout, vp);
			putchar('\n');
		}
	}

	return 1;
}


/*
 *	Free detail-specific stuff.
 */
static void detail_free(rad_listen_t *this)
{
	listen_detail_t *data = this->data;

	free(data->detail);
	pairfree(&data->vps);
	free(data->outstanding);

	if (data->fp != NULL) fclose(data->fp);
}


static int detail_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	return snprintf(buffer, bufsize, "%s",
			((listen_detail_t *)(this->data))->detail);
}


/*
 *	Parse a detail section.
 */
static int detail_parse(const char *filename, int lineno,
			const CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	const char	*detail = NULL;
	listen_detail_t *data;

	this->data = data = rad_malloc(sizeof(*data));

	rcode = cf_item_parse(cs, "detail", PW_TYPE_STRING_PTR,
			      &detail, NULL);
	if (rcode < 0) return -1;
	if (rcode == 1) {
		radlog(L_ERR, "%s[%d]: No detail file specified in listen section",
		       filename, lineno);
		return -1;
	}
	
	data->detail = detail;
	data->vps = NULL;
	data->fp = NULL;
	data->state = STATE_UNOPENED;
	
	rcode = cf_item_parse(cs, "max_outstanding",
			      PW_TYPE_INTEGER,
			      &(data->max_outstanding), "100");
	if (rcode < 0) return -1;
	if (data->max_outstanding > 0) {
		data->outstanding = rad_malloc(sizeof(int) * data->max_outstanding);
	}
	
	detail_open(this);

	return 0;
}


/*
 *	See radiusd.c & request_list.c
 */
#define SLEEP_FOREVER (65536)
/*
 *	A generic "update the request list once a second" function.
 */
static int generic_update(rad_listen_t *this, time_t now)
{
	if (!this->rl) return SLEEP_FOREVER;

	return rl_clean_list(this->rl, now);
}



static const rad_listen_master_t master_listen[RAD_LISTEN_MAX] = {
	{ NULL, NULL, NULL, NULL, NULL, NULL},	/* RAD_LISTEN_NONE */

	/* authentication */
	{ common_socket_parse, NULL,
	  auth_socket_recv, auth_socket_send,
	  generic_update, socket_print },

	/* accounting */
	{ common_socket_parse, NULL,
	  acct_socket_recv, acct_socket_send,
	  generic_update, socket_print},

	/* proxying */
	{ NULL, NULL,
	  proxy_socket_recv, proxy_socket_send,
	  generic_update, socket_print }, /* FIXME: update func is wrong! */

	/* detail */
	{ detail_parse, detail_free,
	  detail_recv, detail_send,
	  generic_update, detail_print }
};


/*
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
	struct sockaddr salocal;
	socklen_t	salen;
	rad_listen_t	**last;
	listen_socket_t *sock = this->data;

	/*
	 *	If the port is zero, then it means the appropriate
	 *	thing from /etc/services.
	 */
	if (sock->port == 0) {
		struct servent	*svp;

		switch (this->type) {
		case RAD_LISTEN_AUTH:
			svp = getservbyname ("radius", "udp");
			if (svp != NULL) {
				sock->port = ntohs(svp->s_port);
			} else {
				sock->port = PW_AUTH_UDP_PORT;
			}
			break;

		case RAD_LISTEN_ACCT:
			svp = getservbyname ("radacct", "udp");
			if (svp != NULL) {
				sock->port = ntohs(svp->s_port);
			} else {
				sock->port = PW_ACCT_UDP_PORT;
			}
			break;

		default:
			radlog(L_ERR|L_CONS, "ERROR: Non-fatal internal sanity check failed in bind.");
			return -1;
		}
	}

	/*
	 *	Find it in the old list, AFTER updating the port.  If
	 *	it's there, use that, rather than creating a new
	 *	socket.  This allows HUP's to re-use the old sockets,
	 *	which means that packets waiting in the socket queue
	 *	don't get lost.
	 */
	for (last = &mainconfig.listen;
	     *last != NULL;
	     last = &((*last)->next)) {
		if ((this->type == (*last)->type) &&
		    (sock->port == ((listen_socket_t *)((*last)->data))->port) &&
		    (sock->ipaddr.af == ((listen_socket_t *)((*last)->data))->ipaddr.af)) {
			int equal;

			if (sock->ipaddr.af == AF_INET) {
				equal = (sock->ipaddr.ipaddr.ip4addr.s_addr == ((listen_socket_t *)((*last)->data))->ipaddr.ipaddr.ip4addr.s_addr);
			} else if (sock->ipaddr.af == AF_INET6) {
				equal = IN6_ARE_ADDR_EQUAL(&(sock->ipaddr.ipaddr.ip6addr), &(((listen_socket_t *)((*last)->data))->ipaddr.ipaddr.ip6addr));
			} else {
				equal = 0;
			}
			
			if (equal) {
				this->fd = (*last)->fd;
				(*last)->fd = -1;
				return 0;
			}
		}
	}

	/*
	 *	Create the socket.
	 */
	this->fd = socket(sock->ipaddr.af, SOCK_DGRAM, 0);
	if (this->fd < 0) {
		radlog(L_ERR|L_CONS, "ERROR: Failed to open socket: %s",
		       strerror(errno));
		return -1;
	}
	

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(this->fd) != 0) {
		radlog(L_ERR|L_CONS, "ERROR: udpfromto init failed.");
	}
#endif

	if (sock->ipaddr.af == AF_INET) {
		struct sockaddr_in *sa;

		sa = (struct sockaddr_in *) &salocal;
		memset(sa, 0, sizeof(salocal));
		sa->sin_family = AF_INET;
		sa->sin_addr = sock->ipaddr.ipaddr.ip4addr;
		sa->sin_port = htons(sock->port);
		salen = sizeof(*sa);

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	} else if (sock->ipaddr.af == AF_INET6) {
		struct sockaddr_in6 *sa;

		sa = (struct sockaddr_in6 *) &salocal;
		memset(sa, 0, sizeof(salocal));
		sa->sin6_family = AF_INET6;
		sa->sin6_addr = sock->ipaddr.ipaddr.ip6addr;
		sa->sin6_port = htons(sock->port);
		salen = sizeof(*sa);

		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY
		if (IN6_IS_ADDR_UNSPECIFIED(&sock->ipaddr.ipaddr.ip6addr)) {
			int on = 1;
			
			setsockopt(this->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				   (char *)&on, sizeof(on));
		}
#endif /* IPV6_V6ONLY */
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */
	} else {
		radlog(L_ERR|L_CONS, "ERROR: Unsupported protocol family %d",
		       sock->ipaddr.af);
		close(this->fd);
		this->fd = -1;
		return -1;
	}

	if (bind(this->fd, &salocal, salen) < 0) {
		char buffer[128];

		radlog(L_ERR|L_CONS, "ERROR: Bind to %s port %d failed: %s",
		       inet_ntop(sock->ipaddr.af, &sock->ipaddr.ipaddr,
				 buffer, sizeof(buffer)),
		       sock->port, strerror(errno));
				 
		close(this->fd);
		this->fd = -1;
		return -1;
	}

	return 0;
}


/*
 *	Externally visible function for creating a new proxy LISTENER.
 *
 *	For now, don't take ipaddr or port.
 *
 *	Not thread-safe, but all calls to it are protected by the
 *	proxy mutex in request_list.c
 */
rad_listen_t *proxy_new_listener()
{
	int last_proxy_port, port;
	rad_listen_t *this, *tmp, **last;
	listen_socket_t *sock, *old;

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));
	this->data = rad_malloc(sizeof(*sock));
	memset(this->data, 0, sizeof(*sock));

	/*
	 *	Find an existing proxy socket to copy.
	 *
	 *	FIXME: Make it per-realm, or per-home server!
	 */
	last_proxy_port = 0;
	old = NULL;
	last = &mainconfig.listen;
	for (tmp = mainconfig.listen; tmp != NULL; tmp = tmp->next) {
		if (tmp->type == RAD_LISTEN_PROXY) {
			sock = tmp->data;
			if (sock->port > last_proxy_port) {
				last_proxy_port = sock->port + 1;
			}
			if (!old) old = sock;
		}

		last = &(tmp->next);
	}

	if (!old) return NULL;	/* This is a serious error. */

	/*
	 *	FIXME: find a new IP address to listen on?
	 */
	sock = this->data;
	memcpy(&sock->ipaddr, &old->ipaddr, sizeof(sock->ipaddr));
	this->type = RAD_LISTEN_PROXY;

	this->recv = master_listen[RAD_LISTEN_PROXY].recv;
	this->send = master_listen[RAD_LISTEN_PROXY].send;
	this->update = master_listen[RAD_LISTEN_PROXY].update;
	this->print = master_listen[RAD_LISTEN_PROXY].print;

	/*
	 *	Keep going until we find an unused port.
	 */
	for (port = last_proxy_port; port < 64000; port++) {
		sock->port = port;
		if (listen_bind(this) == 0) {
			/*
			 *	Add the new listener to the list of
			 *	listeners.
			 */
			*last = this;
			return this;
		}
	}

	return NULL;
}


static const LRAD_NAME_NUMBER listen_compare[] = {
	{ "auth",	RAD_LISTEN_AUTH },
	{ "acct",	RAD_LISTEN_ACCT },
	{ "detail",	RAD_LISTEN_DETAIL },
	{ NULL, 0 },
};


/*
 *	Generate a list of listeners.  Takes an input list of
 *	listeners, too, so we don't close sockets with waiting packets.
 */
int listen_init(const char *filename, rad_listen_t **head)
{
	int		rcode;
	CONF_SECTION	*cs;
	rad_listen_t	**last;
	rad_listen_t	*this;
	lrad_ipaddr_t	server_ipaddr;
	int		auth_port = 0;

	/*
	 *	We shouldn't be called with a pre-existing list.
	 */
	rad_assert(head && (*head == NULL));
	
	if (start_time != 0) start_time = time(NULL);

	last = head;
	server_ipaddr.af = AF_UNSPEC;

	/*
	 *	If the port is specified on the command-line,
	 *	it over-rides the configuration file.
	 */
	if (mainconfig.port >= 0) {
		auth_port = mainconfig.port;
	} else {
		rcode = cf_item_parse(mainconfig.config, "port",
				      PW_TYPE_INTEGER, &auth_port,
				      Stringify(PW_AUTH_UDP_PORT));
		if (rcode < 0) return -1; /* error parsing it */

		if (rcode == 0)
			radlog(L_INFO, "WARNING: The directive 'port' is deprecated, and will be removed in future versions of FreeRADIUS. Please edit the configuration files to use the directive 'listen'.");
	}

	/*
	 *	If the IP address was configured on the command-line,
	 *	use that as the "bind_address"
	 */
	if (mainconfig.myip.af != AF_UNSPEC) {
		memcpy(&server_ipaddr, &mainconfig.myip,
		       sizeof(server_ipaddr));
		goto bind_it;
	}

	/*
	 *	Else look for bind_address and/or listen sections.
	 */
	server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(mainconfig.config, "bind_address",
			      PW_TYPE_IPADDR,
			      &server_ipaddr.ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1; /* error parsing it */
	
	if (rcode == 0) { /* successfully parsed IPv4 */
		listen_socket_t *sock;
		server_ipaddr.af = AF_INET;

		radlog(L_INFO, "WARNING: The directive 'bind_adress' is deprecated, and will be removed in future versions of FreeRADIUS. Please edit the configuration files to use the directive 'listen'.");

	bind_it:
		this = rad_malloc(sizeof(*this));
		memset(this, 0, sizeof(*this));
		this->data = sock = rad_malloc(sizeof(*sock));
		memset(sock, 0, sizeof(*sock));
		
		/*
		 *	Create the authentication socket.
		 */
		this->type = RAD_LISTEN_AUTH;
		sock->ipaddr = server_ipaddr;
		sock->port = auth_port;
		
		if (listen_bind(this) < 0) {
			radlog(L_CONS|L_ERR, "There appears to be another RADIUS server running on the authentication port %d", sock->port);
			free(this);
			return -1;
		}
		auth_port = sock->port;	/* may have been updated in listen_bind */
		this->recv = master_listen[this->type].recv;
		this->send = master_listen[this->type].send;
		this->update = master_listen[this->type].update;
		this->print = master_listen[this->type].print;

		*last = this;
		last = &(this->next);
		
		/*
		 *	Open Accounting Socket.
		 *
		 *	If we haven't already gotten acct_port from
		 *	/etc/services, then make it auth_port + 1.
		 */
		this = rad_malloc(sizeof(*this));
		memset(this, 0, sizeof(*this));
		this->data = sock = rad_malloc(sizeof(*sock));
		memset(sock, 0, sizeof(*sock));
		
		/*
		 *	Create the accounting socket.
		 *
		 *	The accounting port is always the
		 *	authentication port + 1
		 */
		this->type = RAD_LISTEN_ACCT;
		sock->ipaddr = server_ipaddr;
		sock->port = auth_port + 1;
		
		if (listen_bind(this) < 0) {
			radlog(L_CONS|L_ERR, "There appears to be another RADIUS server running on the accounting port %d", sock->port);
			free(this);
			return -1;
		}

		this->recv = master_listen[this->type].recv;
		this->send = master_listen[this->type].send;
		this->update = master_listen[this->type].update;
		this->print = master_listen[this->type].print;

		*last = this;
		last = &(this->next);

	} else if (mainconfig.port > 0) { /* no bind address, but a port */
		radlog(L_CONS|L_ERR, "The command-line says \"-p %d\", but there is no associated IP address to use",
		       mainconfig.port);
		return -1;
	}

	/*
	 *	They specified an IP on the command-line, ignore
	 *	all listen sections.
	 */
	if (mainconfig.myip.af != AF_UNSPEC) goto do_proxy;

	/*
	 *	Walk through the "listen" sections, if they exist.
	 */
	for (cs = cf_subsection_find_next(mainconfig.config, NULL, "listen");
	     cs != NULL;
	     cs = cf_subsection_find_next(mainconfig.config, cs, "listen")) {
		int		type;
		char		*listen_type, *identity;
		int		lineno = cf_section_lineno(cs);

		listen_type = identity = NULL;
		
		rcode = cf_item_parse(cs, "type", PW_TYPE_STRING_PTR,
				      &listen_type, "");
		if (rcode < 0) return -1;
		if (rcode == 1) {
			free(listen_type);
			radlog(L_ERR, "%s[%d]: No type specified in listen section",
			       filename, lineno);
			return -1;
		}

		/*
		 *	FIXME: We leak identity if we return, but who
		 *	cares...  the server will kill itself anyhow.
		 */
		rcode = cf_item_parse(cs, "identity", PW_TYPE_STRING_PTR,
				      &identity, NULL);
		if (rcode < 0) return -1;

		type = lrad_str2int(listen_compare, listen_type,
				    RAD_LISTEN_NONE);
		if (type == RAD_LISTEN_NONE) {
			radlog(L_CONS|L_ERR, "%s[%d]: Invalid type in listen section.",
			       filename, lineno);
			return -1;
		}

		/*
		 *	Set up cross-type data.
		 */
		this = rad_malloc(sizeof(*this));
		memset(this, 0, sizeof(*this));
		
		this->type = type;
		this->identity = identity;
		this->fd = -1;
		
		this->recv = master_listen[type].recv;
		this->send = master_listen[type].send;
		this->update = master_listen[type].update;
		this->print = master_listen[type].print;

		/*
		 *	Call per-type parsers, if they're necessary.
		 */
		rad_assert(master_listen[type].parse != NULL);
		if (master_listen[type].parse(filename, lineno,
					      cs, this) < 0) {
			listen_free(&this);
			listen_free(head);
			return -1;
		}

		*last = this;
		last = &(this->next);	
	}

	/*
	 *	If we're proxying requests, open the proxy FD.
	 *	Otherwise, don't do anything.
	 */
 do_proxy:
	if (mainconfig.proxy_requests == TRUE) {
		int		port = -1;
		listen_socket_t *sock = NULL;

		/*
		 *	No sockets to receive packets, therefore
		 *	proxying is pointless.
		 */
		if (!*head) return -1;

		/*
		 *	Find the first authentication port,
		 *	and use it
		 */
		for (this = *head; this != NULL; this = this->next) {
			if (this->type == RAD_LISTEN_AUTH) {
				sock = this->data;
				if (server_ipaddr.af == AF_UNSPEC) {
					server_ipaddr = sock->ipaddr;
				}
				port = sock->port + 2; /* skip acct port */
				break;
			}
		}
		rad_assert(port > 0); /* must have found at least one entry! */

		/*
		 *	Address is still unspecified, use IPv4.
		 */
		if (server_ipaddr.af == AF_UNSPEC) {
			server_ipaddr.af = AF_INET;
			server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_ANY);
		}

		this = rad_malloc(sizeof(*this));
		memset(this, 0, sizeof(*this));
		this->data = sock = rad_malloc(sizeof(*sock));
		memset(sock, 0, sizeof(*sock));

		/*
		 *	Create the first proxy socket.
		 */
		this->type = RAD_LISTEN_PROXY;
		sock->ipaddr = server_ipaddr;

		this->recv = master_listen[RAD_LISTEN_PROXY].recv;
		this->send = master_listen[RAD_LISTEN_PROXY].send;
		this->update = master_listen[RAD_LISTEN_PROXY].update;
		this->print = master_listen[RAD_LISTEN_PROXY].print;

		/*
		 *	Try to find a proxy port (value doesn't matter)
		 */
		for (sock->port = port;
		     sock->port < 64000;
		     sock->port++) {
			if (listen_bind(this) == 0) {
				*last = this;
				last = &(this->next); /* just in case */
				break;
			}
		}

		if (sock->port >= 64000) {
			radlog(L_ERR|L_CONS, "Failed to open socket for proxying");
			free(this);
			return -1;
		}
	}

	/*
	 *	Sanity check the configuration.
	 */
	rcode = 0;
	for (this = *head; this != NULL; this = this->next) {
		if (this->type != RAD_LISTEN_PROXY) {
			/*
			 *	FIXME: Pass type to rl_init, so that
			 *	it knows how to deal with accounting
			 *	packets.  i.e. it caches them, but
			 *	doesn't bother trying to re-transmit.
			 */
			this->rl = rl_init();
			if (!this->rl) {
				rad_assert(0 == 1); /* FIXME: */
			}
		}

		if (((this->type == RAD_LISTEN_ACCT) &&
		     (rcode == RAD_LISTEN_DETAIL)) ||
		    ((this->type == RAD_LISTEN_DETAIL) &&
		     (rcode == RAD_LISTEN_ACCT))) {
			rad_assert(0 == 1); /* FIXME: configuration error */
		}

		if (rcode != 0) continue;

		if ((this->type == RAD_LISTEN_ACCT) ||
		    (this->type == RAD_LISTEN_DETAIL)) {
			rcode = this->type;
		}
	}

	return 0;
}

/*
 *	Free a linked list of listeners;
 */
void listen_free(rad_listen_t **head)
{
	rad_listen_t *this;

	if (!head || !*head) return;

	this = *head;
	while (this) {
		rad_listen_t *next = this->next;
		
		free(this->identity);

		rl_deinit(this->rl);

		/*
		 *	Other code may have eaten the FD.
		 */
		if (this->fd >= 0) close(this->fd);

		if (master_listen[this->type].free) {
			master_listen[this->type].free(this);
		}
		free(this->data);
		free(this);
		
		this = next;
	}

	*head = NULL;
}
