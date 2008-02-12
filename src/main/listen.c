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
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2005,2006  The FreeRADIUS server project
 * Copyright 2005  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius_snmp.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/vqp.h>

#include <freeradius-devel/vmps.h>
#include <freeradius-devel/detail.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif


/*
 *	We'll use this below.
 */
typedef int (*rad_listen_parse_t)(CONF_SECTION *, rad_listen_t *);
typedef void (*rad_listen_free_t)(rad_listen_t *);

typedef struct rad_listen_master_t {
	rad_listen_parse_t	parse;
	rad_listen_free_t	free;
	rad_listen_recv_t	recv;
	rad_listen_send_t	send;
	rad_listen_print_t	print;
	rad_listen_encode_t	encode;
	rad_listen_decode_t	decode;
} rad_listen_master_t;

typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	ipaddr;
	int		port;
	RADCLIENT_LIST	*clients;
} listen_socket_t;

/*
 *	Find a per-socket client.
 */
RADCLIENT *client_listener_find(const rad_listen_t *listener,
				       const fr_ipaddr_t *ipaddr)
{
	const RADCLIENT_LIST *clients;

	rad_assert(listener != NULL);
	rad_assert(ipaddr != NULL);

	rad_assert((listener->type == RAD_LISTEN_AUTH) ||
		   (listener->type == RAD_LISTEN_ACCT) ||
		   (listener->type == RAD_LISTEN_VQP));

	clients = ((listen_socket_t *)listener->data)->clients;

	/*
	 *	This HAS to have been initialized previously.
	 */
	rad_assert(clients != NULL);

	return client_find(clients, ipaddr);
}

static int listen_bind(rad_listen_t *this);


/*
 *	Process and reply to a server-status request.
 *	Like rad_authenticate and rad_accounting this should
 *	live in it's own file but it's so small we don't bother.
 */
static int rad_status_server(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	DICT_VALUE *dval;

	switch (request->listener->type) {
	case RAD_LISTEN_AUTH:
		dval = dict_valbyname(PW_AUTZ_TYPE, "Status-Server");
		if (dval) {
			rcode = module_authorize(dval->value, request);
		} else {
			rcode = RLM_MODULE_OK;
		}

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = PW_AUTHENTICATION_ACK;
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_HANDLED:
			request->reply->code = 0; /* don't reply */
			break;

		default:
		case RLM_MODULE_REJECT:
			request->reply->code = PW_AUTHENTICATION_REJECT;
			break;
		}
		break;

	case RAD_LISTEN_ACCT:
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
		break;

	default:
		return 0;
	}

	return 0;
}


static int socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	listen_socket_t *sock = this->data;
	const char *name;
	char ip_buf[256];

	if ((sock->ipaddr.af == AF_INET) &&
	    (sock->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strcpy(ip_buf, "*");
	} else {
		ip_ntoh(&sock->ipaddr, ip_buf, sizeof(ip_buf));
	}

	switch (this->type) {
	case RAD_LISTEN_AUTH:
		name = "authentication";
		break;

	case RAD_LISTEN_ACCT:
		name = "accounting";
		break;

	case RAD_LISTEN_PROXY:
		name = "proxy";
		break;

#ifdef WITH_VMPS
	case RAD_LISTEN_VQP:
		name = "vmps";
		break;
#endif

	default:
		name = "??";
		break;
	}

	if (!this->server) {
		return snprintf(buffer, bufsize, "%s address %s port %d",
				name, ip_buf, sock->port);
	}

	return snprintf(buffer, bufsize, "%s address %s port %d as server %s",
			name, ip_buf, sock->port, this->server);
}


/*
 *	Parse an authentication or accounting socket.
 */
static int common_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	int		listen_port;
	fr_ipaddr_t	ipaddr;
	listen_socket_t *sock = this->data;
	char		*section_name = NULL;
	CONF_SECTION	*client_cs, *parentcs;

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
			cf_log_err(cf_sectiontoitem(cs),
				   "No address specified in listen section");
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
		cf_log_err(cf_sectiontoitem(cs),
			   "Error binding to port for %s port %d",
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
		cf_log_err(cf_sectiontoitem(cs),
			   "System does not support binding to interfaces.  Delete this line from the configuration file.");
		return -1;
#else
		const char *value;
		CONF_PAIR *cp = cf_pair_find(cs, "interface");
		struct ifreq ifreq;

		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No interface name given");
			return -1;
		}

		strcpy(ifreq.ifr_name, value);

		if (setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
			       (char *)&ifreq, sizeof(ifreq)) < 0) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed binding to interface %s: %s",
				   value, strerror(errno));
			return -1;
		} /* else it worked. */
#endif
	}
	
	/*
	 *	The more specific configurations are preferred to more
	 *	generic ones.
	 */
	client_cs = NULL;
	rcode = cf_item_parse(cs, "clients", PW_TYPE_STRING_PTR,
			      &section_name, NULL);
	if (rcode < 0) return -1; /* bad string */
	if (rcode == 0) {
		/*
		 *	Explicit list given: use it.
		 */
		client_cs = cf_section_find(section_name);
		if (!client_cs) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed to find clients %s {...}",
				   section_name);
			free(section_name);
			return -1;
		}
		free(section_name);
	} /* else there was no "clients = " entry. */

	parentcs = cf_top_section(cs);
	if (!client_cs) {
		CONF_SECTION *server_cs;

		server_cs = cf_section_sub_find_name2(parentcs,
						      "server",
						      this->server);
		/*
		 *	Found a "server foo" section.  If there are clients
		 *	in it, use them.
		 */
		if (server_cs &&
		    (cf_section_sub_find(server_cs, "client") != NULL)) {
			client_cs = server_cs;
		}
	}

	/*
	 *	Still nothing.  Look for global clients.
	 */
	if (!client_cs) client_cs = parentcs;

	sock->clients = clients_parse_section(client_cs);
	if (!sock->clients) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Failed to find any clients for this listen section");
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

	return rad_send(request->reply, request->packet,
			request->client->secret);
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


/*
 *	Send a packet to a home server.
 *
 *	FIXME: have different code for proxy auth & acct!
 */
static int proxy_socket_send(rad_listen_t *listener, REQUEST *request)
{
	listen_socket_t *sock = listener->data;

	rad_assert(request->proxy_listener == listener);
	rad_assert(listener->send == proxy_socket_send);

	request->proxy->src_ipaddr = sock->ipaddr;
	request->proxy->src_port = sock->port;

	return rad_send(request->proxy, request->packet,
			request->home_server->secret);
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
	ssize_t		rcode;
	int		code, src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;
	fr_ipaddr_t	src_ipaddr;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	RAD_SNMP_TYPE_INC(listener, total_requests);

	if (rcode < 20) {	/* AUTH_HDR_LEN */
		RAD_SNMP_TYPE_INC(listener, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr)) == NULL) {
		rad_recv_discard(listener->fd);
		RAD_SNMP_TYPE_INC(listener, total_invalid_requests);

		if (debug_flag > 0) {
			char name[1024];

			listener->print(listener, name, sizeof(name));

			/*
			 *	This is debugging rather than logging, so that
			 *	DoS attacks don't affect us.
			 */
			DEBUG("Ignoring request to %s from unknown client %s port %d",
			      name,
			      inet_ntop(src_ipaddr.af, &src_ipaddr.ipaddr,
					buffer, sizeof(buffer)), src_port);
		}

		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch(code) {
	case PW_AUTHENTICATION_REQUEST:
		RAD_SNMP_CLIENT_INC(listener, client, requests);
		fun = rad_authenticate;
		break;

	case PW_STATUS_SERVER:
		if (!mainconfig.status_server) {
			rad_recv_discard(listener->fd);
			RAD_SNMP_TYPE_INC(listener, total_packets_dropped);
			RAD_SNMP_CLIENT_INC(listener, client, packets_dropped);
			DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		RAD_SNMP_INC(rad_snmp.auth.total_unknown_types);
		RAD_SNMP_CLIENT_INC(listener, client, unknown_types);

		DEBUG("Invalid packet code %d sent to authentication port from client %s port %d : IGNORED",
		      code, client->shortname, src_port);
		return 0;
		break;
	} /* switch over packet types */

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(listener->fd, client->message_authenticator);
	if (!packet) {
		RAD_SNMP_TYPE_INC(listener, total_malformed_requests);
		DEBUG("%s", librad_errstr);
		return 0;
	}

	if (!received_request(listener, packet, prequest, client)) {
		RAD_SNMP_TYPE_INC(listener, total_packets_dropped);
		RAD_SNMP_CLIENT_INC(listener, client, packets_dropped);
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
	ssize_t		rcode;
	int		code, src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;
	fr_ipaddr_t	src_ipaddr;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	RAD_SNMP_TYPE_INC(listener, total_requests);

	if (rcode < 20) {	/* AUTH_HDR_LEN */
		RAD_SNMP_TYPE_INC(listener, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr)) == NULL) {
		rad_recv_discard(listener->fd);
		RAD_SNMP_TYPE_INC(listener, total_invalid_requests);

		/*
		 *	This is debugging rather than logging, so that
		 *	DoS attacks don't affect us.
		 */
		if (debug_flag > 0) {
			char name[1024];

			listener->print(listener, name, sizeof(name));

			DEBUG("Ignoring request to %s from unknown client %s port %d",
			      name,
			      inet_ntop(src_ipaddr.af, &src_ipaddr.ipaddr,
					buffer, sizeof(buffer)), src_port);
		}

		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch(code) {
	case PW_ACCOUNTING_REQUEST:
		RAD_SNMP_CLIENT_INC(listener, client, requests);
		fun = rad_accounting;
		break;

	case PW_STATUS_SERVER:
		if (!mainconfig.status_server) {
			rad_recv_discard(listener->fd);
			RAD_SNMP_TYPE_INC(listener, total_packets_dropped);
			RAD_SNMP_CLIENT_INC(listener, client, unknown_types);

			DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		RAD_SNMP_TYPE_INC(listener, total_unknown_types);
		RAD_SNMP_CLIENT_INC(listener, client, unknown_types);

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
		RAD_SNMP_TYPE_INC(listener, total_malformed_requests);
		radlog(L_ERR, "%s", librad_errstr);
		return 0;
	}

	/*
	 *	There can be no duplicate accounting packets.
	 */
	if (!received_request(listener, packet, prequest, client)) {
		RAD_SNMP_TYPE_INC(listener, total_packets_dropped);
		RAD_SNMP_CLIENT_INC(listener, client, packets_dropped);
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
	REQUEST		*request;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];

	packet = rad_recv(listener->fd, 0);
	if (!packet) {
		radlog(L_ERR, "%s", librad_errstr);
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

	request = received_proxy_response(packet);
	if (!request) {
		return 0;
	}

	rad_assert(fun != NULL);
	*pfun = fun;
	*prequest = request;

	return 1;
}


static int client_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (!request->reply->code) return 0;

	rad_encode(request->reply, request->packet,
		   request->client->secret);
	rad_sign(request->reply, request->packet,
		 request->client->secret);

	return 0;
}


static int client_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (rad_verify(request->packet, NULL,
		       request->client->secret) < 0) {
		return -1;
	}

	return rad_decode(request->packet, NULL,
			  request->client->secret);
}

static int proxy_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	rad_encode(request->proxy, NULL, request->home_server->secret);
	rad_sign(request->proxy, NULL, request->home_server->secret);

	return 0;
}


static int proxy_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (rad_verify(request->proxy_reply, request->proxy,
		       request->home_server->secret) < 0) {
		return -1;
	}

	return rad_decode(request->proxy_reply, request->proxy,
			   request->home_server->secret);
}


#ifdef WITH_SNMP
static int radius_snmp_recv(rad_listen_t *listener,
			    UNUSED RAD_REQUEST_FUNP *pfun,
			    UNUSED REQUEST **prequest)
{
	if ((rad_snmp.smux_fd >= 0) &&
	    (rad_snmp.smux_event == SMUX_READ)) {
		smux_read();
	}

	/*
	 *  If we've got to re-connect, then do so now,
	 *  before calling select again.
	 */
	if (rad_snmp.smux_event == SMUX_CONNECT) {
		smux_connect();
	}

	/*
	 *	Reset this every time, as the smux connect may have
	 *	opened a new socket.
	 */
	listener->fd = rad_snmp.smux_fd;

	return 0;
}


static int radius_snmp_print(UNUSED rad_listen_t *this, char *buffer, size_t bufsize)
{
	return snprintf(buffer, bufsize, "SMUX with OID .1.3.6.1.4.1.11344.1.1.1");
}

#endif

static const rad_listen_master_t master_listen[RAD_LISTEN_MAX] = {
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL},	/* RAD_LISTEN_NONE */

	/* proxying */
	{ NULL, NULL,
	  proxy_socket_recv, proxy_socket_send,
	  socket_print, proxy_socket_encode, proxy_socket_decode },

	/* authentication */
	{ common_socket_parse, NULL,
	  auth_socket_recv, auth_socket_send,
	  socket_print, client_socket_encode, client_socket_decode },

	/* accounting */
	{ common_socket_parse, NULL,
	  acct_socket_recv, acct_socket_send,
	  socket_print, client_socket_encode, client_socket_decode},

	/* detail */
	{ detail_parse, detail_free,
	  detail_recv, detail_send,
	  detail_print, detail_encode, detail_decode },

#ifdef WITH_VMPS
	/* vlan query protocol */
	{ common_socket_parse, NULL,
	  vqp_socket_recv, vqp_socket_send,
	  socket_print, vqp_socket_encode, vqp_socket_decode },
#else
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL},
#endif

	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL}	/* RAD_LISTEN_SNMP */
};



/*
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
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

#ifdef WITH_VMPS
		case RAD_LISTEN_VQP:
			sock->port = 1589;
			break;
#endif

		default:
			radlog(L_ERR, "ERROR: Non-fatal internal sanity check failed in bind.");
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
		listen_socket_t *other;

		if (this->type != (*last)->type) continue;

		if ((this->type == RAD_LISTEN_DETAIL) ||
		    (this->type == RAD_LISTEN_SNMP)) continue;

		other = (listen_socket_t *)((*last)->data);

		if ((sock->port == other->port) &&
		    (sock->ipaddr.af == other->ipaddr.af) &&
		    (fr_ipaddr_cmp(&sock->ipaddr, &other->ipaddr) == 0)) {
			this->fd = (*last)->fd;
			(*last)->fd = -1;
			return 0;
		}
	}

	this->fd = fr_socket(&sock->ipaddr, sock->port);
	if (this->fd < 0) {
		radlog(L_ERR, "ERROR: Failed to open socket: %s",
		       librad_errstr);
		return -1;
	}

	/*
	 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
	 *	kernel instead binds us to a 1.2.3.4.  If this
	 *	happens, notice, and remember our real IP.
	 */
	{
		struct sockaddr_storage	src;
		socklen_t	        sizeof_src = sizeof(src);

		memset(&src, 0, sizeof_src);
		if (getsockname(this->fd, (struct sockaddr *) &src,
				&sizeof_src) < 0) {
			radlog(L_ERR, "Failed getting socket name: %s",
			       strerror(errno));
			return -1;
		}

		if (src.ss_family == AF_INET) {
			struct sockaddr_in	*s4;
			
			s4 = (struct sockaddr_in *)&src;
			sock->ipaddr.ipaddr.ip4addr = s4->sin_addr;
			
#ifdef HAVE_STRUCT_SOCKADDR_IN6
		} else if (src.ss_family == AF_INET6) {
			struct sockaddr_in6	*s6;
			
			s6 = (struct sockaddr_in6 *)&src;
			sock->ipaddr.ipaddr.ip6addr = s6->sin6_addr;
#endif
		} else {
			radlog(L_ERR, "Socket has unsupported address family");
			return -1;
		}
	}

#ifdef O_NONBLOCK
	{
		int flags;
		
		if ((flags = fcntl(this->fd, F_GETFL, NULL)) < 0)  {
			radlog(L_ERR, "Failure getting socket flags: %s)\n",
			       strerror(errno));
			return -1;
		}
		
		flags |= O_NONBLOCK;
		if( fcntl(this->fd, F_SETFL, flags) < 0) {
			radlog(L_ERR, "Failure setting socket flags: %s)\n",
			       strerror(errno));
			return -1;
		}
	}
#endif

	return 0;
}


/*
 *	Allocate & initialize a new listener.
 */
static rad_listen_t *listen_alloc(RAD_LISTEN_TYPE type)
{
	rad_listen_t *this;

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	this->type = type;
	this->recv = master_listen[this->type].recv;
	this->send = master_listen[this->type].send;
	this->print = master_listen[this->type].print;
	this->encode = master_listen[this->type].encode;
	this->decode = master_listen[this->type].decode;

	switch (type) {
	case RAD_LISTEN_AUTH:
	case RAD_LISTEN_ACCT:
	case RAD_LISTEN_PROXY:
	case RAD_LISTEN_VQP:
		this->data = rad_malloc(sizeof(listen_socket_t));
		memset(this->data, 0, sizeof(listen_socket_t));
		break;

	case RAD_LISTEN_DETAIL:
		this->data = NULL;
		break;

	default:
		rad_assert("Unsupported option!" == NULL);
		break;
	}

	return this;
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

	this = listen_alloc(RAD_LISTEN_PROXY);

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

	if (!old) {
		listen_free(&this);
		return NULL;	/* This is a serious error. */
	}

	/*
	 *	FIXME: find a new IP address to listen on?
	 *
	 *	This could likely be done in the "home server"
	 *	configuration, to have per-home-server source IP's.
	 */
	sock = this->data;
	memcpy(&sock->ipaddr, &old->ipaddr, sizeof(sock->ipaddr));

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

	listen_free(&this);
	return NULL;
}


static const FR_NAME_NUMBER listen_compare[] = {
	{ "auth",	RAD_LISTEN_AUTH },
	{ "acct",	RAD_LISTEN_ACCT },
	{ "detail",	RAD_LISTEN_DETAIL },
#ifdef WITH_VMPS
	{ "vmps",	RAD_LISTEN_VQP },
#endif
	{ NULL, 0 },
};


static rad_listen_t *listen_parse(CONF_SECTION *cs, const char *server)
{
	int		type, rcode;
	char		*listen_type;
	rad_listen_t	*this;

	listen_type = NULL;
	
	cf_log_info(cs, "listen {");

	rcode = cf_item_parse(cs, "type", PW_TYPE_STRING_PTR,
			      &listen_type, "");
	if (rcode < 0) return NULL;
	if (rcode == 1) {
		free(listen_type);
		cf_log_err(cf_sectiontoitem(cs),
			   "No type specified in listen section");
		return NULL;
	}

	type = fr_str2int(listen_compare, listen_type,
			    RAD_LISTEN_NONE);
	if (type == RAD_LISTEN_NONE) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Invalid type \"%s\" in listen section.",
			   listen_type);
		free(listen_type);
		return NULL;
	}
	free(listen_type);
	
	/*
	 *	Allow listen sections in the default config to
	 *	refer to a server.
	 */
	if (!server) {
		rcode = cf_item_parse(cs, "virtual_server", PW_TYPE_STRING_PTR,
				      &server, NULL);
		if (rcode == 1) { /* compatiblity with 2.0-pre */
			rcode = cf_item_parse(cs, "server", PW_TYPE_STRING_PTR,
					      &server, NULL);
		}
		if (rcode < 0) return NULL;
	}

	/*
	 *	Set up cross-type data.
	 */
	this = listen_alloc(type);
	this->server = server;
	this->fd = -1;

	/*
	 *	Call per-type parser.
	 */
	if (master_listen[type].parse(cs, this) < 0) {
		listen_free(&this);
		return NULL;
	}

	cf_log_info(cs, "}");

	return this;
}

/*
 *	Generate a list of listeners.  Takes an input list of
 *	listeners, too, so we don't close sockets with waiting packets.
 */
int listen_init(CONF_SECTION *config, rad_listen_t **head)
{
	int		override = FALSE;
	int		rcode;
	CONF_SECTION	*cs;
	rad_listen_t	**last;
	rad_listen_t	*this;
	fr_ipaddr_t	server_ipaddr;
	int		auth_port = 0;

	/*
	 *	We shouldn't be called with a pre-existing list.
	 */
	rad_assert(head && (*head == NULL));

	last = head;
	server_ipaddr.af = AF_UNSPEC;

	/*
	 *	If the port is specified on the command-line,
	 *	it over-rides the configuration file.
	 *
	 *	FIXME: If argv[0] == "vmpsd", then don't listen on auth/acct!
	 */
	if (mainconfig.port >= 0) auth_port = mainconfig.port;

	/*
	 *	If the IP address was configured on the command-line,
	 *	use that as the "bind_address"
	 */
	if (mainconfig.myip.af != AF_UNSPEC) {
		memcpy(&server_ipaddr, &mainconfig.myip,
		       sizeof(server_ipaddr));
		override = TRUE;
		goto bind_it;
	}

	/*
	 *	Else look for bind_address and/or listen sections.
	 */
	server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(config, "bind_address",
			      PW_TYPE_IPADDR,
			      &server_ipaddr.ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1; /* error parsing it */

	if (rcode == 0) { /* successfully parsed IPv4 */
		listen_socket_t *sock;
		server_ipaddr.af = AF_INET;

		radlog(L_INFO, "WARNING: The directive 'bind_adress' is deprecated, and will be removed in future versions of FreeRADIUS. Please edit the configuration files to use the directive 'listen'.");

	bind_it:
#ifdef WITH_VMPS
		if (strcmp(progname, "vmpsd") == 0) {
			this = listen_alloc(RAD_LISTEN_VQP);
			if (!auth_port) auth_port = 1589;
		} else
#endif
			this = listen_alloc(RAD_LISTEN_AUTH);

		sock = this->data;

		sock->ipaddr = server_ipaddr;
		sock->port = auth_port;

		sock->clients = clients_parse_section(config);
		if (!sock->clients) {
			cf_log_err(cf_sectiontoitem(config),
				   "Failed to find any clients for this listen section");
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			radlog(L_ERR, "There appears to be another RADIUS server running on the authentication port %d", sock->port);
			return -1;
		}
		auth_port = sock->port;	/* may have been updated in listen_bind */
		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       mainconfig.name);
			if (cs) this->server = mainconfig.name;
		}

		*last = this;
		last = &(this->next);

#ifdef WITH_VMPS
		/*
		 *	No acct for vmpsd
		 */
		if (strcmp(progname, "vmpsd") == 0) goto do_proxy;
#endif

		/*
		 *	Open Accounting Socket.
		 *
		 *	If we haven't already gotten acct_port from
		 *	/etc/services, then make it auth_port + 1.
		 */
		this = listen_alloc(RAD_LISTEN_ACCT);
		sock = this->data;

		/*
		 *	Create the accounting socket.
		 *
		 *	The accounting port is always the
		 *	authentication port + 1
		 */
		sock->ipaddr = server_ipaddr;
		sock->port = auth_port + 1;

		sock->clients = clients_parse_section(config);
		if (!sock->clients) {
			cf_log_err(cf_sectiontoitem(config),
				   "Failed to find any clients for this listen section");
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			radlog(L_ERR, "There appears to be another RADIUS server running on the accounting port %d", sock->port);
			return -1;
		}

		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       mainconfig.name);
			if (cs) this->server = mainconfig.name;
		}

		*last = this;
		last = &(this->next);

	} else if (mainconfig.port > 0) { /* no bind address, but a port */
		radlog(L_ERR, "The command-line says \"-p %d\", but there is no associated IP address to use",
		       mainconfig.port);
		return -1;
	}

	/*
	 *	They specified an IP on the command-line, ignore
	 *	all listen sections except the one in '-n'.
	 */
	if (mainconfig.myip.af != AF_UNSPEC) {
		CONF_SECTION *subcs;
		const char *name2 = cf_section_name2(cs);

		cs = cf_section_sub_find_name2(config, "server",
					       mainconfig.name);
		if (!cs) goto do_proxy;

		/*
		 *	Should really abstract this code...
		 */
		for (subcs = cf_subsection_find_next(cs, NULL, "listen");
		     subcs != NULL;
		     subcs = cf_subsection_find_next(cs, subcs, "listen")) {
			this = listen_parse(subcs, name2);
			if (!this) {
				listen_free(head);
				return -1;
			}
			
			*last = this;
			last = &(this->next);
		} /* loop over "listen" directives in server <foo> */

		goto do_proxy;
	}

	/*
	 *	Walk through the "listen" sections, if they exist.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "listen");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "listen")) {
		this = listen_parse(cs, NULL);
		if (!this) {
			listen_free(head);
			return -1;
		}

		*last = this;
		last = &(this->next);
	}

	/*
	 *	Check virtual servers for "listen" sections, too.
	 *
	 *	FIXME: Move to virtual server init?
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		CONF_SECTION *subcs;
		const char *name2 = cf_section_name2(cs);
		
		for (subcs = cf_subsection_find_next(cs, NULL, "listen");
		     subcs != NULL;
		     subcs = cf_subsection_find_next(cs, subcs, "listen")) {
			this = listen_parse(subcs, name2);
			if (!this) {
				listen_free(head);
				return -1;
			}
			
			*last = this;
			last = &(this->next);
		} /* loop over "listen" directives in virtual servers */
	} /* loop over virtual servers */

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
		 *	If we previously had proxy sockets, copy them
		 *	to the new config.
		 */
		if (mainconfig.listen != NULL) {
			rad_listen_t *old, *next, **tail;

			tail = &mainconfig.listen;
			for (old = mainconfig.listen;
			     old != NULL;
			     old = next) {
				next = old->next;

				if (old->type != RAD_LISTEN_PROXY) {
					tail = &((*tail)->next);
					continue;
				}

				*last = old;
				*tail = next;
				old->next = NULL;
				last = &(old->next);
			}

			goto do_snmp;
		}

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
			if (this->type == RAD_LISTEN_VQP) {
				sock = this->data;
				if (server_ipaddr.af == AF_UNSPEC) {
					server_ipaddr = sock->ipaddr;
				}
				port = sock->port + 1;
				break;
			}
		}

		if (port < 0) port = 1024 + (fr_rand() & 0x1ff);

		/*
		 *	Address is still unspecified, use IPv4.
		 */
		if (server_ipaddr.af == AF_UNSPEC) {
			server_ipaddr.af = AF_INET;
			server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_ANY);
		}

		this = listen_alloc(RAD_LISTEN_PROXY);
		sock = this->data;

		/*
		 *	Create the first proxy socket.
		 */
		sock->ipaddr = server_ipaddr;

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
			listen_free(head);
			listen_free(&this);
			radlog(L_ERR, "Failed to open socket for proxying");
			return -1;
		}
	}

 do_snmp:
#ifdef WITH_SNMP
	if (radius_snmp_init(config)) {
		/*
		 *      Forget about the old one.
		 */
		for (this = mainconfig.listen;
		     this != NULL;
		     this = this->next) {
			if (this->type != RAD_LISTEN_SNMP) continue;
			this->fd = -1;
		}

		this = rad_malloc(sizeof(*this));
		memset(this, 0, sizeof(*this));

		this->type = RAD_LISTEN_SNMP;
		this->fd = rad_snmp.smux_fd;

		this->recv = radius_snmp_recv;
		this->print = radius_snmp_print;

		*last = this;
		last = &(this->next);
	}
#endif

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
