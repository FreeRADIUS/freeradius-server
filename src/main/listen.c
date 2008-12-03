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
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/vqp.h>
#include <freeradius-devel/dhcp.h>

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
#ifdef SO_BINDTODEVICE
	const char		*interface;
#endif
	RADCLIENT_LIST	*clients;
} listen_socket_t;

static rad_listen_t *listen_alloc(RAD_LISTEN_TYPE type);

/*
 *	Find a per-socket client.
 */
RADCLIENT *client_listener_find(const rad_listen_t *listener,
				const fr_ipaddr_t *ipaddr, int src_port)
{
#ifdef WITH_DYNAMIC_CLIENTS
	int rcode;
	listen_socket_t *sock;
	REQUEST *request;
	RADCLIENT *created;
#endif
	time_t now;
	RADCLIENT *client;
	RADCLIENT_LIST *clients;

	rad_assert(listener != NULL);
	rad_assert(ipaddr != NULL);

	rad_assert((listener->type == RAD_LISTEN_AUTH)
#ifdef WITH_STATS
		   || (listener->type == RAD_LISTEN_NONE)
#endif
#ifdef WITH_ACCOUNTING
		   || (listener->type == RAD_LISTEN_ACCT)
#endif
#ifdef WITH_VMPS
		   || (listener->type == RAD_LISTEN_VQP)
#endif
#ifdef WITH_DHCP
		   || (listener->type == RAD_LISTEN_DHCP)
#endif
		   );

	clients = ((listen_socket_t *)listener->data)->clients;

	/*
	 *	This HAS to have been initialized previously.
	 */
	rad_assert(clients != NULL);

	client = client_find(clients, ipaddr);
	if (!client) {
		static time_t last_printed = 0;
		char name[256], buffer[128];
					
#ifdef WITH_DYNAMIC_CLIENTS
	unknown:		/* used only for dynamic clients */
#endif

		/*
		 *	DoS attack quenching, but only in debug mode.
		 *	If they're running in debug mode, show them
		 *	every packet.
		 */
		if (debug_flag == 0) {
			now = time(NULL);
			if (last_printed == now) return NULL;
			
			last_printed = now;
		}

		listener->print(listener, name, sizeof(name));

		radlog(L_ERR, "Ignoring request to %s from unknown client %s port %d",
		       name, inet_ntop(ipaddr->af, &ipaddr->ipaddr,
				       buffer, sizeof(buffer)),
		       src_port);
		return NULL;
	}

#ifndef WITH_DYNAMIC_CLIENTS
	return client;		/* return the found client. */
#else

	/*
	 *	No server defined, and it's not dynamic.  Return it.
	 */
	if (!client->client_server && !client->dynamic) return client;

	now = time(NULL);
	
	/*
	 *	It's a dynamically generated client, check it.
	 */
	if (client->dynamic) {
		/*
		 *	Lives forever.  Return it.
		 */
		if (client->lifetime == 0) return client;
		
		/*
		 *	Rate-limit the deletion of known clients.
		 *	This makes them last a little longer, but
		 *	prevents the server from melting down if (say)
		 *	10k clients all expire at once.
		 */
		if (now == client->last_new_client) return client;

		/*
		 *	It's not dead yet.  Return it.
		 */
		if ((client->created + client->lifetime) > now) return client;
		
		/*
		 *	It's dead, Jim.  Delete it.
		 */
		client_delete(clients, client);

		/*
		 *	Go find the enclosing network again.
		 */
		client = client_find(clients, ipaddr);

		/*
		 *	WTF?
		 */
		if (!client) goto unknown;
		if (!client->client_server) goto unknown;

		/*
		 *	At this point, 'client' is the enclosing
		 *	network that configures where dynamic clients
		 *	can be defined.
		 */
		rad_assert(client->dynamic == 0);
	} else {
		/*
		 *	The IP is unknown, so we've found an enclosing
		 *	network.  Enable DoS protection.  We only
		 *	allow one new client per second.  Known
		 *	clients aren't subject to this restriction.
		 */
		if (now == client->last_new_client) goto unknown;
	}

	client->last_new_client = now;

	request = request_alloc();
	if (!request) goto unknown;

	request->listener = listener;
	request->client = client;
	request->packet = rad_alloc(0);
	if (!request->packet) {
		request_free(&request);
		goto unknown;
	}
	request->reply = rad_alloc(0);
	if (!request->reply) {
		request_free(&request);
		goto unknown;
	}
	request->packet->timestamp = request->timestamp;
	request->number = 0;
	request->priority = listener->type;
	request->server = client->client_server;
	request->root = &mainconfig;

	/*
	 *	Run a fake request through the given virtual server.
	 *	Look for FreeRADIUS-Client-IP-Address
	 *	         FreeRADIUS-Client-Secret
	 *		...
	 *
	 *	and create the RADCLIENT structure from that.
	 */

	sock = listener->data;
	request->packet->sockfd = listener->fd;
	request->packet->src_ipaddr = *ipaddr;
	request->packet->src_port = 0; /* who cares... */
	request->packet->dst_ipaddr = sock->ipaddr;
	request->packet->dst_port = sock->port;

	request->reply->sockfd = request->packet->sockfd;
	request->reply->dst_ipaddr = request->packet->src_ipaddr;
	request->reply->src_ipaddr = request->packet->dst_ipaddr;
	request->reply->dst_port = request->packet->src_port;
	request->reply->src_port = request->packet->dst_port;
	request->reply->id = request->packet->id;
	request->reply->code = 0; /* UNKNOWN code */

	
	DEBUG("server %s {", request->server);

	rcode = module_authorize(0, request);

	DEBUG("} # server %s", request->server);

	if (rcode != RLM_MODULE_OK) {
		request_free(&request);
		goto unknown;
	}

	/*
	 *	If the client was updated by rlm_dynamic_clients,
	 *	don't create the client from attribute-value pairs.
	 */
	if (request->client == client) {
		created = client_create(clients, request);
	} else {
		created = request->client;

		/*
		 *	This frees the client if it isn't valid.
		 */
		if (!client_validate(clients, client, created)) goto unknown;
	}
	request_free(&request);

	if (!created) goto unknown;

	return created;
#endif
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
#ifdef WITH_STATS
	case RAD_LISTEN_NONE:
#endif
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

#ifdef WITH_ACCOUNTING
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
#endif

	default:
		return 0;
	}

#ifdef WITH_STATS
	/*
	 *	Full statistics are available only on a statistics
	 *	socket.
	 */
	if (request->listener->type == RAD_LISTEN_NONE) {
		request_stats_reply(request);
	}
#endif

	return 0;
}


static int socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	size_t len;
	listen_socket_t *sock = this->data;
	const char *name;

	switch (this->type) {
#ifdef WITH_STATS
	case RAD_LISTEN_NONE:	/* what a hack... */
		name = "status";
		break;
#endif

	case RAD_LISTEN_AUTH:
		name = "authentication";
		break;

#ifdef WITH_ACCOUNTING
	case RAD_LISTEN_ACCT:
		name = "accounting";
		break;
#endif

#ifdef WITH_PROXY
	case RAD_LISTEN_PROXY:
		name = "proxy";
		break;
#endif

#ifdef WITH_VMPS
	case RAD_LISTEN_VQP:
		name = "vmps";
		break;
#endif

#ifdef WITH_DHCP
	case RAD_LISTEN_DHCP:
		name = "dhcp";
		break;
#endif

	default:
		name = "??";
		break;
	}

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len
#define ADDSTRING(_x) strlcpy(buffer, _x, bufsize);FORWARD

	ADDSTRING(name);

#ifdef SO_BINDTODEVICE
	if (sock->interface) {
		ADDSTRING(" interface ");
		ADDSTRING(sock->interface);
	}
#endif

	ADDSTRING(" address ");
	
	if ((sock->ipaddr.af == AF_INET) &&
	    (sock->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strlcpy(buffer, "*", bufsize);
	} else {
		ip_ntoh(&sock->ipaddr, buffer, bufsize);
	}
	FORWARD;

	ADDSTRING(" port ");
	snprintf(buffer, bufsize, "%d", sock->port);
	FORWARD;

	if (this->server) {
		ADDSTRING(" as server ");
		ADDSTRING(this->server);
	}

#undef ADDSTRING
#undef FORWARD

	return 1;
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

	if ((listen_port < 0) || (listen_port > 65535)) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Invalid value for \"port\"");
			return -1;
	}

	sock->ipaddr = ipaddr;
	sock->port = listen_port;

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

		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No interface name given");
			return -1;
		}
		sock->interface = value;
#endif
	}

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

#ifdef WITH_PROXY
	/*
	 *	Proxy sockets don't have clients.
	 */
	if (this->type == RAD_LISTEN_PROXY) return 0;
#endif
	
	/*
	 *	The more specific configurations are preferred to more
	 *	generic ones.
	 */
	client_cs = NULL;
	parentcs = cf_top_section(cs);
	rcode = cf_item_parse(cs, "clients", PW_TYPE_STRING_PTR,
			      &section_name, NULL);
	if (rcode < 0) return -1; /* bad string */
	if (rcode == 0) {
		/*
		 *	Explicit list given: use it.
		 */
		client_cs = cf_section_sub_find_name2(parentcs,
						      "clients",
						      section_name);
		if (!client_cs) {
			client_cs = cf_section_find(section_name);
		}
		if (!client_cs) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed to find clients %s {...}",
				   section_name);
			free(section_name);
			return -1;
		}
		free(section_name);
	} /* else there was no "clients = " entry. */

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
			   "Failed to load clients for this listen section");
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


#ifdef WITH_ACCOUNTING
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
#endif

#ifdef WITH_PROXY
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
#endif

#ifdef WITH_STATS
/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int stats_socket_recv(rad_listen_t *listener,
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

	*pfun = rad_status_server;
	return 1;
}
#endif


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
	case PW_AUTHENTICATION_REQUEST:
		RAD_STATS_CLIENT_INC(listener, client, total_requests);
		fun = rad_authenticate;
		break;

	case PW_STATUS_SERVER:
		if (!mainconfig.status_server) {
			rad_recv_discard(listener->fd);
			RAD_STATS_TYPE_INC(listener, total_packets_dropped);
			RAD_STATS_CLIENT_INC(listener, client, total_packets_dropped);
			DEBUG("WARNING: Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		RAD_STATS_INC(radius_auth_stats.total_unknown_types);
		RAD_STATS_CLIENT_INC(listener, client, total_unknown_types);

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

	*pfun = fun;
	return 1;
}


#ifdef WITH_ACCOUNTING
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
		fun = rad_status_server;
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
#endif

#ifdef WITH_PROXY
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
		radlog(L_ERR, "%s", fr_strerror());
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

#ifdef WITH_ACCOUNTING
	case PW_ACCOUNTING_RESPONSE:
		fun = rad_accounting;
		break;
#endif

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
#endif


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

#ifdef WITH_PROXY
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
#endif

#include "dhcpd.c"

#include "command.c"

static const rad_listen_master_t master_listen[RAD_LISTEN_MAX] = {
#ifdef WITH_STATS
	{ common_socket_parse, NULL,
	  stats_socket_recv, auth_socket_send,
	  socket_print, client_socket_encode, client_socket_decode },
#else
	/*
	 *	This always gets defined.
	 */
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL},	/* RAD_LISTEN_NONE */
#endif

#ifdef WITH_PROXY
	/* proxying */
	{ common_socket_parse, NULL,
	  proxy_socket_recv, proxy_socket_send,
	  socket_print, proxy_socket_encode, proxy_socket_decode },
#endif

	/* authentication */
	{ common_socket_parse, NULL,
	  auth_socket_recv, auth_socket_send,
	  socket_print, client_socket_encode, client_socket_decode },

#ifdef WITH_ACCOUNTING
	/* accounting */
	{ common_socket_parse, NULL,
	  acct_socket_recv, acct_socket_send,
	  socket_print, client_socket_encode, client_socket_decode},
#endif

#ifdef WITH_DETAIL
	/* detail */
	{ detail_parse, detail_free,
	  detail_recv, detail_send,
	  detail_print, detail_encode, detail_decode },
#endif

#ifdef WITH_VMPS
	/* vlan query protocol */
	{ common_socket_parse, NULL,
	  vqp_socket_recv, vqp_socket_send,
	  socket_print, vqp_socket_encode, vqp_socket_decode },
#endif

#ifdef WITH_DHCP
	/* dhcp query protocol */
	{ dhcp_socket_parse, NULL,
	  dhcp_socket_recv, dhcp_socket_send,
	  socket_print, dhcp_socket_encode, dhcp_socket_decode },
#endif

#ifdef WITH_COMMAND_SOCKET
	/* TCP command socket */
	{ command_socket_parse, NULL,
	  command_domain_accept, command_domain_send,
	  command_socket_print, command_socket_encode, command_socket_decode },
#endif

};



/*
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
	struct sockaddr_storage salocal;
	socklen_t	salen;
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

#ifdef WITH_ACCOUNTING
		case RAD_LISTEN_ACCT:
			svp = getservbyname ("radacct", "udp");
			if (svp != NULL) {
				sock->port = ntohs(svp->s_port);
			} else {
				sock->port = PW_ACCT_UDP_PORT;
			}
			break;
#endif

#ifdef WITH_PROXY
		case RAD_LISTEN_PROXY:
			sock->port = 0;
			break;
#endif

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
	 *	Copy fr_socket() here, as we may need to bind to a device.
	 */
	this->fd = socket(sock->ipaddr.af, SOCK_DGRAM, 0);
	if (this->fd < 0) {
		radlog(L_ERR, "Failed opening socket: %s", strerror(errno));
		return -1;
	}
		
#ifdef SO_BINDTODEVICE
	/*
	 *	Bind to a device BEFORE touching IP addresses.
	 */
	if (sock->interface) {
		struct ifreq ifreq;
		strcpy(ifreq.ifr_name, sock->interface);
		
		if (setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
			       (char *)&ifreq, sizeof(ifreq)) < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed opening to interface %s: %s",
			       sock->interface, strerror(errno));
			return -1;
		} /* else it worked. */
	}
#endif

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(this->fd) != 0) {
		close(this->fd);
		return -1;
	}
#endif
	
	/*
	 *	Set up sockaddr stuff.
	 */
	if (!fr_ipaddr2sockaddr(&sock->ipaddr, sock->port, &salocal, &salen)) {
		close(this->fd);
		return -1;
	}
		
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (sock->ipaddr.af == AF_INET6) {
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
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */
		
	if (bind(this->fd, (struct sockaddr *) &salocal, salen) < 0) {
		close(this->fd);
		radlog(L_ERR, "Failed binding to socket: %s\n",
		       strerror(errno));
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

		if (!fr_sockaddr2ipaddr(&src, sizeof_src,
					&sock->ipaddr, &sock->port)) {
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
#ifdef WITH_STATS
	case RAD_LISTEN_NONE:
#endif
	case RAD_LISTEN_AUTH:
#ifdef WITH_ACCOUNTING
	case RAD_LISTEN_ACCT:
#endif
#ifdef WITH_PROXY
	case RAD_LISTEN_PROXY:
#endif
#ifdef WITH_VMPS
	case RAD_LISTEN_VQP:
#endif
#ifdef WITH_DHCP
	case RAD_LISTEN_DHCP:
#endif
		this->data = rad_malloc(sizeof(listen_socket_t));
		memset(this->data, 0, sizeof(listen_socket_t));
		break;

#ifdef WITH_DETAIL
	case RAD_LISTEN_DETAIL:
		this->data = NULL;
		break;
#endif

#ifdef WITH_COMMAND_SOCKET
	case RAD_LISTEN_COMMAND:
		this->data = rad_malloc(sizeof(fr_command_socket_t));
		memset(this->data, 0, sizeof(fr_command_socket_t));
		break;
#endif

	default:
		rad_assert("Unsupported option!" == NULL);
		break;
	}

	return this;
}


#ifdef WITH_PROXY
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
#endif

static const FR_NAME_NUMBER listen_compare[] = {
#ifdef WITH_STATS
	{ "status",	RAD_LISTEN_NONE },
#endif
	{ "auth",	RAD_LISTEN_AUTH },
#ifdef WITH_ACCOUNTING
	{ "acct",	RAD_LISTEN_ACCT },
#endif
#ifdef WITH_DETAIL
	{ "detail",	RAD_LISTEN_DETAIL },
#endif
#ifdef WITH_PROXY
	{ "proxy",	RAD_LISTEN_PROXY },
#endif
#ifdef WITH_VMPS
	{ "vmps",	RAD_LISTEN_VQP },
#endif
#ifdef WITH_DHCP
	{ "dhcp",	RAD_LISTEN_DHCP },
#endif
#ifdef WITH_COMMAND_SOCKET
	{ "control",	RAD_LISTEN_COMMAND },
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

	type = fr_str2int(listen_compare, listen_type, -1);
	if (type < 0) {
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
	CONF_SECTION	*cs = NULL;
	rad_listen_t	**last;
	rad_listen_t	*this;
	fr_ipaddr_t	server_ipaddr;
	int		auth_port = 0;
#ifdef WITH_PROXY
	int		defined_proxy = 0;
#endif

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
			listen_free(&this);
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(head);
			radlog(L_ERR, "There appears to be another RADIUS server running on the authentication port %d", sock->port);
			listen_free(&this);
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

#ifdef WITH_ACCOUNTING
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
#endif
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

#ifdef WITH_PROXY
			if (this->type == RAD_LISTEN_PROXY) defined_proxy = 1;
#endif
			
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

#ifdef WITH_PROXY
		if (this->type == RAD_LISTEN_PROXY) defined_proxy = 1;
#endif

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
			
#ifdef WITH_PROXY
			if (this->type == RAD_LISTEN_PROXY) {
				radlog(L_ERR, "Error: listen type \"proxy\" Cannot appear in a virtual server section");
				listen_free(head);
				return -1;
			}
#endif

			*last = this;
			last = &(this->next);
		} /* loop over "listen" directives in virtual servers */
	} /* loop over virtual servers */

	/*
	 *	If we're proxying requests, open the proxy FD.
	 *	Otherwise, don't do anything.
	 */
 do_proxy:
#ifdef WITH_PROXY
	if (mainconfig.proxy_requests == TRUE) {
		int		port = -1;
		listen_socket_t *sock = NULL;

		/*
		 *	No sockets to receive packets, therefore
		 *	proxying is pointless.
		 */
		if (!*head) return -1;

		if (defined_proxy) goto done;

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

 done:			/* used only in proxy code. */
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

#ifdef WITH_STATS
RADCLIENT_LIST *listener_find_client_list(const fr_ipaddr_t *ipaddr,
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
			return sock->clients;
		}
	}

	return NULL;
}

rad_listen_t *listener_find_byipaddr(const fr_ipaddr_t *ipaddr, int port)
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
#endif
