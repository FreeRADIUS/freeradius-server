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

#include <sys/resource.h>

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#include <fcntl.h>

#define USEC (1000000)

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
	lrad_ipaddr_t	ipaddr;
	int		port;
	RADCLIENT_LIST	*clients;
} listen_socket_t;

typedef struct listen_detail_t {
	const char	*filename;
	VALUE_PAIR	*vps;
	FILE		*fp;
	int		state;
	time_t		timestamp;
	lrad_ipaddr_t	client_ip;
	int		load_factor; /* 1..100 */

	int		has_rtt;
	int		srtt;
	int		rttvar;
	int		delay_time;
	struct timeval  last_packet;
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
		   (listener->type == RAD_LISTEN_ACCT) ||
		   (listener->type == RAD_LISTEN_VQP));

	clients = ((listen_socket_t *)listener->data)->clients;
	if (!clients) clients = mainconfig.clients;

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
	size_t len;
	listen_socket_t *sock = this->data;

	if ((sock->ipaddr.af == AF_INET) &&
	    (sock->ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strcpy(buffer, "*");
	} else {
		ip_ntoh(&sock->ipaddr, buffer, bufsize);
	}

	len = strlen(buffer);

	if (!this->server) {
		return len + snprintf(buffer + len, bufsize - len, " port %d",
				      sock->port);
	}

	return len + snprintf(buffer + len, bufsize - len, " port %d as server %s",
			      sock->port, this->server);
}


/*
 *	Parse an authentication or accounting socket.
 */
static int common_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	int		listen_port;
	lrad_ipaddr_t	ipaddr;
	listen_socket_t *sock = this->data;
	const char	*section_name = NULL;
	CONF_SECTION	*client_cs;

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
			       cf_section_filename(cs), cf_section_lineno(cs));
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
		       cf_section_filename(cs), cf_section_lineno(cs),
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
		       cf_section_filename(cs), cf_section_lineno(cs));
		return -1;
#else
		const char *value;
		CONF_PAIR *cp = cf_pair_find(cs, "interface");
		struct ifreq ifreq;

		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		if (!value) {
			radlog(L_CONS|L_ERR, "%s[%d]: No interface name given",
			       cf_section_filename(cs), cf_section_lineno(cs));
			return -1;
		}

		strcpy(ifreq.ifr_name, value);

		if (setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
			       (char *)&ifreq, sizeof(ifreq)) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed binding to interface %s: %s",
			       cf_section_filename(cs), cf_section_lineno(cs),
			       value, strerror(errno));
			return -1;
		} /* else it worked. */
#endif
	}
	
	/*
	 *	If we have a server, prefer to use clients defined
	 *	in that server, and ignore any "clients = "
	 *	directive, UNLESS there are no clients in the server.
	 */
	client_cs = NULL;
	client_cs = cf_section_sub_find_name2(mainconfig.config,
					      "server",
					      this->server);
	
	/*
	 *	Found a "server foo" section, but there are no
	 *	clients in it.  Don't use this section.
	 */
	if (client_cs &&
	    (cf_section_sub_find(client_cs, "client") == NULL)) {
		client_cs = NULL;
	}

	/*
	 *	No clients, look for the name of a section that holds
	 *	a list of clients.
	 */
	if (!client_cs) {
		rcode = cf_item_parse(cs, "clients", PW_TYPE_STRING_PTR,
				      &section_name, NULL);
		if (rcode < 0) return -1; /* bad string */
		if (rcode == 0) {
			/*
			 *	Explicit list given: use it.
			 */
			client_cs = cf_section_find(section_name);
			free(section_name);
			if (!client_cs) {
				radlog(L_CONS|L_ERR, "%s[%d]: Failed to find client section %s",
				       cf_section_filename(cs), cf_section_lineno(cs), section_name);
				return -1;
			}
		} /* else there was no "clients = " entry. */
	}

	/*
	 *	Still nothing.  Make it global.
	 */
	if (!client_cs) client_cs = mainconfig.config;

	sock->clients = clients_parse_section(client_cs);
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
	lrad_ipaddr_t	src_ipaddr;

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
		DEBUG("Ignoring request from unknown client %s port %d",
		      inet_ntop(src_ipaddr.af, &src_ipaddr.ipaddr,
				buffer, sizeof(buffer)), src_port);
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
	packet = rad_recv(listener->fd);
	if (!packet) {
		RAD_SNMP_TYPE_INC(listener, total_malformed_requests);
		radlog(L_ERR, "%s", librad_errstr);
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
	lrad_ipaddr_t	src_ipaddr;

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
		DEBUG("Ignoring request from unknown client %s port %d",
		      inet_ntop(src_ipaddr.af, &src_ipaddr.ipaddr,
				buffer, sizeof(buffer)), src_port);
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
	packet = rad_recv(listener->fd);
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

	packet = rad_recv(listener->fd);
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


#define STATE_UNOPENED	(0)
#define STATE_UNLOCKED	(1)
#define STATE_HEADER	(2)
#define STATE_READING	(3)
#define STATE_QUEUED	(4)
#define STATE_RUNNING	(5)
#define STATE_NO_REPLY	(6)
#define STATE_REPLIED	(7)

/*
 *	If we're limiting outstanding packets, then mark the response
 *	as being sent.
 */
static int detail_send(rad_listen_t *listener, REQUEST *request)
{
	int rtt;
	struct timeval now;
	listen_detail_t *data = listener->data;

	rad_assert(request->listener == listener);
	rad_assert(listener->send == detail_send);

	/*
	 *	This request timed out.  Remember that, and tell the
	 *	caller it's OK to read more "detail" file stuff.
	 */
	if (request->reply->code == 0) {
		radius_signal_self(RADIUS_SIGNAL_SELF_DETAIL);
		data->state = STATE_NO_REPLY;
		return 0;
	}

	/*
	 *	We call gettimeofday a lot.  But here it should be OK,
	 *	because there's nothing else to do.
	 */
	gettimeofday(&now, NULL);

	/*
	 *	If we haven't sent a packet in the last second, reset
	 *	the RTT.
	 */
	now.tv_sec -= 1;
	if (timercmp(&data->last_packet, &now, <)) {
		data->has_rtt = FALSE;
	}
	now.tv_sec += 1;

	/*
	 *	Only one detail packet may be outstanding at a time,
	 *	so it's safe to update some entries in the detail
	 *	structure.
	 *
	 *	We keep smoothed round trip time (SRTT), but not round
	 *	trip timeout (RTO).  We use SRTT to calculate a rough
	 *	load factor.
	 */
	rtt = now.tv_sec - request->received.tv_sec;
	rtt *= USEC;
	rtt += now.tv_usec;
	rtt -= request->received.tv_usec;

	/*
	 *	If we're proxying, the RTT is our processing time,
	 *	plus the network delay there and back, plus the time
	 *	on the other end to process the packet.  Ideally, we
	 *	should remove the network delays from the RTT, but we
	 *	don't know what they are.
	 *
	 *	So, to be safe, we over-estimate the total cost of
	 *	processing the packet.
	 */
	if (!data->has_rtt) {
		data->has_rtt = TRUE;
		data->srtt = rtt;
		data->rttvar = rtt / 2;

	} else {
		data->rttvar -= data->rttvar >> 2;
		data->rttvar += (data->srtt - rtt);
		data->srtt -= data->srtt >> 3;
		data->srtt += rtt >> 3;
	}

	/*
	 *	Calculate the time we wait before sending the next
	 *	packet.
	 *
	 *	rtt / (rtt + delay) = load_factor / 100
	 */
	data->delay_time = (data->srtt * (100 - data->load_factor)) / (data->load_factor);

	/*
	 *	FIXME: Push this delay to the event handler!
	 */
	DEBUG2("RTT %d\tdelay %d", data->srtt, data->delay_time);

	usleep(data->delay_time);
	data->last_packet = now;
	data->state = STATE_REPLIED;

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
	snprintf(buffer, sizeof(buffer), "%s.work", data->filename);

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
		if (stat(data->filename, &st) < 0) {
			return 0;
		}

		/*
		 *	Open it BEFORE we rename it, just to
		 *	be safe...
		 */
		this->fd = open(data->filename, O_RDWR);
		if (this->fd < 0) {
			radlog(L_ERR, "Failed to open %s: %s",
			       data->filename, strerror(errno));
			return 0;
		}

		/*
		 *	Rename detail to detail.work
		 */
		if (rename(data->filename, buffer) < 0) {
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
		       data->filename, strerror(errno));
		return 0;
	}

	data->state = STATE_UNLOCKED;

	data->client_ip.af = AF_UNSPEC;
	data->timestamp = 0;

	return 1;
}

/*
 *	FIXME: this should be dynamically allocated.
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
#ifdef WITH_SNMP
	, NULL, NULL
#endif
};

/*
 *	FIXME: add a configuration "exit when done" so that the detail
 *	file reader can be used as a one-off tool to update stuff.
 *
 *	The time sequence for reading from the detail file is:
 *
 *	t_0		signalled that the server is idle, and we
 *			can read from the detail file.
 *
 *	t_rtt		the packet has been processed successfully,
 *			wait for t_delay to enforce load factor.
 *			
 *	t_rtt + t_delay wait for signal that the server is idle.
 *	
 */
static int detail_recv(rad_listen_t *listener,
		       RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	char		key[256], value[1024];
	VALUE_PAIR	*vp, **tail;
	RADIUS_PACKET	*packet;
	char		buffer[2048];
	listen_detail_t *data = listener->data;

	switch (data->state) {
		case STATE_UNOPENED:
			rad_assert(listener->fd < 0);
			
			/*
			 *	FIXME: If the file doesn't exist, then
			 *	return "sleep for 1s", to avoid busy
			 *	looping.
			 */
			if (!detail_open(listener)) return 0;

			rad_assert(data->state == STATE_UNLOCKED);
			rad_assert(listener->fd >= 0);

			/* FALL-THROUGH */

			/*
			 *	Try to lock fd.  If we can't, return.
			 *	If we can, continue.  This means that
			 *	the server doesn't block while waiting
			 *	for the lock to open...
			 */
		case STATE_UNLOCKED:
			/*
			 *	Note that we do NOT block waiting for
			 *	the lock.  We've re-named the file
			 *	above, so we've already guaranteed
			 *	that any *new* detail writer will not
			 *	be opening this file.  The only
			 *	purpose of the lock is to catch a race
			 *	condition where the execution
			 *	"ping-pongs" between radiusd &
			 *	radrelay.
			 */
			if (rad_lockfd_nonblock(listener->fd, 0) < 0) {
				return 0;
			}
			/*
			 *	Look for the header
			 */
			data->state = STATE_HEADER;
			data->vps = NULL;

			/* FALL-THROUGH */

		case STATE_HEADER:
		do_header:
			/*
			 *	End of file.  Delete it, and re-set
			 *	everything.
			 */
			if (feof(data->fp)) {
			cleanup:
				snprintf(buffer, sizeof(buffer),
					 "%s.work", data->filename);
				unlink(buffer);
				fclose(data->fp); /* closes listener->fd */
				data->fp = NULL;
				listener->fd = -1;
				data->state = STATE_UNOPENED;
				rad_assert(data->vps == NULL);
				return 0;
			}

			/*
			 *	Else go read something.
			 */
			break;

			/*
			 *	Read more value-pair's, unless we're
			 *	at EOF.  In that case, queue whatever
			 *	we have.
			 */
		case STATE_READING:
			if (!feof(data->fp)) break;
			data->state = STATE_QUEUED;

			/* FALL-THROUGH */

		case STATE_QUEUED:
			goto alloc_packet;

			/*
			 *	We still have an outstanding packet.
			 *	Don't read any more.
			 */
		case STATE_RUNNING:
			return 0;

			/*
			 *	If there's no reply, keep
			 *	retransmitting the current packet
			 *	forever.
			 */
		case STATE_NO_REPLY:
			data->state = STATE_QUEUED;
			goto alloc_packet;
				
			/*
			 *	We have a reply.  Clean up the old
			 *	request, and go read another one.
			 */
		case STATE_REPLIED:
			pairfree(&data->vps);
			data->state = STATE_HEADER;
			goto do_header;
	}
	
	tail = &data->vps;
	while (*tail) tail = &(*tail)->next;

	/*
	 *	Read a header, OR a value-pair.
	 */
	while (fgets(buffer, sizeof(buffer), data->fp)) {
		/*
		 *	Badly formatted file: delete it.
		 *
		 *	FIXME: Maybe flag an error?
		 */
		if (!strchr(buffer, '\n')) {
			pairfree(&data->vps);
			goto cleanup;
		}

		/*
		 *	We're reading VP's, and got a blank line.
		 *	Queue the packet.
		 */
		if ((data->state == STATE_READING) &&
		    (buffer[0] == '\n')) {
			data->state = STATE_QUEUED;
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
		 *
		 *	FIXME: print an error for badly formatted attributes?
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
	 *	Some kind of error.
	 *
	 *	FIXME: Leave the file in-place, and warn the
	 *	administrator?
	 */
	if (ferror(data->fp)) goto cleanup;

	/*
	 *	Process the packet.
	 */
 alloc_packet:
	rad_assert(data->state == STATE_QUEUED);

	/*
	 *	We're done reading the file, but we didn't read
	 *	anything.  Clean up, and don't return anything.
	 */
	if (!data->vps) {
		data->state = STATE_HEADER;
		return 0;
	}

	/*
	 *	Allocate the packet.  If we fail, it's a serious
	 *	problem.
	 */
	packet = rad_alloc(1);
	if (!packet) {
		data->state = STATE_NO_REPLY;	/* try again later */
		return 0;	/* maybe memory will magically free up... */
	}

	memset(packet, 0, sizeof(*packet));
	packet->sockfd = -1;
	packet->src_ipaddr.af = AF_INET;
	packet->src_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	packet->code = PW_ACCOUNTING_REQUEST;
	packet->timestamp = time(NULL);

	/*
	 *	Remember where it came from, so that we don't
	 *	proxy it to the place it came from...
	 */
	if (data->client_ip.af != AF_UNSPEC) {
		packet->src_ipaddr = data->client_ip;
	}

	vp = pairfind(packet->vps, PW_PACKET_SRC_IP_ADDRESS);
	if (vp) {
		packet->src_ipaddr.af = AF_INET;
		packet->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	} else {
		vp = pairfind(packet->vps, PW_PACKET_SRC_IPV6_ADDRESS);
		if (vp) {
			packet->src_ipaddr.af = AF_INET6;
			memcpy(&packet->src_ipaddr.ipaddr.ip6addr,
			       &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		}
	}

	vp = pairfind(packet->vps, PW_PACKET_DST_IP_ADDRESS);
	if (vp) {
		packet->dst_ipaddr.af = AF_INET;
		packet->dst_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
	} else {
		vp = pairfind(packet->vps, PW_PACKET_DST_IPV6_ADDRESS);
		if (vp) {
			packet->dst_ipaddr.af = AF_INET6;
			memcpy(&packet->dst_ipaddr.ipaddr.ip6addr,
			       &vp->vp_ipv6addr, sizeof(vp->vp_ipv6addr));
		}
	}

	/*
	 *	We've got to give SOME value for Id & ports, so that
	 *	the packets can be added to the request queue.
	 *	However, we don't want to keep track of used/unused
	 *	id's and ports, as that's a lot of work.  This hack
	 *	ensures that (if we have real random numbers), that
	 *	there will be a collision on every 2^(16+15+15+24 - 1)
	 *	packets, on average.  That means we can read 2^37
	 *	packets before having a collision, which means it's
	 *	effectively impossible.
	 */
	packet->id = lrad_rand() & 0xffff;
	packet->src_port = 1024 + (lrad_rand() & 0x7fff);
	packet->dst_port = 1024 + (lrad_rand() & 0x7fff);

	packet->dst_ipaddr.af = AF_INET;
	packet->dst_ipaddr.ipaddr.ip4addr.s_addr = htonl((INADDR_LOOPBACK & ~0xffffff) | (lrad_rand() & 0xffffff));

	/*
	 *	If everything's OK, this is a waste of memory.
	 *	Otherwise, it lets us re-send the original packet
	 *	contents, unmolested.
	 */
	packet->vps = paircopy(data->vps);

	/*
	 *	Look for Acct-Delay-Time, and update
	 *	based on Acct-Delay-Time += (time(NULL) - timestamp)
	 */
	vp = pairfind(packet->vps, PW_ACCT_DELAY_TIME);
	if (!vp) {
		vp = paircreate(PW_ACCT_DELAY_TIME, PW_TYPE_INTEGER);
		rad_assert(vp != NULL);
		pairadd(&packet->vps, vp);
	}
	if (data->timestamp != 0) {
		vp->vp_integer += time(NULL) - data->timestamp;
	}

	*pfun = rad_accounting;

	if (debug_flag) {
		printf("detail_recv: Read packet from %s\n", data->filename);
		for (vp = packet->vps; vp; vp = vp->next) {
			putchar('\t');
			vp_print(stdout, vp);
			putchar('\n');
		}
	}

	/*
	 *	FIXME: many of these checks may not be necessary when
	 *	reading from the detail file.
	 *
	 *	Try again later...
	 */
	if (!received_request(listener, packet, prequest, &detail_client)) {
		rad_free(&packet);
		data->state = STATE_NO_REPLY;	/* try again later */
		return 0;
	}

	data->state = STATE_RUNNING;

	return 1;
}


/*
 *	Free detail-specific stuff.
 */
static void detail_free(rad_listen_t *this)
{
	listen_detail_t *data = this->data;

	free(data->filename);
	pairfree(&data->vps);

	if (data->fp != NULL) fclose(data->fp);
}


static int detail_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	if (!this->server) {
		return snprintf(buffer, bufsize, "%s",
				((listen_detail_t *)(this->data))->filename);
	}

	return snprintf(buffer, bufsize, "%s as server %s",
			((listen_detail_t *)(this->data))->filename,
			this->server);
}

static int detail_encode(UNUSED rad_listen_t *this, UNUSED REQUEST *request)
{
	/*
	 *	We never encode responses "sent to" the detail file.
	 */
	return 0;
}

static int detail_decode(UNUSED rad_listen_t *this, UNUSED REQUEST *request)
{
	/*
	 *	We never decode responses read from the detail file.
	 */
	return 0;
}


static const CONF_PARSER detail_config[] = {
	{ "filename",   PW_TYPE_STRING_PTR,
	  offsetof(listen_detail_t, filename), NULL,  NULL },
	{ "load_factor",   PW_TYPE_INTEGER,
	  offsetof(listen_detail_t, load_factor), NULL, Stringify(10)},

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};


/*
 *	Parse a detail section.
 */
static int detail_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	listen_detail_t *data;

	data = this->data;

	rcode = cf_section_parse(cs, data, detail_config);
	if (rcode < 0) {
		radlog(L_ERR, "%s[%d]: Failed parsing listen section",
		       cf_section_filename(cs), cf_section_lineno(cs));
		return -1;
	}

	if (!data->filename) {
		radlog(L_ERR, "%s[%d]: No detail file specified in listen section",
		       cf_section_filename(cs), cf_section_lineno(cs));
		return -1;
	}

	if ((data->load_factor < 1) || (data->load_factor > 100)) {
		radlog(L_ERR, "%s[%d]: Load factor must be between 1 and 100",
		       cf_section_filename(cs), cf_section_lineno(cs));
		return -1;
	}

	data->vps = NULL;
	data->fp = NULL;
	data->state = STATE_UNOPENED;
	detail_open(this);

	return 0;
}


#ifdef WITH_SNMP
static int radius_snmp_recv(rad_listen_t *listener,
			    UNUSED RAD_REQUEST_FUNP *pfun,
			    UNUSED REQUEST **prequest)
{
	if (!mainconfig.do_snmp) return 0;

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

#ifdef WITH_VMPS
/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
 */
static int vqp_socket_recv(rad_listen_t *listener,
			   RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;

	packet = vqp_recv(listener->fd);
	if (!packet) {
		radlog(L_ERR, "%s", librad_errstr);
		return 0;
	}

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
	 *	Do new stuff.
	 */
	fun = vmps_process;

	if (!received_request(listener, packet, prequest, client)) {
		rad_free(&packet);
		return 0;
	}

	*pfun = fun;

	return 1;
}


/*
 *	Send an authentication response packet
 */
static int vqp_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == vqp_socket_send);

	if (vqp_encode(request->reply, request->packet) < 0) {
		DEBUG2("Failed encoding packet: %s\n", librad_errstr);
		return -1;
	}

	return vqp_send(request->reply);
}


static int vqp_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return vqp_encode(request->reply, request->packet);
}


static int vqp_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	return vqp_decode(request->packet);
}
#endif /* WITH_VMPS */


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
		listen_socket_t *other;

		if (this->type != (*last)->type) continue;

		if ((this->type == RAD_LISTEN_DETAIL) ||
		    (this->type == RAD_LISTEN_SNMP)) continue;

		other = (listen_socket_t *)((*last)->data);

		if ((sock->port == other->port) &&
		    (sock->ipaddr.af == other->ipaddr.af) &&
		    (lrad_ipaddr_cmp(&sock->ipaddr, &other->ipaddr) == 0)) {
			this->fd = (*last)->fd;
			(*last)->fd = -1;
			return 0;
		}
	}

	this->fd = lrad_socket(&sock->ipaddr, sock->port);
	if (this->fd < 0) {
		radlog(L_ERR|L_CONS, "ERROR: Failed to open socket: %s",
		       librad_errstr);
		return -1;
	}

#if 0
#ifdef O_NONBLOCK
	if ((flags = fcntl(this->fd, F_GETFL, NULL)) < 0)  {
		radlog(L_ERR, "Failure in fcntl: %s)\n", strerror(errno));
		return -1;
	}

	flags |= O_NONBLOCK;
	if( fcntl(this->fd, F_SETFL, flags) < 0) {
		radlog(L_ERR, "Failure in fcntl: %s)\n", strerror(errno));
		return -1;
	}
#endif
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
		this->data = rad_malloc(sizeof(listen_detail_t));
		memset(this->data, 0, sizeof(listen_detail_t));

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

	if (!old) return NULL;	/* This is a serious error. */

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

	return NULL;
}


static const LRAD_NAME_NUMBER listen_compare[] = {
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
	
	DEBUG2(" listen {");

	rcode = cf_item_parse(cs, "type", PW_TYPE_STRING_PTR,
			      &listen_type, "");
	if (rcode < 0) return NULL;
	if (rcode == 1) {
		free(listen_type);
		radlog(L_ERR, "%s[%d]: No type specified in listen section",
		       cf_section_filename(cs), cf_section_lineno(cs));
		return NULL;
	}

	type = lrad_str2int(listen_compare, listen_type,
			    RAD_LISTEN_NONE);
	free(listen_type);
	if (type == RAD_LISTEN_NONE) {
		radlog(L_CONS|L_ERR, "%s[%d]: Invalid type in listen section.",
		       cf_section_filename(cs), cf_section_lineno(cs));
		return NULL;
	}
	
	/*
	 *	Allow listen sections in the default config to
	 *	refer to a server.
	 */
	if (!server) {
		rcode = cf_item_parse(cs, "server", PW_TYPE_STRING_PTR,
				      &server, NULL);
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

	DEBUG2(" }");

	return this;
}

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

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			radlog(L_CONS|L_ERR, "There appears to be another RADIUS server running on the authentication port %d", sock->port);
			return -1;
		}
		auth_port = sock->port;	/* may have been updated in listen_bind */
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

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			radlog(L_CONS|L_ERR, "There appears to be another RADIUS server running on the accounting port %d", sock->port);
			return -1;
		}

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
	for (cs = cf_subsection_find_next(mainconfig.config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(mainconfig.config, cs, "server")) {
		CONF_SECTION *subcs;
		const char *name2 = cf_section_name2(cs);
		
		if (!name2) {
			radlog(L_ERR, "%s[%d]: \"server\" sections require a server name",
			       filename, cf_section_lineno(cs));
			listen_free(head);
			return -1;
		}

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

		if (port < 0) port = 1024 + (lrad_rand() & 0x1ff);

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
			radlog(L_ERR|L_CONS, "Failed to open socket for proxying");
			return -1;
		}
	}

 do_snmp:
#ifdef WITH_SNMP
	if (mainconfig.do_snmp) {
		radius_snmp_init();

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
