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

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <freeradius-devel/process.h>
#include <freeradius-devel/protocol.h>
#include <freeradius-devel/modpriv.h>

#include <freeradius-devel/detail.h>

#ifdef WITH_UDPFROMTO
#include <freeradius-devel/udpfromto.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef WITH_TLS
#include <netinet/tcp.h>

#  if defined(__APPLE__) || defined(__FreeBSD__) || defined(__illumos__) || defined(__sun__)
#    if !defined(SOL_TCP) && defined(IPPROTO_TCP)
#      define SOL_TCP IPPROTO_TCP
#    endif
#  endif

#endif

#ifdef DEBUG_PRINT_PACKET
static void print_packet(RADIUS_PACKET *packet)
{
	char src[256], dst[256];

	ip_ntoh(&packet->src_ipaddr, src, sizeof(src));
	ip_ntoh(&packet->dst_ipaddr, dst, sizeof(dst));

	fprintf(stderr, "ID %d: %s %d -> %s %d\n", packet->id,
		src, packet->src_port, dst, packet->dst_port);

}
#endif


static rad_listen_t *listen_alloc(TALLOC_CTX *ctx, RAD_LISTEN_TYPE type);

#ifdef WITH_COMMAND_SOCKET
#ifdef WITH_TCP
static int command_tcp_recv(rad_listen_t *listener);
static int command_tcp_send(rad_listen_t *listener, REQUEST *request);
static int command_write_magic(int newfd, listen_socket_t *sock);
#endif
#endif

#ifdef WITH_COA_TUNNEL
static int listen_coa_init(void);
#endif

static fr_protocol_t master_listen[];

#ifdef WITH_DYNAMIC_CLIENTS
static void client_timer_free(void *ctx)
{
	RADCLIENT *client = ctx;

	client_free(client);
}
#endif

/*
 *	Find a per-socket client.
 */
RADCLIENT *client_listener_find(rad_listen_t *listener,
				fr_ipaddr_t const *ipaddr, uint16_t src_port)
{
#ifdef WITH_DYNAMIC_CLIENTS
	int rcode;
	REQUEST *request;
	RADCLIENT *created;
#endif
	time_t now;
	RADCLIENT *client;
	RADCLIENT_LIST *clients;
	listen_socket_t *sock;

	rad_assert(listener != NULL);
	rad_assert(ipaddr != NULL);

	sock = listener->data;
	clients = sock->clients;

	/*
	 *	This HAS to have been initialized previously.
	 */
	rad_assert(clients != NULL);

	client = client_find(clients, ipaddr, sock->proto);
	if (!client) {
		char name[256], buffer[128];

#ifdef WITH_DYNAMIC_CLIENTS
	unknown:		/* used only for dynamic clients */
#endif

		/*
		 *	DoS attack quenching, but only in daemon mode.
		 *	If they're running in debug mode, show them
		 *	every packet.
		 */
		if (rad_debug_lvl == 0) {
			static time_t last_printed = 0;

			now = time(NULL);
			if (last_printed == now) return NULL;

			last_printed = now;
		}

		listener->print(listener, name, sizeof(name));

		radlog(L_ERR, "Ignoring request to %s from unknown client %s port %d"
#ifdef WITH_TCP
		       " proto %s"
#endif
		       , name, inet_ntop(ipaddr->af, &ipaddr->ipaddr,
					 buffer, sizeof(buffer)), src_port
#ifdef WITH_TCP
		       , (sock->proto == IPPROTO_UDP) ? "udp" : "tcp"
#endif
		       );
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
	if (client->dynamic && (src_port != 0)) {
#ifdef HAVE_SYS_STAT_H
		char const *filename;
#endif
		fr_event_list_t *el;
		struct timeval when;

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

#ifdef HAVE_SYS_STAT_H
		/*
		 *	The client was read from a file, and the file
		 *	hasn't changed since the client was created.
		 *	Just renew the creation time, and continue.
		 *	We don't need to re-load the same information.
		 */
		if (client->cs &&
		    (filename = cf_section_filename(client->cs)) != NULL) {
			struct stat buf;

			if ((stat(filename, &buf) >= 0) &&
			    (buf.st_mtime < client->created)) {
				client->created = now;
				return client;
			}
		}
#endif


		/*
		 *	Delete the client from the known list.
		 */
		client_delete(clients, client);

		/*
		 *	Add a timer to free the client 20s after it's already timed out.
		 */
		el = radius_event_list_corral(EVENT_CORRAL_MAIN);

		gettimeofday(&when, NULL);
		when.tv_sec += main_config.max_request_time + 20;

		/*
		 *	If this fails, we leak memory.  That's better than crashing...
		 */
		(void) fr_event_insert(el, client_timer_free, client, &when, &client->ev);

		/*
		 *	Go find the enclosing network again.
		 */
		client = client_find(clients, ipaddr, sock->proto);

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

	} else if (!client->dynamic && client->rate_limit) {
		/*
		 *	The IP is unknown, so we've found an enclosing
		 *	network.  Enable DoS protection.  We only
		 *	allow one new client per second.  Known
		 *	clients aren't subject to this restriction.
		 */
		if (now == client->last_new_client) goto unknown;
	}

	client->last_new_client = now;

	request = request_alloc(NULL);
	if (!request) goto unknown;

	request->listener = listener;
	request->client = client;

	request->packet = rad_alloc(request, false);
	if (!request->packet) {				/* badly formed, etc */
		talloc_free(request);
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		goto unknown;
	}
	request->packet->src_ipaddr = *ipaddr;
	request->packet->src_port = src_port;
	request->packet->dst_ipaddr = sock->my_ipaddr;
	request->packet->dst_port = sock->my_port;
	request->packet->proto = sock->proto;

	request->reply = rad_alloc_reply(request, request->packet);
	if (!request->reply) {
		talloc_free(request);
		goto unknown;
	}
	gettimeofday(&request->packet->timestamp, NULL);
	request->number = 0;
	request->priority = listener->type;
	request->server = client->client_server;
	request->root = &main_config;

	/*
	 *	Run a fake request through the given virtual server.
	 *	Look for FreeRADIUS-Client-IP-Address
	 *		 FreeRADIUS-Client-Secret
	 *		...
	 *
	 *	and create the RADCLIENT structure from that.
	 */
	RDEBUG("server %s {", request->server);

	rcode = process_authorize(0, request);

	RDEBUG("} # server %s", request->server);

	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	/*
	 *	Likely a fatal error we want to warn the user about
	 */
	case RLM_MODULE_INVALID:
	case RLM_MODULE_FAIL:
		ERROR("Virtual-Server %s returned %s, creating dynamic client failed", request->server,
		      fr_int2str(mod_rcode_table, rcode, "<INVALID>"));
		talloc_free(request);
		goto unknown;

	/*
	 *	Probably the result of policy, or the client not existing.
	 */
	default:
		DEBUG("Virtual-Server %s returned %s, ignoring client", request->server,
		      fr_int2str(mod_rcode_table, rcode, "<INVALID>"));
		talloc_free(request);
		goto unknown;
	}

	/*
	 *	If the client was updated by rlm_dynamic_clients,
	 *	don't create the client from attribute-value pairs.
	 */
	if (request->client == client) {
		created = client_afrom_request(clients, request);
	} else {
		created = request->client;

		/*
		 *	This frees the client if it isn't valid.
		 */
		if (!client_add_dynamic(clients, client, created)) goto unknown;
	}

	request->server = client->server;
	exec_trigger(request, NULL, "server.client.add", false);

	talloc_free(request);

	if (!created) goto unknown;

	return created;
#endif
}

static int listen_bind(rad_listen_t *this);

#ifdef WITH_COA_TUNNEL
static void listener_coa_update(rad_listen_t *this, VALUE_PAIR *vps);
#endif

/*
 *	Process and reply to a server-status request.
 *	Like rad_authenticate and rad_accounting this should
 *	live in it's own file but it's so small we don't bother.
 */
int rad_status_server(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	DICT_VALUE *dval;

#ifdef WITH_TLS
	if (request->listener->tls) {
		listen_socket_t *sock = request->listener->data;

		if (sock->state == LISTEN_TLS_CHECKING) {
			int autz_type = PW_AUTZ_TYPE;
			char const *name = "Autz-Type";
			rad_listen_t *listener = request->listener;

			if (request->listener->type == RAD_LISTEN_ACCT) {
				autz_type = PW_ACCT_TYPE;
				name = "Acct-Type";
			}

			RDEBUG("(TLS) Checking connection to see if it is authorized.");

			dval = dict_valbyname(autz_type, 0, "New-TLS-Connection");
			if (dval) {
				rcode = process_authorize(dval->value, request);
			} else {
				rcode = RLM_MODULE_OK;
				RWDEBUG("(TLS) Did not find '%s New-TLS-Connection' - defaulting to accept", name);
			}

			if ((rcode == RLM_MODULE_OK) || (rcode == RLM_MODULE_UPDATED)) {
				RDEBUG("(TLS) Connection is authorized");
				request->reply->code = PW_CODE_ACCESS_ACCEPT;

				listener->status = RAD_LISTEN_STATUS_RESUME;

				rad_assert(sock->request->packet != request->packet);

				sock->state = LISTEN_TLS_SETUP;

			} else {
				RWDEBUG("(TLS) Connection is not authorized - closing TCP socket.");
				request->reply->code = PW_CODE_ACCESS_REJECT;

				listener->status = RAD_LISTEN_STATUS_EOL;
				listener->tls = NULL; /* parent owns this! */
			}

			radius_update_listener(listener);
			return 0;
		}
	}
#endif

#ifdef WITH_STATS
	/*
	 *	Full statistics are available only on a statistics
	 *	socket.
	 */
	if (request->listener->type == RAD_LISTEN_NONE) {
		request_stats_reply(request);
	}
#endif

	switch (request->listener->type) {
#ifdef WITH_STATS
	case RAD_LISTEN_NONE:
#endif
	case RAD_LISTEN_AUTH:
		dval = dict_valbyname(PW_AUTZ_TYPE, 0, "Status-Server");
		if (dval) {
			rcode = process_authorize(dval->value, request);
		} else {
			rcode = RLM_MODULE_OK;
		}

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = PW_CODE_ACCESS_ACCEPT;

#ifdef WITH_COA_TUNNEL
			if (request->listener->send_coa) listener_coa_update(request->listener, request->packet->vps);
#endif
			break;

		case RLM_MODULE_FAIL:
		case RLM_MODULE_HANDLED:
			request->reply->code = 0; /* don't reply */
			break;

		default:
		case RLM_MODULE_REJECT:
			request->reply->code = PW_CODE_ACCESS_REJECT;
			break;
		}
		break;

#ifdef WITH_ACCOUNTING
	case RAD_LISTEN_ACCT:
		dval = dict_valbyname(PW_ACCT_TYPE, 0, "Status-Server");
		if (dval) {
			rcode = process_accounting(dval->value, request);
		} else {
			rcode = RLM_MODULE_OK;
		}

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = PW_CODE_ACCOUNTING_RESPONSE;

#ifdef WITH_COA_TUNNEL
			if (request->listener->send_coa) listener_coa_update(request->listener, request->packet->vps);
#endif
			break;

		default:
			request->reply->code = 0; /* don't reply */
			break;
		}
		break;
#endif

#ifdef WITH_COA
		/*
		 *	This is a vendor extension.  Suggested by Glen
		 *	Zorn in IETF 72, and rejected by the rest of
		 *	the WG.  We like it, so it goes in here.
		 */
	case RAD_LISTEN_COA:
		dval = dict_valbyname(PW_RECV_COA_TYPE, 0, "Status-Server");
		if (dval) {
			rcode = process_recv_coa(dval->value, request);
		} else {
			rcode = RLM_MODULE_OK;
		}

		switch (rcode) {
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = PW_CODE_COA_ACK;
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

	return 0;
}

static void blastradius_checks(RADIUS_PACKET *packet, RADCLIENT *client)
{
	if (client->require_ma == FR_BOOL_TRUE) return;

	if (client->require_ma == FR_BOOL_AUTO) {
		if (!packet->message_authenticator) {
			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			ERROR("BlastRADIUS check: Received packet without Message-Authenticator.");
			ERROR("Setting \"require_message_authenticator = false\" for client %s", client->shortname);
			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			ERROR("UPGRADE THE CLIENT AS YOUR NETWORK IS VULNERABLE TO THE BLASTRADIUS ATTACK.");
			ERROR("Once the client is upgraded, set \"require_message_authenticator = true\" for  client %s", client->shortname);
			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			client->require_ma = FR_BOOL_FALSE;

			/*
			 *	And fall through to the
			 *	limit_proxy_state checks, which might
			 *	complain again.  Oh well, maybe that
			 *	will make people read the messages.
			 */

		} else if (packet->eap_message) {
			/*
			 *	Don't set it to "true" for packets
			 *	with EAP-Message.  It's already
			 *	required there, and we might get a
			 *	non-EAP packet with (or without)
			 *	Message-Authenticator
			 */
			return;

		} else if (((client->src_ipaddr.af == AF_INET) &&
			    (client->src_ipaddr.prefix != 32)) ||
			   ((client->src_ipaddr.af == AF_INET6) &&
			    (client->src_ipaddr.prefix != 128))) {
			/*
			 *	Don't change it from "auto" for wildcard clients.
			 */
			DEBUG("BlastRADIUS check: Received packet with Message-Authenticator.");
			DEBUG("NOT changing \"require_message_authenticator\" flag for client %s with IP/mask", client->shortname);
			return;

		} else {

			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			ERROR("BlastRADIUS check: Received packet with Message-Authenticator.");
			ERROR("Setting \"require_message_authenticator = true\" for client %s", client->shortname);
			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			ERROR("It looks like the client has been updated to protect from the BlastRADIUS attack.");
			ERROR("Please set \"require_message_authenticator = true\" for client %s", client->shortname);
			ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

			client->require_ma = FR_BOOL_TRUE;
			return;
		}

	}

	/*
	 *	If all of the checks are turned off, then complain for every packet we receive.
	 */
	if (client->limit_proxy_state == FR_BOOL_FALSE) {
		/*
		 *	We have a Message-Authenticator, and it's valid.  We don't need to compain.
		 */
		if (packet->message_authenticator) return;

		if (!fr_debug_lvl) return; /* easier than checking for each line below */

		DEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		DEBUG("BlastRADIUS check: Received packet without Message-Authenticator.");
		DEBUG("YOU MUST SET \"require_message_authenticator = true\", or");
		DEBUG("YOU MUST SET \"limit_proxy_state = true\" for client %s", client->shortname);
		DEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		DEBUG("The packet does not contain Message-Authenticator, which is a security issue");
		DEBUG("UPGRADE THE CLIENT AS YOUR NETWORK IS VULNERABLE TO THE BLASTRADIUS ATTACK.");
		DEBUG("Once the client is upgraded, set \"require_message_authenticator = true\" for client %s", client->shortname);
		DEBUG("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		return;
	}

	/*
	 *	Don't complain here.  rad_packet_ok() will instead
	 *	complain about every packet with Proxy-State but which
	 *	is missing Message-Authenticator.
	 */
	if (client->limit_proxy_state == FR_BOOL_TRUE) {
		return;
	}

	if (packet->proxy_state && !packet->message_authenticator) {
		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		ERROR("BlastRADIUS check: Received packet with Proxy-State, but without Message-Authenticator.");
		ERROR("This is either a BlastRADIUS attack, OR");
		ERROR("the client is a proxy RADIUS server which has not been upgraded.");
		ERROR("Setting \"limit_proxy_state = false\" for client %s", client->shortname);
		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		ERROR("UPGRADE THE CLIENT AS YOUR NETWORK IS VULNERABLE TO THE BLASTRADIUS ATTACK.");
		ERROR("Once the client is upgraded, set \"require_message_authenticator = true\" for client %s", client->shortname);
		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

		client->limit_proxy_state = FR_BOOL_FALSE;

	} else if (((client->src_ipaddr.af == AF_INET) &&
		    (client->src_ipaddr.prefix != 32)) ||
		   ((client->src_ipaddr.af == AF_INET6) &&
		    (client->src_ipaddr.prefix != 128))) {
		/*
		 *	Don't change it from "auto" for wildcard clients.
		 */
		return;

	} else {
		client->limit_proxy_state = FR_BOOL_TRUE;

		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		if (!packet->proxy_state) {
			ERROR("BlastRADIUS check: Received packet without Proxy-State.");
		} else {
			ERROR("BlastRADIUS check: Received packet with Proxy-State and Message-Authenticator.");
		}

		ERROR("Setting \"limit_proxy_state = true\" for client %s", client->shortname);
		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

		if (!packet->message_authenticator) {
			ERROR("The packet does not contain Message-Authenticator, which is a security issue.");
			ERROR("UPGRADE THE CLIENT AS YOUR NETWORK MAY BE VULNERABLE TO THE BLASTRADIUS ATTACK.");
			ERROR("Once the client is upgraded, set \"require_message_authenticator = true\" for client %s", client->shortname);
		} else {
			ERROR("The packet contains Message-Authenticator.");
			if (!packet->eap_message) ERROR("The client has likely been upgraded to protect from the attack.");
			ERROR("Please set \"require_message_authenticator = true\" for client %s", client->shortname);
		}
		ERROR("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
	}
}

#ifdef WITH_TCP
static int dual_tcp_recv(rad_listen_t *listener)
{
	int rcode;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	listen_socket_t *sock = listener->data;
	RADCLIENT	*client = sock->client;

	rad_assert(client != NULL);

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return 0;

	/*
	 *	Allocate a packet for partial reads.
	 */
	if (!sock->packet) {
		sock->packet = rad_alloc(sock, false);
		if (!sock->packet) return 0;

		sock->packet->sockfd = listener->fd;
		sock->packet->src_ipaddr = sock->other_ipaddr;
		sock->packet->src_port = sock->other_port;
		sock->packet->dst_ipaddr = sock->my_ipaddr;
		sock->packet->dst_port = sock->my_port;
		sock->packet->proto = sock->proto;
	}

	/*
	 *	Grab the packet currently being processed.
	 */
	packet = sock->packet;

	rcode = fr_tcp_read_packet(packet, 0);

	/*
	 *	Still only a partial packet.  Put it back, and return,
	 *	so that we'll read more data when it's ready.
	 */
	if (rcode == 0) {
		return 0;
	}

	if (rcode == -1) {	/* error reading packet */
		char buffer[256];

		ERROR("Invalid packet from %s port %d, closing socket: %s",
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, fr_strerror());
	}

	if (rcode < 0) {	/* error or connection reset */
		listener->status = RAD_LISTEN_STATUS_EOL;

		/*
		 *	Tell the event handler that an FD has disappeared.
		 */
		DEBUG("Client has closed connection");
		radius_update_listener(listener);

		/*
		 *	Do NOT free the listener here.  It's in use by
		 *	a request, and will need to hang around until
		 *	all of the requests are done.
		 *
		 *	It is instead free'd in remove_from_request_hash()
		 */
		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_REQUEST:
		if (listener->type != RAD_LISTEN_AUTH) goto bad_packet;

		/*
		 *	Enforce BlastRADIUS checks on TCP, too.
		 */
		if (!rad_packet_ok(packet, (client->require_ma == FR_BOOL_TRUE) | ((client->limit_proxy_state == FR_BOOL_TRUE) << 2), NULL)) {
			FR_STATS_INC(auth, total_malformed_requests);
			rad_free(&sock->packet);
			return 0;
		}

		/*
		 *	Perform BlastRADIUS checks and warnings.
		 */
		if (packet->code == PW_CODE_ACCESS_REQUEST) blastradius_checks(packet, client);

		FR_STATS_INC(auth, total_requests);
		fun = rad_authenticate;
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_REQUEST:
		if (listener->type != RAD_LISTEN_ACCT) {
			/*
			 *	Allow auth + dual.  Disallow
			 *	everything else.
			 */
			if (!((listener->type == RAD_LISTEN_AUTH) &&
			      (listener->dual))) {
				    goto bad_packet;
			}
		}
		FR_STATS_INC(acct, total_requests);
		fun = rad_accounting;
		break;
#endif

	case PW_CODE_STATUS_SERVER:
		if (!main_config.status_server) {
			FR_STATS_INC(auth, total_unknown_types);
			WARN("Ignoring Status-Server request due to security configuration");
			rad_free(&sock->packet);
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
	bad_packet:
		FR_STATS_INC(auth, total_unknown_types);

		DEBUG("Invalid packet code %d sent from client %s port %d : IGNORED",
		      packet->code, client->shortname, packet->src_port);
		rad_free(&sock->packet);
		return 0;
	} /* switch over packet types */

	if (!request_receive(NULL, listener, packet, client, fun)) {
		FR_STATS_INC(auth, total_packets_dropped);
		rad_free(&sock->packet);
		return 0;
	}

	sock->packet = NULL;	/* we have no need for more partial reads */
	return 1;
}

#ifdef WITH_TLS
typedef struct {
	char const	*name;
	SSL_CTX		*ctx;
} fr_realm_ctx_t;		/* hack from tls. */

static int tls_sni_callback(SSL *ssl, UNUSED int *al, void *arg)
{
	fr_tls_server_conf_t *conf = arg;
	char const *name, *p;
	int type;
	fr_realm_ctx_t my_r, *r;
	REQUEST *request;
	char buffer[PATH_MAX];

	/*
	 *	No SNI, that's fine.
	 */
	type = SSL_get_servername_type(ssl);
	if (type < 0) return SSL_TLSEXT_ERR_OK;

	/*
	 *	No realms configured, just use the default context.
	 */
	if (!conf->realms) return SSL_TLSEXT_ERR_OK;

	name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (!name) return SSL_TLSEXT_ERR_OK;

	/*
	 *	RFC Section 6066 Section 3 says that the names are
	 *	ASCII, without a trailing dot.  i.e. punycode.
	 */
	for (p = name; *p != '\0'; p++) {
		if (*p == '-') continue;
		if (*p == '.') continue;
		if ((*p >= 'A') && (*p <= 'Z')) continue;
		if ((*p >= 'a') && (*p <= 'z')) continue;
		if ((*p >= '0') && (*p <= '9')) continue;

		/*
		 *	Anything else, fail.
		 */
		return SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	/*
	 *	Too long, fail.
	 */
	if ((p - name) > 255) return SSL_TLSEXT_ERR_ALERT_FATAL;

	snprintf(buffer, sizeof(buffer), "%s/%s.pem", conf->realm_dir, name);

	my_r.name = buffer;
	r = fr_hash_table_finddata(conf->realms, &my_r);

	/*
	 *	If found, switch certs.  Otherwise use the default
	 *	one.
	 */
	if (r) (void) SSL_set_SSL_CTX(ssl, r->ctx);

	/*
	 *	Set an attribute saying which server has been selected.
	 */
	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	if (request) {
		(void) pair_make_config("TLS-Server-Name-Indication", name, T_OP_SET);
	}

	return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef WITH_RADIUSV11
static const unsigned char radiusv11_allow_protos[] = {
	10, 'r', 'a', 'd', 'i', 'u', 's', '/', '1', '.', '1', /* prefer this */
	10, 'r', 'a', 'd', 'i', 'u', 's', '/', '1', '.', '0',
};

static const unsigned char radiusv11_require_protos[] = {
	10, 'r', 'a', 'd', 'i', 'u', 's', '/', '1', '.', '1',
};

/*
 *	On the server, get the ALPN list requested by the client.
 */
static int radiusv11_server_alpn_cb(SSL *ssl,
				    const unsigned char **out,
				    unsigned char *outlen,
				    const unsigned char *in,
				    unsigned int inlen,
				    void *arg)
{
	rad_listen_t *this = arg;
	listen_socket_t *sock = this->data;
	unsigned char **hack;
	const unsigned char *server;
	unsigned int server_len, i;
	int rcode;
	REQUEST *request;

	request = (REQUEST *)SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);
	fr_assert(request != NULL);

	fr_assert(inlen > 0);

	memcpy(&hack, &out, sizeof(out)); /* const issues */

	/*
	 *	The RADIUS/1.1 configuration for this socket is a combination of what we require, and what we
	 *	require of the client.
	 */
	switch (this->radiusv11) {
		/*
		 *	If we forbid RADIUS/1.1, then we never advertised it via ALPN, and this callback should
		 *	never have been registered.
		 */
	case FR_RADIUSV11_FORBID:
		fr_assert(0);
		server =  radiusv11_allow_protos + 11;
		server_len = 11;
		break;

	case FR_RADIUSV11_ALLOW:
		server = radiusv11_allow_protos;
		server_len = sizeof(radiusv11_allow_protos);
		break;

	case FR_RADIUSV11_REQUIRE:
		server = radiusv11_require_protos;
		server_len = sizeof(radiusv11_require_protos);
		break;
	}

	for (i = 0; i < inlen; i += in[0] + 1) {
		RDEBUG("(TLS) ALPN sent by client is \"%.*s\"", in[i], &in[i + 1]);
	}

	/*
	 *	Select the next protocol.
	 */
	rcode = SSL_select_next_proto(hack, outlen, server, server_len, in, inlen);
	if (rcode == OPENSSL_NPN_NEGOTIATED) {
		server = *out;

		/*
		 *	Tell our socket which protocol we negotiated.
		 */
		fr_assert(*outlen == 10);
		sock->radiusv11 = (server[9] == '1');
		sock->alpn_checked = true;

		RDEBUG("(TLS) ALPN server negotiated application protocol \"%.*s\"", (int) *outlen, server);
		return SSL_TLSEXT_ERR_OK;
	}

	/*
	 *	No common ALPN.
	 */
	RDEBUG("(TLS) ALPN failure - no protocols in common");
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int radiusv11_client_hello_cb(UNUSED SSL *s, int *alert, void *arg)
{
	rad_listen_t *this = arg;
	listen_socket_t *sock = this->data;

	/*
	 *	The server_alpn_cb ran, and checked that the configured ALPN matches the negotiated one.
	 */
	if (sock->alpn_checked) return SSL_CLIENT_HELLO_SUCCESS;

	/*
	 *	The server_alpn_cb did NOT run (???) but we still have a client hello.  We require ALPN and
	 *	none was negotiated, so we return an error.
	 */
	*alert = SSL_AD_NO_APPLICATION_PROTOCOL;

	return SSL_CLIENT_HELLO_ERROR;
}


int fr_radiusv11_client_init(fr_tls_server_conf_t *tls);
int fr_radiusv11_client_get_alpn(rad_listen_t *listener);

int fr_radiusv11_client_init(fr_tls_server_conf_t *tls)
{
	switch (tls->radiusv11) {
	case FR_RADIUSV11_ALLOW:
		if (SSL_CTX_set_alpn_protos(tls->ctx, radiusv11_allow_protos, sizeof(radiusv11_allow_protos)) != 0) {
		fail_protos:
			ERROR("Failed setting RADIUS/1.1 negotiation flags");
			return -1;
		}
		break;

	case FR_RADIUSV11_REQUIRE:
		if (SSL_CTX_set_alpn_protos(tls->ctx, radiusv11_require_protos, sizeof(radiusv11_require_protos)) != 0) goto fail_protos;
		break;

	default:
		break;
	}

	return 0;
}

int fr_radiusv11_client_get_alpn(rad_listen_t *listener)
{
	const unsigned char *data;
	unsigned int len;
	listen_socket_t *sock = listener->data;

	SSL_get0_alpn_selected(sock->ssn->ssl, &data, &len);
	if (!data) {
		DEBUG("(TLS) ALPN server did not send any application protocol");
		if (listener->radiusv11 == FR_RADIUSV11_REQUIRE) {
			DEBUG("(TLS) We have 'radiusv11 = require', but the home server has not negotiated it - closing socket");
			return -1;
		}

		DEBUG("(TLS) ALPN assuming \"radius/1.0\"");
		return 0;	/* allow radius/1.0 */
	}

	DEBUG("(TLS) ALPN server sent application protocol \"%.*s\"", (int) len, data);

	if (len != 10) {
	radiusv11_unknown:
		DEBUG("(TLS) ALPN server sent unknown application protocol - closing connection to home server");
		return -1;
	}

	/*
	 *	Should always be "radius/1.0" or "radius/1.1".  The server MUST echo back one of the strings
	 *	we sent.  If it doesn't, it's a bad server.
	 */
	if (memcmp(data, "radius/1.", 9) != 0) goto radiusv11_unknown;

	if ((data[9] != '0') && (data[9] != '1')) goto radiusv11_unknown;

	/*
	 *	Double-check what the server sent us.  It SHOULD be sane, but it never hurts to check.
	 */
	switch (listener->radiusv11) {
	case FR_RADIUSV11_FORBID:
		if (data[9] != '0') {
			DEBUG("(TLS) ALPN server did not send \"radius/v1.0\" - closing connection to home server");
			return -1;
		}
		break;

	case FR_RADIUSV11_ALLOW:
		sock->radiusv11 = (data[9] == '1');
		break;

	case FR_RADIUSV11_REQUIRE:
		if (data[9] != '1') {
			DEBUG("(TLS) ALPN server did not send \"radius/v1.1\" - closing connection to home server");
			return -1;
		}

		sock->radiusv11 = true;
		break;
	}

	sock->alpn_checked = true;
	return 0;
}
#endif


static int dual_tcp_accept(rad_listen_t *listener)
{
	int newfd;
	uint16_t src_port;
	rad_listen_t *this;
	socklen_t salen;
	struct sockaddr_storage src;
	listen_socket_t *sock;
	fr_ipaddr_t src_ipaddr;
	RADCLIENT *client = NULL;

	salen = sizeof(src);

	DEBUG2(" ... new connection request on TCP socket");

	newfd = accept(listener->fd, (struct sockaddr *) &src, &salen);
	if (newfd < 0) {
		/*
		 *	Non-blocking sockets must handle this.
		 */
#ifdef EWOULDBLOCK
		if (errno == EWOULDBLOCK) {
			return 0;
		}
#endif

		DEBUG2(" ... failed to accept connection");
		return -1;
	}

	if (!fr_sockaddr2ipaddr(&src, salen, &src_ipaddr, &src_port)) {
		close(newfd);
		DEBUG2(" ... unknown address family");
		return 0;
	}

	/*
	 *	Enforce client IP address checks on accept, not on
	 *	every packet.
	 */
	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		close(newfd);
		FR_STATS_INC(auth, total_invalid_requests);
		return 0;
	}

#ifdef WITH_TLS
	/*
	 *	Enforce security restrictions.
	 *
	 *	This shouldn't be necessary in practice.  However, it
	 *	serves as a double-check on configurations.  Marking a
	 *	client as "tls required" means that any accidental
	 *	exposure of the client to non-TLS traffic is
	 *	prevented.
	 */
	if (client->tls_required && !listener->tls) {
		INFO("Ignoring connection to TLS socket from non-TLS client");
		close(newfd);
		return 0;
	}

#ifdef WITH_RADIUSV11
	if (listener->tls) {
		switch (listener->tls->radiusv11) {
		case FR_RADIUSV11_FORBID:
			if (client->radiusv11 == FR_RADIUSV11_REQUIRE) {
				RATE_LIMIT(INFO("Ignoring new connection from client %s it is marked as 'radiusv11 = require', and this socket has 'radiusv11 = forbid'", client->shortname));
				close(newfd);
				return 0;
			}
			break;

		case FR_RADIUSV11_ALLOW:
			/*
			 *	We negotiate it as per the client recommendations (forbid, allow, require)
			 */
			break;

		case FR_RADIUSV11_REQUIRE:
			if (client->radiusv11 == FR_RADIUSV11_FORBID) {
				RATE_LIMIT(INFO("Ignoring new connection from client %s as it is marked as 'radiusv11 = forbid', and this socket has 'radiusv11 = require'", client->shortname));
				close(newfd);
				return 0;
			}
			break;
		}
	}
#endif

#endif

	/*
	 *	Enforce max_connections on client && listen section.
	 */
	if ((client->limit.max_connections != 0) &&
	    (client->limit.max_connections == client->limit.num_connections)) {
		/*
		 *	FIXME: Print client IP/port, and server IP/port.
		 */
		RATE_LIMIT(INFO("Ignoring new connection from client %s due to client max_connections (%d)", client->shortname, client->limit.max_connections));
		close(newfd);
		return 0;
	}

	sock = listener->data;
	if ((sock->limit.max_connections != 0) &&
	    (sock->limit.max_connections == sock->limit.num_connections)) {
		/*
		 *	FIXME: Print client IP/port, and server IP/port.
		 */
		RATE_LIMIT(INFO("Ignoring new connection from client %s due to socket max_connections (%d)", client->shortname, sock->limit.num_connections));
		close(newfd);
		return 0;
	}

	/*
	 *	Add the new listener.  We require a new context here,
	 *	because the allocations for the packet, etc. in the
	 *	child listener will be done in a child thread.
	 */
	this = listen_alloc(NULL, listener->type);
	if (!this) return -1;

	/*
	 *	Now that we've opened a connection, increment the reference count.
	 */
	client->limit.num_connections++;
	sock->limit.num_connections++;

	/*
	 *	Copy everything, including the pointer to the socket
	 *	information.
	 */
	sock = this->data;
	memcpy(this->data, listener->data, sizeof(*sock));
	memcpy(this, listener, sizeof(*this));
	this->next = NULL;
	this->data = sock;	/* fix it back */

	sock->parent = listener->data;
	sock->other_ipaddr = src_ipaddr;
	sock->other_port = src_port;
	sock->client = client;
	sock->opened = sock->last_packet = time(NULL);

	/*
	 *	Set the limits.  The defaults are the parent limits.
	 *	Client limits on max_connections are enforced dynamically.
	 *	Set the MINIMUM of client/socket idle timeout or lifetime.
	 */
	memcpy(&sock->limit, &sock->parent->limit, sizeof(sock->limit));

	if (client->limit.idle_timeout &&
	    ((sock->limit.idle_timeout == 0) ||
	     (client->limit.idle_timeout < sock->limit.idle_timeout))) {
		sock->limit.idle_timeout = client->limit.idle_timeout;
	}

	if (client->limit.lifetime &&
	    ((sock->limit.lifetime == 0) ||
	     (client->limit.lifetime < sock->limit.lifetime))) {
		sock->limit.lifetime = client->limit.lifetime;
	}

	this->fd = newfd;
	this->status = RAD_LISTEN_STATUS_INIT;

	this->parent = listener;
	if (!rbtree_insert(listener->children, this)) {
		ERROR("Failed inserting TCP socket into parent list.");
	}

#ifdef WITH_COMMAND_SOCKET
	if (this->type == RAD_LISTEN_COMMAND) {
		this->recv = command_tcp_recv;
		this->send = command_tcp_send;
		command_write_magic(this->fd, sock);
	} else
#endif
	{

		this->recv = dual_tcp_recv;

#ifdef WITH_TLS
		if (client->tls) this->tls = client->tls;
		if (this->tls) {
			this->recv = dual_tls_recv;
			this->send = dual_tls_send;

			/*
			 *	Set up SNI callback.  We don't do it
			 *	in the main TLS code, because EAP
			 *	doesn't need or use SNI.
			 */
			SSL_CTX_set_tlsext_servername_callback(this->tls->ctx, tls_sni_callback);
			SSL_CTX_set_tlsext_servername_arg(this->tls->ctx, this->tls);
#ifdef WITH_RADIUSV11
			switch (client->radiusv11) {
				/*
				 *	We don't set any callbacks.  If the client sends ALPN (or not), we
				 *	just do normal RADIUS.
				 */
			case FR_RADIUSV11_FORBID:
				DEBUG("(TLS) ALPN radiusv11 = forbid");
				break;

				/*
				 *	Setting the client hello callback catches the case where we send ALPN,
				 *	and the client doesn't send anything.
				 */
			case FR_RADIUSV11_REQUIRE:
				SSL_CTX_set_client_hello_cb(this->tls->ctx, radiusv11_client_hello_cb, this);
				/* FALL-THROUGH */

				/*
				 *	We're willing to do normal RADIUS, but we send ALPN, and then check if
				 *	(or what) the client sends back as ALPN.
				 */
			case FR_RADIUSV11_ALLOW:
				SSL_CTX_set_alpn_select_cb(this->tls->ctx, radiusv11_server_alpn_cb, this);
				DEBUG("(TLS) ALPN radiusv11 = allow / require");
			}
#endif
		}
#endif
	}

#ifdef WITH_COA_TUNNEL
	/*
	 *	Originate CoA requests to a NAS.
	 */
	if (this->send_coa) {
		home_server_t *home;

		rad_assert(this->type != RAD_LISTEN_PROXY);

		this->proxy_send = dual_tls_send_coa_request;
		this->proxy_encode = master_listen[RAD_LISTEN_PROXY].encode;
		this->proxy_decode = master_listen[RAD_LISTEN_PROXY].decode;

		/*
		 *	Automatically create a home server for this
		 *	client.  There MAY be one already one for that
		 *	IP in the configuration files, but it will not
		 *	have this particular port.
		 */
		sock->home = home = talloc_zero(this, home_server_t);
		home->ipaddr = sock->other_ipaddr;
		home->port = sock->other_port;
		home->proto = sock->proto;
		home->secret = sock->client->secret;

		home->coa_irt = this->coa_irt;
		home->coa_mrt = this->coa_mrt;
		home->coa_mrc = this->coa_mrc;
		home->coa_mrd = this->coa_mrd;
		home->recv_coa_server = this->server;
	}
#endif

	/*
	 *	FIXME: set O_NONBLOCK on the accept'd fd.
	 *	See djb's portability rants for details.
	 */

	/*
	 *	Tell the event loop that we have a new FD.
	 *	This can be called from a child thread...
	 */
	radius_update_listener(this);

	return 0;
}
#endif

/*
 *	Ensure that we always keep the correct counters.
 */
#ifdef WITH_TCP
static void common_socket_free(rad_listen_t *this)
{
	listen_socket_t *sock = this->data;

	if (sock->proto != IPPROTO_TCP) return;

	/*
	 *      Decrement the number of connections.
	 */
	if (sock->parent && (sock->parent->limit.num_connections > 0)) {
		sock->parent->limit.num_connections--;
	}
	if (sock->client && sock->client->limit.num_connections > 0) {
		sock->client->limit.num_connections--;
	}
	if (sock->home && sock->home->limit.num_connections > 0) {
		sock->home->limit.num_connections--;
	}
}
#else
#define common_socket_free NULL
#endif

/*
 *	This function is stupid and complicated.
 */
int common_socket_print(rad_listen_t const *this, char *buffer, size_t bufsize)
{
	size_t len;
	listen_socket_t *sock = this->data;
	char const *name = master_listen[this->type].name;

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len
#define ADDSTRING(_x) strlcpy(buffer, _x, bufsize);FORWARD

	ADDSTRING(name);

#ifdef WITH_TCP
	if (this->dual) {
		ADDSTRING("+acct");
	}
#endif

#ifdef WITH_COA_TUNNEL
	if (this->send_coa) {
		ADDSTRING("+coa");
	}
#endif

	if (sock->interface) {
		ADDSTRING(" interface ");
		ADDSTRING(sock->interface);
	}

#ifdef WITH_TCP
	if (this->recv == dual_tcp_accept) {
		ADDSTRING(" proto tcp");
	}
#endif

#ifdef WITH_TCP
	/*
	 *	TCP sockets get printed a little differently, to make
	 *	it clear what's going on.
	 */
	if (sock->client) {
		ADDSTRING(" from client (");
		ip_ntoh(&sock->other_ipaddr, buffer, bufsize);
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->other_port);
		FORWARD;
		ADDSTRING(") -> (");

		if ((sock->my_ipaddr.af == AF_INET) &&
		    (sock->my_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
			strlcpy(buffer, "*", bufsize);
		} else {
			ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
		}
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->my_port);
		FORWARD;

		if (this->server) {
			ADDSTRING(", virtual-server=");
			ADDSTRING(this->server);
		}

		ADDSTRING(")");

		return 1;
	}

#ifdef WITH_PROXY
	/*
	 *	Maybe it's a socket that we opened to a home server.
	 */
	if ((sock->proto == IPPROTO_TCP) &&
	    (this->type == RAD_LISTEN_PROXY)) {
		ADDSTRING(" (");
		ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->my_port);
		FORWARD;
		ADDSTRING(") -> home_server (");

		if ((sock->other_ipaddr.af == AF_INET) &&
		    (sock->other_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
			strlcpy(buffer, "*", bufsize);
		} else {
			ip_ntoh(&sock->other_ipaddr, buffer, bufsize);
		}
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->other_port);
		FORWARD;

		ADDSTRING(")");

		return 1;
	}
#endif	/* WITH_PROXY */
#endif	/* WITH_TCP */

	ADDSTRING(" address ");

	if ((sock->my_ipaddr.af == AF_INET) &&
	    (sock->my_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strlcpy(buffer, "*", bufsize);
	} else {
		ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
	}
	FORWARD;

	ADDSTRING(" port ");
	snprintf(buffer, bufsize, "%d", sock->my_port);
	FORWARD;

#ifdef WITH_TLS
	if (this->tls) {
		ADDSTRING(" (TLS)");
		FORWARD;
	}
#endif

	if (this->server) {
		ADDSTRING(" bound to server ");
		strlcpy(buffer, this->server, bufsize);
	}

#undef ADDSTRING
#undef FORWARD

	return 1;
}

static CONF_PARSER performance_config[] = {
	{ "skip_duplicate_checks", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rad_listen_t, nodup), NULL },

	{ "synchronous", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, rad_listen_t, synchronous), NULL },

	{ "workers", FR_CONF_OFFSET(PW_TYPE_INTEGER, rad_listen_t, workers), NULL },
	CONF_PARSER_TERMINATOR
};


static CONF_PARSER limit_config[] = {
	{ "max_pps", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, max_rate), NULL },

#ifdef WITH_TCP
	{ "max_connections", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, limit.max_connections), "16" },
	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, limit.lifetime), "0" },
	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, limit.idle_timeout), STRINGIFY(30) },
#ifdef SO_RCVTIMEO
	{ "read_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, limit.read_timeout), NULL },
#endif
#ifdef SO_SNDTIMEO
	{ "write_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, listen_socket_t, limit.write_timeout), NULL },
#endif
#endif
	CONF_PARSER_TERMINATOR
};

#ifdef WITH_COA_TUNNEL
static CONF_PARSER coa_config[] = {
	{ "irt",  FR_CONF_OFFSET(PW_TYPE_INTEGER, rad_listen_t, coa_irt), STRINGIFY(2) },
	{ "mrt",  FR_CONF_OFFSET(PW_TYPE_INTEGER, rad_listen_t, coa_mrt), STRINGIFY(16) },
	{ "mrc",  FR_CONF_OFFSET(PW_TYPE_INTEGER, rad_listen_t, coa_mrc), STRINGIFY(5) },
	{ "mrd",  FR_CONF_OFFSET(PW_TYPE_INTEGER, rad_listen_t, coa_mrd), STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};
#endif

#ifdef WITH_TCP
/*
 *	TLS requires child threads to handle the listeners.  Which
 *	means that we need a separate talloc context per child thread.
 *	Which means that we need to manually clean up the child
 *	listeners.  Which means we need to manually track them.
 *
 *	All child thread linking/unlinking is done in the master
 *	thread.  If we care, we can later add a mutex for the parent
 *	listener.
 */
static int listener_cmp(void const *one, void const *two)
{
	if (one < two) return -1;
	if (one > two) return +1;
	return 0;
}

static int listener_unlink(UNUSED void *ctx, UNUSED void *data)
{
	return 2;		/* unlink this node from the tree */
}
#endif


/*
 *	Parse an authentication or accounting socket.
 */
int common_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	uint16_t	listen_port;
	fr_ipaddr_t	ipaddr;
	listen_socket_t *sock = this->data;
	char const	*section_name = NULL;
	CONF_SECTION	*client_cs, *parentcs;
	CONF_SECTION	*subcs;
	CONF_PAIR	*cp;

	this->cs = cs;

	/*
	 *	Try IPv4 first
	 */
	memset(&ipaddr, 0, sizeof(ipaddr));
	ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	sock->backlog = 8;

	rcode = cf_item_parse(cs, "ipaddr", FR_ITEM_POINTER(PW_TYPE_COMBO_IP_ADDR, &ipaddr), NULL);
	if (rcode < 0) return -1;
	if (rcode != 0) rcode = cf_item_parse(cs, "ipv4addr", FR_ITEM_POINTER(PW_TYPE_IPV4_ADDR, &ipaddr), NULL);
	if (rcode < 0) return -1;
	if (rcode != 0) rcode = cf_item_parse(cs, "ipv6addr", FR_ITEM_POINTER(PW_TYPE_IPV6_ADDR, &ipaddr), NULL);
	if (rcode < 0) return -1;
	if (rcode != 0) {
		cf_log_err_cs(cs, "No address specified in listen section");
		return -1;
	}

	rcode = cf_item_parse(cs, "port", FR_ITEM_POINTER(PW_TYPE_SHORT, &listen_port), "0");
	if (rcode < 0) return -1;

	rcode = cf_item_parse(cs, "recv_buff", PW_TYPE_INTEGER, &sock->recv_buff, NULL);
	if (rcode < 0) return -1;

	rcode = cf_item_parse(cs, "backlog", FR_ITEM_POINTER(PW_TYPE_INTEGER, &sock->backlog), NULL);
	if (rcode < 0) return -1;

	sock->proto = IPPROTO_UDP;

	if (cf_pair_find(cs, "proto")) {
#ifndef WITH_TCP
		cf_log_err_cs(cs,
			   "System does not support the TCP protocol.  Delete this line from the configuration file");
		return -1;
#else
		char const *proto = NULL;
#ifdef WITH_TLS
		CONF_SECTION *tls;
#endif

		rcode = cf_item_parse(cs, "proto", FR_ITEM_POINTER(PW_TYPE_STRING, &proto), "udp");
		if (rcode < 0) return -1;

		if (!proto || strcmp(proto, "udp") == 0) {
			sock->proto = IPPROTO_UDP;

		} else if (strcmp(proto, "tcp") == 0) {
			sock->proto = IPPROTO_TCP;

		} else {
			cf_log_err_cs(cs,
				   "Unknown proto name \"%s\"", proto);
			return -1;
		}

		/*
		 *	TCP requires a destination IP for sockets.
		 *	UDP doesn't, so it's allowed.
		 */
#ifdef WITH_PROXY
		if ((this->type == RAD_LISTEN_PROXY) &&
		    (sock->proto != IPPROTO_UDP)) {
			cf_log_err_cs(cs,
				   "Proxy listeners can only listen on proto = udp");
			return -1;
		}
#endif	/* WITH_PROXY */

#ifdef WITH_TLS
		tls = cf_section_sub_find(cs, "tls");

		if (tls) {
			/*
			 *	Don't allow TLS configurations for UDP sockets.
			 */
			if (sock->proto != IPPROTO_TCP) {
				cf_log_err_cs(cs,
					      "TLS transport is not available for UDP sockets");
				return -1;
			}

			/*
			 *	Add support for http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
			 */
			rcode = cf_item_parse(cs, "proxy_protocol", FR_ITEM_POINTER(PW_TYPE_BOOLEAN, &this->proxy_protocol), NULL);
			if (rcode < 0) return -1;

			/*
			 *	Allow non-blocking for TLS sockets
			 */
			rcode = cf_item_parse(cs, "nonblock", FR_ITEM_POINTER(PW_TYPE_BOOLEAN, &this->nonblock), NULL);
			if (rcode < 0) return -1;

			/*
			 *	If unset, set to default.
			 */
			if (listen_port == 0) listen_port = PW_RADIUS_TLS_PORT;

			this->tls = tls_server_conf_parse(tls);
			if (!this->tls) {
				return -1;
			}

			this->tls->name = "RADIUS/TLS";

#ifdef HAVE_PTHREAD_H
			if (pthread_mutex_init(&sock->mutex, NULL) < 0) {
				rad_assert(0 == 1);
				listen_free(&this);
				return 0;
			}
#endif

			rcode = cf_item_parse(cs, "check_client_connections", FR_ITEM_POINTER(PW_TYPE_BOOLEAN, &this->check_client_connections), "no");
			if (rcode < 0) return -1;

#ifdef WITH_RADIUSV11
			if (this->tls->radiusv11_name) {
				rcode = fr_str2int(radiusv11_types, this->tls->radiusv11_name, -1);
				if (rcode < 0) {
					cf_log_err_cs(cs, "Invalid value for 'radiusv11'");
					return -1;
				}

				this->radiusv11 = this->tls->radiusv11 = rcode;
			}
#endif
		}
#else  /* WITH_TLS */
		/*
		 *	Built without TLS.  Disallow it.
		 */
		if (cf_section_sub_find(cs, "tls")) {
			cf_log_err_cs(cs,
				   "TLS transport is not available in this executable");
			return -1;
		}
#endif	/* WITH_TLS */

#endif	/* WITH_TCP */

		/*
		 *	No "proto" field.  Disallow TLS.
		 */
	} else if (cf_section_sub_find(cs, "tls")) {
		cf_log_err_cs(cs,
			   "TLS transport is not available in this \"listen\" section");
		return -1;
	}

	/*
	 *	Magical tuning methods!
	 */
	subcs = cf_section_sub_find(cs, "performance");
	if (subcs) {
		rcode = cf_section_parse(subcs, this,
					 performance_config);
		if (rcode < 0) return -1;

		if (this->synchronous && sock->max_rate) {
			WARN("Setting 'max_pps' is incompatible with 'synchronous'.  Disabling 'max_pps'");
			sock->max_rate = 0;
		}

		if (!this->synchronous && this->workers) {
			WARN("Setting 'workers' requires 'synchronous'.  Disabling 'workers'");
			this->workers = 0;
		}
	}

	subcs = cf_section_sub_find(cs, "limit");
	if (subcs) {
		rcode = cf_section_parse(subcs, sock,
					 limit_config);
		if (rcode < 0) return -1;

		if (sock->max_rate && ((sock->max_rate < 10) || (sock->max_rate > 1000000))) {
			cf_log_err_cs(cs,
				      "Invalid value for \"max_pps\"");
			return -1;
		}

#ifdef WITH_TCP
		if ((sock->limit.idle_timeout > 0) && (sock->limit.idle_timeout < 5)) {
			WARN("Setting idle_timeout to 5");
			sock->limit.idle_timeout = 5;
		}

		if (sock->limit.lifetime) {
			if (sock->limit.lifetime < 5) {
				WARN("Setting lifetime to 5");
				sock->limit.lifetime = 5;
			}

			if (sock->limit.idle_timeout > sock->limit.lifetime) {
				WARN("Setting idle_timeout to 0");
				sock->limit.idle_timeout = 0;
			}

		} else if (!sock->limit.idle_timeout) {
			sock->limit.idle_timeout = 30;
		}

		/*
		 *	Force no duplicate detection for TCP sockets.
		 */
		if (sock->proto == IPPROTO_TCP) {
			this->nodup = true;
		}

	} else {
		sock->limit.max_connections = 60;
		sock->limit.idle_timeout = 30;
		sock->limit.lifetime = 0;
#endif
	}

	sock->my_ipaddr = ipaddr;
	sock->my_port = listen_port;

#ifdef WITH_PROXY
	if (check_config) {
		/*
		 *	Until there is a side effects free way of forwarding a
		 *	request to another virtual server, this check is invalid,
		 *	and should be left disabled.
		 */
#if 0
		if (home_server_find(&sock->my_ipaddr, sock->my_port, sock->proto)) {
				char buffer[128];

				ERROR("We have been asked to listen on %s port %d, which is also listed as a "
				       "home server.  This can create a proxy loop",
				       ip_ntoh(&sock->my_ipaddr, buffer, sizeof(buffer)), sock->my_port);
				return -1;
		}
#endif
		return 0;	/* don't do anything */
	}
#endif

	/*
	 *	If we can bind to interfaces, do so,
	 *	else don't.
	 */
	cp = cf_pair_find(cs, "interface");
	if (cp) {
		char const *value = cf_pair_value(cp);
		if (!value) {
			cf_log_err_cs(cs,
				   "No interface name given");
			return -1;
		}
		sock->interface = value;
	}

#ifdef WITH_DHCP
	/*
	 *	If we can do broadcasts..
	 */
	cp = cf_pair_find(cs, "broadcast");
	if (cp) {
#ifndef SO_BROADCAST
		cf_log_err_cs(cs,
			   "System does not support broadcast sockets.  Delete this line from the configuration file");
		return -1;
#else
		if (this->type != RAD_LISTEN_DHCP) {
			cf_log_err_cp(cp,
				   "Broadcast can only be set for DHCP listeners.  Delete this line from the configuration file");
			return -1;
		}

		char const *value = cf_pair_value(cp);
		if (!value) {
			cf_log_err_cs(cs,
				   "No broadcast value given");
			return -1;
		}

		/*
		 *	Hack... whatever happened to cf_section_parse?
		 */
		sock->broadcast = (strcmp(value, "yes") == 0);
#endif
	}
#endif

	/*
	 *	And bind it to the port.
	 */
	if (listen_bind(this) < 0) {
		char buffer[128];
		cf_log_err_cs(cs,
			   "Error binding to port for %s port %d",
			   ip_ntoh(&sock->my_ipaddr, buffer, sizeof(buffer)),
			   sock->my_port);
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
	rcode = cf_item_parse(cs, "clients", FR_ITEM_POINTER(PW_TYPE_STRING, &section_name), NULL);
	if (rcode < 0) return -1; /* bad string */
	if (rcode == 0) {
		/*
		 *	Explicit list given: use it.
		 */
		client_cs = cf_section_sub_find_name2(parentcs, "clients", section_name);
		if (!client_cs) {
			client_cs = cf_section_find(section_name);
		}
		if (!client_cs) {
			cf_log_err_cs(cs,
				   "Failed to find clients %s {...}",
				   section_name);
			return -1;
		}
	} /* else there was no "clients = " entry. */

	/*
	 *	The "listen" section wasn't given an explicit client list.
	 *	Look for (a) clients in this virtual server, or
	 *	(b) the global client list.
	 */
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

#ifdef WITH_TLS
	sock->clients = client_list_parse_section(client_cs, (this->tls != NULL));
#else
	sock->clients = client_list_parse_section(client_cs, false);
#endif
	if (!sock->clients) {
		cf_log_err_cs(cs,
			   "Failed to load clients for this listen section");
		return -1;
	}

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		/*
		 *	Re-write the listener receive function to
		 *	allow us to accept the socket.
		 */
		this->recv = dual_tcp_accept;

		/*
		 *	@todo - add a free function?  Though this only
		 *	matters when we're tearing down the server, so
		 *	perhaps it's less relevant.
		 */
		this->children = rbtree_create(this, listener_cmp, NULL, 0);
		if (!this->children) {
			cf_log_err_cs(cs, "Failed to create child list for TCP socket.");
			return -1;
		}
	}
#endif

	return 0;
}

/*
 *	Send a response packet
 */
static int common_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == common_socket_send);

	if (request->reply->code == 0) return 0;

#ifdef WITH_UDPFROMTO
	/*
	 *	Overwrite the src ip address on the outbound packet
	 *	with the one specified by the client.
	 *	This is useful to work around broken DSR implementations
	 *	and other routing issues.
	 */
	if (request->client->src_ipaddr.af != AF_UNSPEC) {
		request->reply->src_ipaddr = request->client->src_ipaddr;
	}
#endif

	if (rad_send(request->reply, request->packet,
		     request->client->secret) < 0) {
		RERROR("Failed sending reply: %s",
			       fr_strerror());
		return -1;
	}
	return 0;
}


#ifdef WITH_PROXY
/*
 *	Send a packet to a home server.
 *
 *	FIXME: have different code for proxy auth & acct!
 */
static int proxy_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->proxy_listener == listener);
	rad_assert(listener->proxy_send == proxy_socket_send);

	if (rad_send(request->proxy, NULL,
		     request->home_server->secret) < 0) {
		RERROR("Failed sending proxied request: %s",
			       fr_strerror());
		return -1;
	}

	return 0;
}
#endif

#ifdef WITH_STATS
/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int stats_socket_recv(rad_listen_t *listener)
{
	ssize_t		rcode;
	int		code;
	uint16_t	src_port;
	RADIUS_PACKET	*packet;
	RADCLIENT	*client = NULL;
	fr_ipaddr_t	src_ipaddr;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	if (rcode < 20) {	/* RADIUS_HDR_LEN */
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		FR_STATS_INC(auth, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(auth, total_invalid_requests);
		return 0;
	}

	FR_STATS_TYPE_INC(client->auth.total_requests);

	/*
	 *	We only understand Status-Server on this socket.
	 */
	if (code != PW_CODE_STATUS_SERVER) {
		DEBUG("Ignoring packet code %d sent to Status-Server port",
		      code);
		rad_recv_discard(listener->fd);
		FR_STATS_INC(auth, total_unknown_types);
		return 0;
	}

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(NULL, listener->fd, 1); /* require message authenticator */
	if (!packet) {
		FR_STATS_INC(auth, total_malformed_requests);
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		return 0;
	}

	if (!request_receive(NULL, listener, packet, client, rad_status_server)) {
		FR_STATS_INC(auth, total_packets_dropped);
		rad_free(&packet);
		return 0;
	}

	return 1;
}
#endif

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int auth_socket_recv(rad_listen_t *listener)
{
	ssize_t		rcode;
	int		code;
	uint16_t	src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	RADCLIENT	*client = NULL;
	fr_ipaddr_t	src_ipaddr;
	TALLOC_CTX	*ctx;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	FR_STATS_INC(auth, total_requests);

	if (rcode < 20) {	/* RADIUS_HDR_LEN */
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		FR_STATS_INC(auth, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(auth, total_invalid_requests);
		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch (code) {
	case PW_CODE_ACCESS_REQUEST:
		FR_STATS_TYPE_INC(client->auth.total_requests);
		fun = rad_authenticate;
		break;

	case PW_CODE_STATUS_SERVER:
		if (!main_config.status_server) {
			rad_recv_discard(listener->fd);
			FR_STATS_INC(auth, total_unknown_types);
			WARN("Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		FR_STATS_INC(auth, total_unknown_types);

		if (DEBUG_ENABLED) ERROR("Receive - Invalid packet code %d sent to authentication port from "
					 "client %s port %d", code, client->shortname, src_port);
		return 0;
	} /* switch over packet types */

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(auth, total_packets_dropped);
		return 0;
	}
	talloc_set_name_const(ctx, "auth_listener_pool");

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(ctx, listener->fd, (client->require_ma == FR_BOOL_TRUE) | ((client->limit_proxy_state == FR_BOOL_TRUE) << 2));
	if (!packet) {
		FR_STATS_INC(auth, total_malformed_requests);
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	/*
	 *	Perform BlastRADIUS checks and warnings.
	 */
	if (packet->code == PW_CODE_ACCESS_REQUEST) blastradius_checks(packet, client);

#ifdef __APPLE__
#ifdef WITH_UDPFROMTO
	/*
	 *	This is a NICE Mac OSX bug.  Create an interface with
	 *	two IP address, and then configure one listener for
	 *	each IP address.  Send thousands of packets to one
	 *	address, and some will show up on the OTHER socket.
	 *
	 *	This hack works ONLY if the clients are global.  If
	 *	each listener has the same client IP, but with
	 *	different secrets, then it will fail the rad_recv()
	 *	check above, and there's nothing you can do.
	 */
	{
		listen_socket_t *sock = listener->data;
		rad_listen_t *other;

		other = listener_find_byipaddr(&packet->dst_ipaddr,
					       packet->dst_port, sock->proto);
		if (other) listener = other;
	}
#endif
#endif

	if (!request_receive(ctx, listener, packet, client, fun)) {
		FR_STATS_INC(auth, total_packets_dropped);
		talloc_free(ctx);
		return 0;
	}

	return 1;
}


#ifdef WITH_ACCOUNTING
/*
 *	Receive packets from an accounting socket
 */
static int acct_socket_recv(rad_listen_t *listener)
{
	ssize_t		rcode;
	int		code;
	uint16_t	src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	RADCLIENT	*client = NULL;
	fr_ipaddr_t	src_ipaddr;
	TALLOC_CTX	*ctx;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	FR_STATS_INC(acct, total_requests);

	if (rcode < 20) {	/* RADIUS_HDR_LEN */
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		FR_STATS_INC(acct, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(acct, total_invalid_requests);
		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch (code) {
	case PW_CODE_ACCOUNTING_REQUEST:
		FR_STATS_TYPE_INC(client->acct.total_requests);
		fun = rad_accounting;
		break;

	case PW_CODE_STATUS_SERVER:
		if (!main_config.status_server) {
			rad_recv_discard(listener->fd);
			FR_STATS_INC(acct, total_unknown_types);

			WARN("Ignoring Status-Server request due to security configuration");
			return 0;
		}
		fun = rad_status_server;
		break;

	default:
		rad_recv_discard(listener->fd);
		FR_STATS_INC(acct, total_unknown_types);

		DEBUG("Invalid packet code %d sent to a accounting port from client %s port %d : IGNORED",
		      code, client->shortname, src_port);
		return 0;
	} /* switch over packet types */

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(acct, total_packets_dropped);
		return 0;
	}
	talloc_set_name_const(ctx, "acct_listener_pool");

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(ctx, listener->fd, 0);
	if (!packet) {
		FR_STATS_INC(acct, total_malformed_requests);
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	/*
	 *	There can be no duplicate accounting packets.
	 */
	if (!request_receive(ctx, listener, packet, client, fun)) {
		FR_STATS_INC(acct, total_packets_dropped);
		rad_free(&packet);
		talloc_free(ctx);
		return 0;
	}

	return 1;
}
#endif


#ifdef WITH_COA
static int do_proxy(REQUEST *request)
{
	VALUE_PAIR *vp;

	if (request->in_proxy_hash ||
	    (request->proxy_reply && (request->proxy_reply->code != 0))) {
		return 0;
	}

	vp = fr_pair_find_by_num(request->config, PW_HOME_SERVER_POOL, 0, TAG_ANY);

	if (vp) {
		if (!home_pool_byname(vp->vp_strvalue, HOME_TYPE_COA)) {
			REDEBUG2("Cannot proxy to unknown pool %s",
				 vp->vp_strvalue);
			return -1;
		}

		return 1;
	}

	/*
	 *	We have a destination IP address.  It will (later) proxied.
	 */
	vp = fr_pair_find_by_num(request->config, PW_PACKET_DST_IP_ADDRESS, 0, TAG_ANY);
	if (!vp) vp = fr_pair_find_by_num(request->config, PW_PACKET_DST_IPV6_ADDRESS, 0, TAG_ANY);

#ifdef WITH_COA_TUNNEL
	if (!vp) vp = fr_pair_find_by_num(request->config, PW_PROXY_TO_ORIGINATING_REALM, 0, TAG_ANY);
#endif

	if (!vp) return 0;

	return 1;
}

/*
 *	Receive a CoA packet.
 */
int rad_coa_recv(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	int ack, nak;
	int proxy_status;
	VALUE_PAIR *vp;

	/*
	 *	Get the correct response
	 */
	switch (request->packet->code) {
	case PW_CODE_COA_REQUEST:
		ack = PW_CODE_COA_ACK;
		nak = PW_CODE_COA_NAK;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		ack = PW_CODE_DISCONNECT_ACK;
		nak = PW_CODE_DISCONNECT_NAK;
		break;

	default:		/* shouldn't happen */
		return RLM_MODULE_FAIL;
	}

#ifdef WITH_PROXY
#define WAS_PROXIED (request->proxy)
#else
#define WAS_PROXIED (0)
#endif

	if (!WAS_PROXIED) {
		/*
		 *	RFC 5176 Section 3.3.  If we have a CoA-Request
		 *	with Service-Type = Authorize-Only, it MUST
		 *	have a State attribute in it.
		 */
		vp = fr_pair_find_by_num(request->packet->vps, PW_SERVICE_TYPE, 0, TAG_ANY);
		if (request->packet->code == PW_CODE_COA_REQUEST) {
			if (vp && (vp->vp_integer == PW_AUTHORIZE_ONLY)) {
				vp = fr_pair_find_by_num(request->packet->vps, PW_STATE, 0, TAG_ANY);
				if (!vp || (vp->vp_length == 0)) {
					REDEBUG("CoA-Request with Service-Type = Authorize-Only MUST contain a State attribute");
					request->reply->code = PW_CODE_COA_NAK;
					return RLM_MODULE_FAIL;
				}
			}
		} else if (vp) {
			/*
			 *	RFC 5176, Section 3.2.
			 */
			REDEBUG("Disconnect-Request MUST NOT contain a Service-Type attribute");
			request->reply->code = PW_CODE_DISCONNECT_NAK;
			return RLM_MODULE_FAIL;
		}

		rcode = process_recv_coa(0, request);
		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = nak;
			break;

		case RLM_MODULE_HANDLED:
			return rcode;

		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			proxy_status = do_proxy(request);
			if (proxy_status == 1) return RLM_MODULE_OK;

			if (proxy_status < 0) {
				request->reply->code = nak;
			} else {
				request->reply->code = ack;
			}
			break;
		}

	}

#ifdef WITH_PROXY
	else if (request->proxy_reply) {
		/*
		 *	Start the reply code with the proxy reply
		 *	code.
		 */
		request->reply->code = request->proxy_reply->code;
	}
#endif

	/*
	 *	Copy State from the request to the reply.
	 *	See RFC 5176 Section 3.3.
	 */
	vp = fr_pair_list_copy_by_num(request->reply, request->packet->vps, PW_STATE, 0, TAG_ANY);
	if (vp) fr_pair_add(&request->reply->vps, vp);

	/*
	 *	We may want to over-ride the reply.
	 */
	if (request->reply->code) {
		rcode = process_send_coa(0, request);
		switch (rcode) {
			/*
			 *	We need to send CoA-NAK back if Service-Type
			 *	is Authorize-Only.  Rely on the user's policy
			 *	to do that.  We're not a real NAS, so this
			 *	restriction doesn't (ahem) apply to us.
			 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			/*
			 *	Over-ride an ACK with a NAK
			 */
			request->reply->code = nak;
			break;

		case RLM_MODULE_HANDLED:
			return rcode;

		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/*
			 *	Do NOT over-ride a previously set value.
			 *	Otherwise an "ok" here will re-write a
			 *	NAK to an ACK.
			 */
			if (request->reply->code == 0) {
				request->reply->code = ack;
			}
			break;
		}
	}

	return RLM_MODULE_OK;
}


/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int coa_socket_recv(rad_listen_t *listener)
{
	ssize_t		rcode;
	int		code;
	uint16_t	src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	RADCLIENT	*client = NULL;
	fr_ipaddr_t	src_ipaddr;
	TALLOC_CTX	*ctx;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	if (rcode < 20) {	/* RADIUS_HDR_LEN */
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		FR_STATS_INC(coa, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(coa, total_requests);
		FR_STATS_INC(coa, total_invalid_requests);
		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch (code) {
	case PW_CODE_COA_REQUEST:
		FR_STATS_INC(coa, total_requests);
		fun = rad_coa_recv;
		break;

	case PW_CODE_DISCONNECT_REQUEST:
		FR_STATS_INC(dsc, total_requests);
		fun = rad_coa_recv;
		break;

	default:
		rad_recv_discard(listener->fd);
		FR_STATS_INC(coa, total_unknown_types);
		DEBUG("Invalid packet code %d sent to coa port from client %s port %d : IGNORED",
		      code, client->shortname, src_port);
		return 0;
	} /* switch over packet types */

	ctx = talloc_pool(NULL, main_config.talloc_pool_size);
	if (!ctx) {
		rad_recv_discard(listener->fd);
		FR_STATS_INC(coa, total_packets_dropped);
		return 0;
	}
	talloc_set_name_const(ctx, "coa_socket_recv_pool");

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(ctx, listener->fd, (client->require_ma == FR_BOOL_TRUE));
	if (!packet) {
		FR_STATS_INC(coa, total_malformed_requests);
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		talloc_free(ctx);
		return 0;
	}

	if (!request_receive(ctx, listener, packet, client, fun)) {
		FR_STATS_INC(coa, total_packets_dropped);
		rad_free(&packet);
		talloc_free(ctx);
		return 0;
	}

	return 1;
}
#endif

#ifdef WITH_PROXY
/*
 *	Recieve packets from a proxy socket.
 */
static int proxy_socket_recv(rad_listen_t *listener)
{
	RADIUS_PACKET	*packet;
#ifdef WITH_TCP
	listen_socket_t *sock;
#endif
	char		buffer[128];

	packet = rad_recv(NULL, listener->fd, 0);
	if (!packet) {
		if (DEBUG_ENABLED) ERROR("Receive - %s", fr_strerror());
		return 0;
	}

	switch (packet->code) {
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_ACCESS_REJECT:
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
		break;
#endif

#ifdef WITH_COA
	case PW_CODE_DISCONNECT_ACK:
	case PW_CODE_DISCONNECT_NAK:
	case PW_CODE_COA_ACK:
	case PW_CODE_COA_NAK:
		break;
#endif

	default:
		/*
		 *	FIXME: Update MIB for packet types?
		 */
		ERROR("Invalid packet code %d sent to a proxy port "
		       "from home server %s port %d - ID %d : IGNORED",
		       packet->code,
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
#ifdef WITH_STATS
		listener->stats.total_unknown_types++;
#endif
		rad_free(&packet);
		return 0;
	}

#ifdef WITH_TCP
	sock = listener->data;
	packet->proto = sock->proto;
#endif

	if (!request_proxy_reply(packet)) {
#ifdef WITH_STATS
		listener->stats.total_packets_dropped++;
#endif
		rad_free(&packet);
		return 0;
	}

	return 1;
}

#ifdef WITH_TCP
/*
 *	Recieve packets from a proxy socket.
 */
static int proxy_socket_tcp_recv(rad_listen_t *listener)
{
	int rcode;
	RADIUS_PACKET	*packet;
	listen_socket_t	*sock = listener->data;
	char		buffer[256];

	if (listener->status != RAD_LISTEN_STATUS_KNOWN) return 0;

	if (!sock->packet) {
		sock->packet = rad_alloc(sock, false);
		if (!sock->packet) return 0;

		sock->packet->sockfd = listener->fd;
		sock->packet->src_ipaddr = sock->other_ipaddr;
		sock->packet->src_port = sock->other_port;
		sock->packet->dst_ipaddr = sock->my_ipaddr;
		sock->packet->dst_port = sock->my_port;
		sock->packet->proto = sock->proto;
	}

	packet = sock->packet;

	rcode = fr_tcp_read_packet(packet, 0);

	/*
	 *	Still only a partial packet.  Put it back, and return,
	 *	so that we'll read more data when it's ready.
	 */
	if (rcode == 0) {
		return 0;
	}

	if (rcode == -1) {	/* error reading packet */
		ERROR("Invalid packet from %s port %d, closing socket: %s",
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, fr_strerror());
	}

	if (rcode < 0) {	/* error or connection reset */
		listener->status = RAD_LISTEN_STATUS_EOL;

		/*
		 *	Tell the event handler that an FD has disappeared.
		 */
		DEBUG("Home server %s port %d has closed connection",
		      ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		      packet->src_port);

		radius_update_listener(listener);

		/*
		 *	Do NOT free the listener here.  It's in use by
		 *	a request, and will need to hang around until
		 *	all of the requests are done.
		 *
		 *	It is instead free'd in remove_from_request_hash()
		 */
		return 0;
	}

	sock->packet = NULL;	/* we have no need for more partial reads */

	/*
	 *	FIXME: Client MIB updates?
	 */
	switch (packet->code) {
	case PW_CODE_ACCESS_ACCEPT:
	case PW_CODE_ACCESS_CHALLENGE:
	case PW_CODE_ACCESS_REJECT:
		break;

#ifdef WITH_ACCOUNTING
	case PW_CODE_ACCOUNTING_RESPONSE:
		break;
#endif

	default:
		/*
		 *	FIXME: Update MIB for packet types?
		 */
		ERROR("Invalid packet code %d sent to a proxy port "
		       "from home server %s port %d - ID %d : IGNORED",
		       packet->code,
		       ip_ntoh(&packet->src_ipaddr, buffer, sizeof(buffer)),
		       packet->src_port, packet->id);
		rad_free(&packet);
		return 0;
	}


	/*
	 *	FIXME: Have it return an indication of packets that
	 *	are OK to ignore (dups, too late), versus ones that
	 *	aren't OK to ignore (unknown response, spoofed, etc.)
	 *
	 *	Close the socket on bad packets...
	 */
	if (!request_proxy_reply(packet)) {
		rad_free(&packet);
		return 0;
	}

	sock->opened = sock->last_packet = time(NULL);

	return 1;
}
#endif
#endif

#ifdef WITH_TLS
#define TLS_UNUSED
#else
#define TLS_UNUSED UNUSED
#endif

static int client_socket_encode(TLS_UNUSED rad_listen_t *listener, REQUEST *request)
{
#ifdef WITH_TLS
	/*
	 *	Don't encode fake packets.
	 */
	listen_socket_t *sock = listener->data;
	if (sock->state == LISTEN_TLS_CHECKING) return 0;

#ifdef WITH_RADIUSV11
	request->reply->radiusv11 = sock->radiusv11;
#endif

#endif

	if (!request->reply->code) return 0;

	if (request->reply->data) return 0; /* already encoded */

	if (rad_encode(request->reply, request->packet, request->client->secret) < 0) {
		RERROR("Failed encoding packet: %s", fr_strerror());

		return -1;
	}

	if (request->reply->data_len > (MAX_PACKET_LEN - 100)) {
		RWDEBUG("Packet is large, and possibly truncated - %zd vs max %d",
		      request->reply->data_len, MAX_PACKET_LEN);
	}

	if (rad_sign(request->reply, request->packet, request->client->secret) < 0) {
		RERROR("Failed signing packet: %s", fr_strerror());

		return -1;
	}

	return 0;
}


static int client_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
#ifdef WITH_TLS
	listen_socket_t *sock = request->listener->data;

#ifdef WITH_RADIUSV11
	request->packet->radiusv11 = sock->radiusv11;
#endif
#endif

	if (rad_verify(request->packet, NULL,
		       request->client->secret) < 0) {
		return -1;
	}

#ifdef WITH_TLS
	/*
	 *	FIXME: Add the rest of the TLS parameters, too?  But
	 *	how do we separate EAP-TLS parameters from RADIUS/TLS
	 *	parameters?
	 */
	if (sock->ssn && sock->ssn->ssl) {
#ifdef PSK_MAX_IDENTITY_LEN
		const char *identity = SSL_get_psk_identity(sock->ssn->ssl);
		if (identity) {
			RDEBUG("Retrieved psk identity: %s", identity);
			pair_make_request("TLS-PSK-Identity", identity, T_OP_SET);
		}
#endif
	}
#endif

	return rad_decode(request->packet, NULL,
			  request->client->secret);
}

#ifdef WITH_PROXY
#ifdef WITH_RADIUSV11
#define RADIUSV11_UNUSED
#else
#define RADIUSV11_UNUSED UNUSED
#endif

static int proxy_socket_encode(RADIUSV11_UNUSED rad_listen_t *listener, REQUEST *request)
{
#ifdef WITH_RADIUSV11
	listen_socket_t *sock = listener->data;

	request->proxy->radiusv11 = sock->radiusv11;
#endif

	if (rad_encode(request->proxy, NULL, request->home_server->secret) < 0) {
		RERROR("Failed encoding proxied packet: %s", fr_strerror());

		return -1;
	}

	if (request->proxy->data_len > (MAX_PACKET_LEN - 100)) {
		RWDEBUG("Packet is large, and possibly truncated - %zd vs max %d",
		      request->proxy->data_len, MAX_PACKET_LEN);
	}

	if (rad_sign(request->proxy, NULL, request->home_server->secret) < 0) {
		RERROR("Failed signing proxied packet: %s", fr_strerror());

		return -1;
	}

	return 0;
}


static int proxy_socket_decode(RADIUSV11_UNUSED rad_listen_t *listener, REQUEST *request)
{
#ifdef WITH_RADIUSV11
	listen_socket_t *sock = listener->data;

	request->proxy_reply->radiusv11 = sock->radiusv11;
#endif

	/*
	 *	rad_verify is run in event.c, received_proxy_response()
	 */

	return rad_decode(request->proxy_reply, request->proxy,
			   request->home_server->secret);
}
#endif

#include "command.c"

/*
 *	Temporarily NOT const!
 */
static fr_protocol_t master_listen[RAD_LISTEN_MAX] = {
#ifdef WITH_STATS
	{ RLM_MODULE_INIT, "status", sizeof(listen_socket_t), NULL,
	  common_socket_parse, NULL,
	  stats_socket_recv, common_socket_send,
	  common_socket_print, client_socket_encode, client_socket_decode },
#else
	/*
	 *	This always gets defined.
	 */
	{ RLM_MODULE_INIT, "status", 0, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL},	/* RAD_LISTEN_NONE */
#endif

#ifdef WITH_PROXY
	/* proxying */
	{ RLM_MODULE_INIT, "proxy", sizeof(listen_socket_t), NULL,
	  common_socket_parse, common_socket_free,
	  proxy_socket_recv, proxy_socket_send,
	  common_socket_print, proxy_socket_encode, proxy_socket_decode },
#else
	{ 0, "proxy", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#endif

	/* authentication */
	{ RLM_MODULE_INIT, "auth", sizeof(listen_socket_t), NULL,
	  common_socket_parse, common_socket_free,
	  auth_socket_recv, common_socket_send,
	  common_socket_print, client_socket_encode, client_socket_decode },

#ifdef WITH_ACCOUNTING
	/* accounting */
	{ RLM_MODULE_INIT, "acct", sizeof(listen_socket_t), NULL,
	  common_socket_parse, common_socket_free,
	  acct_socket_recv, common_socket_send,
	  common_socket_print, client_socket_encode, client_socket_decode},
#else
	{ 0, "acct", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#endif

#ifdef WITH_DETAIL
	/* detail */
	{ RLM_MODULE_INIT, "detail", sizeof(listen_detail_t), NULL,
	  detail_parse, detail_free,
	  detail_recv, detail_send,
	  detail_print, detail_encode, detail_decode },
#endif

	/* vlan query protocol */
	{ 0, "vmps", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },

	/* dhcp query protocol */
	{ 0, "dhcp", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },

#ifdef WITH_COMMAND_SOCKET
	/* TCP command socket */
	{ RLM_MODULE_INIT, "control", sizeof(fr_command_socket_t), NULL,
	  command_socket_parse, command_socket_free,
	  command_domain_accept, command_domain_send,
	  command_socket_print, command_socket_encode, command_socket_decode },
#else
	{ 0, "command", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#endif

#ifdef WITH_COA
	/* Change of Authorization */
	{ RLM_MODULE_INIT, "coa", sizeof(listen_socket_t), NULL,
	  common_socket_parse, NULL,
	  coa_socket_recv, common_socket_send,
	  common_socket_print, client_socket_encode, client_socket_decode },
#else
	{ 0, "coa", 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL },
#endif

};



/*
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
	int rcode;
	struct sockaddr_storage salocal;
	socklen_t	salen;
	listen_socket_t *sock = this->data;
#ifndef WITH_TCP
#define proto_for_port "udp"
#define sock_type SOCK_DGRAM
#else
	char const *proto_for_port = "udp";
	int sock_type = SOCK_DGRAM;

	if (sock->proto == IPPROTO_TCP) {
#ifdef WITH_VMPS
		if (this->type == RAD_LISTEN_VQP) {
			ERROR("VQP does not support TCP transport");
			return -1;
		}
#endif

		proto_for_port = "tcp";
		sock_type = SOCK_STREAM;
	}
#endif

	/*
	 *	If the port is zero, then it means the appropriate
	 *	thing from /etc/services.
	 */
	if (sock->my_port == 0) {
		struct servent	*svp;

		switch (this->type) {
		case RAD_LISTEN_AUTH:
			svp = getservbyname ("radius", proto_for_port);
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = PW_AUTH_UDP_PORT;
			}
			break;

#ifdef WITH_ACCOUNTING
		case RAD_LISTEN_ACCT:
			svp = getservbyname ("radacct", proto_for_port);
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = PW_ACCT_UDP_PORT;
			}
			break;
#endif

#ifdef WITH_PROXY
		case RAD_LISTEN_PROXY:
			/* leave it at zero */
			break;
#endif

#ifdef WITH_VMPS
		case RAD_LISTEN_VQP:
			sock->my_port = 1589;
			break;
#endif

#ifdef WITH_COMMAND_SOCKET
		case RAD_LISTEN_COMMAND:
			sock->my_port = PW_RADMIN_PORT;
			break;
#endif

#ifdef WITH_COA
		case RAD_LISTEN_COA:
			svp = getservbyname ("radius-dynauth", "udp");
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = PW_COA_UDP_PORT;
			}
			break;
#endif

#ifdef WITH_DHCP
		case RAD_LISTEN_DHCP:
			svp = getservbyname ("bootps", "udp");
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = 67;
			}
			break;
#endif

		default:
			WARN("Internal sanity check failed in binding to socket.  Ignoring problem");
			return -1;
		}
	}

	/*
	 *	Don't open sockets if we're checking the config.
	 */
	if (check_config) {
		this->fd = -1;
		return 0;
	}

	/*
	 *	Copy fr_socket() here, as we may need to bind to a device.
	 */
	this->fd = socket(sock->my_ipaddr.af, sock_type, 0);
	if (this->fd < 0) {
		char buffer[256];

		this->print(this, buffer, sizeof(buffer));

		ERROR("Failed opening %s: %s", buffer, fr_syserror(errno));
		return -1;
	}

#ifdef FD_CLOEXEC
	/*
	 *	We don't want child processes inheriting these
	 *	file descriptors.
	 */
	rcode = fcntl(this->fd, F_GETFD);
	if (rcode >= 0) {
		if (fcntl(this->fd, F_SETFD, rcode | FD_CLOEXEC) < 0) {
			close(this->fd);
			ERROR("Failed setting close on exec: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

	/*
	 *	Bind to a device BEFORE touching IP addresses.
	 */
	if (sock->interface) {
#ifdef SO_BINDTODEVICE
		/*
		 *	Linux: Bind to an interface by name.
		 */
		struct ifreq ifreq;

		memset(&ifreq, 0, sizeof(ifreq));
		strlcpy(ifreq.ifr_name, sock->interface, sizeof(ifreq.ifr_name));

		rad_suid_up();
		rcode = setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
				   (char *)&ifreq, sizeof(ifreq));
		rad_suid_down();
		if (rcode < 0) {
			close(this->fd);
			ERROR("Failed binding to interface %s: %s",
			      sock->interface, fr_syserror(errno));
			return -1;
		}
#else

		/*
		 *	If we don't bind to an interface by name, we usually bind to it by index.
		 */
		int idx = if_nametoindex(sock->interface);

		if (idx == 0) {
			close(this->fd);
			ERROR("Failed finding interface %s: %s",
			      sock->interface, fr_syserror(errno));
			return -1;
		}

#ifdef IP_BOUND_IF
		/*
		 *	OSX / ?BSD / Solaris: bind to interface by index for IPv4
		 */
		if (sock->my_ipaddr.af == AF_INET) {
			rad_suid_up();
			rcode = setsockopt(this->fd, IPPROTO_IP, IP_BOUND_IF, &idx, sizeof(idx));
			rad_suid_down();
			if (rcode < 0) {
				close(this->fd);
				ERROR("Failed binding to interface %s: %s",
				      sock->interface, fr_syserror(errno));
				return -1;
			}
		} else
#endif

#ifdef IPV6_BOUND_IF
		/*
		 *	OSX / ?BSD / Solaris: bind to interface by index for IPv6
		 */
		if (sock->my_ipaddr.af == AF_INET6) {
			rad_suid_up();
			rcode = setsockopt(this->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, sizeof(idx));
			rad_suid_down();
			if (rcode < 0) {
				close(this->fd);
				ERROR("Failed binding to interface %s: %s",
				      sock->interface, fr_syserror(errno));
				return -1;
			}
		} else
#endif

#ifdef HAVE_STRUCT_SOCKADDR_IN6
#ifdef HAVE_NET_IF_H
		/*
		 *	Otherwise generic IPv6: set the scope to the
		 *	interface, and hope that all of the read/write
		 *	routines respect that.
		 */
		if (sock->my_ipaddr.af == AF_INET6) {
			if (sock->my_ipaddr.scope == 0) {
				sock->my_ipaddr.scope = idx;
			} /* else scope was already defined */
		} else
#endif
#endif

		/*
		 *	IPv4, or no socket options to bind to interface.
		 */
		{
			close(this->fd);
			ERROR("Failed binding to interface %s: \"bind to device\" is unsupported", sock->interface);
			return -1;
		}
#endif	/* SO_BINDTODEVICE */
	}

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			close(this->fd);
			ERROR("Failed to reuse address: %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

#if defined(WITH_TCP) && defined(WITH_UDPFROMTO)
	else			/* UDP sockets get UDPfromto */
#endif

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(this->fd) != 0) {
		ERROR("Failed initializing udpfromto: %s",
		       fr_syserror(errno));
		close(this->fd);
		return -1;
	}
#endif

	/*
	 *	Set up sockaddr stuff.
	 */
	if (!fr_ipaddr2sockaddr(&sock->my_ipaddr, sock->my_port, &salocal, &salen)) {
		close(this->fd);
		return -1;
	}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (sock->my_ipaddr.af == AF_INET6) {
		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY

		if (IN6_IS_ADDR_UNSPECIFIED(&sock->my_ipaddr.ipaddr.ip6addr)) {
			int on = 1;

			if (setsockopt(this->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				       (char *)&on, sizeof(on)) < 0) {
				ERROR("Failed setting socket to IPv6 "
				       "only: %s", fr_syserror(errno));

				close(this->fd);
				return -1;
			}
		}
#endif /* IPV6_V6ONLY */
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

	if (sock->my_ipaddr.af == AF_INET) {
#if (defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)) || defined(IP_DONTFRAG)
		int flag;
#endif

#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)

		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;
		if (setsockopt(this->fd, IPPROTO_IP, IP_MTU_DISCOVER,
			       &flag, sizeof(flag)) < 0) {
			ERROR("Failed disabling PMTU discovery: %s",
			       fr_syserror(errno));

			close(this->fd);
			return -1;
		}
#endif

#if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;
		if (setsockopt(this->fd, IPPROTO_IP, IP_DONTFRAG,
			       &flag, sizeof(flag)) < 0) {
			ERROR("Failed setting don't fragment flag: %s",
			       fr_syserror(errno));

			close(this->fd);
			return -1;
		}
#endif
	}

#ifdef WITH_DHCP
#ifdef SO_BROADCAST
	if (sock->broadcast) {
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
			close(this->fd);
			ERROR("Can't set broadcast option: %s",
			       fr_syserror(errno));
			return -1;
		}
	}
#endif
#endif

#ifdef SO_RCVBUF
	if (sock->recv_buff > 0) {
		int opt;

		opt = sock->recv_buff;
		if (setsockopt(this->fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(int)) < 0) {
			WARN("Failed setting 'recv_buf': %s", fr_syserror(errno));
		}
	}
#endif

	/*
	 *	May be binding to priviledged ports.
	 */
	if (sock->my_port != 0) {
		rad_suid_up();
		rcode = bind(this->fd, (struct sockaddr *) &salocal, salen);
		rad_suid_down();
		if (rcode < 0) {
			char buffer[256];
			close(this->fd);

			this->print(this, buffer, sizeof(buffer));
			ERROR("Failed binding to %s: %s\n",
			       buffer, fr_syserror(errno));
			return -1;
		}

		/*
		 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
		 *	kernel instead binds us to a 1.2.3.4.  If this
		 *	happens, notice, and remember our real IP.
		 */
		{
			struct sockaddr_storage	src;
			socklen_t		sizeof_src = sizeof(src);

			memset(&src, 0, sizeof_src);
			if (getsockname(this->fd, (struct sockaddr *) &src,
					&sizeof_src) < 0) {
				close(this->fd);
				ERROR("Failed getting socket name: %s",
				       fr_syserror(errno));
				return -1;
			}

			if (!fr_sockaddr2ipaddr(&src, sizeof_src,
						&sock->my_ipaddr, &sock->my_port)) {
				close(this->fd);
				ERROR("Socket has unsupported address family");
				return -1;
			}
		}
	}

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		/*
		 *	If we dedicate a worker thread to each socket, then the socket is blocking.
		 *
		 *	Otherwise, all input TCP sockets are non-blocking.
		 */
		if (!this->workers) {
			if (fr_nonblock(this->fd) < 0) {
				close(this->fd);
				ERROR("Failed setting non-blocking on socket: %s",
				      fr_syserror(errno));
				return -1;
			}
		}

		/*
		 *	Allow a backlog of 8 listeners, but only for incoming interfaces.
		 */
#ifdef WITH_PROXY
		if (this->type != RAD_LISTEN_PROXY)
#endif
		if (listen(this->fd, sock->backlog) < 0) {
			close(this->fd);
			ERROR("Failed in listen(): %s", fr_syserror(errno));
			return -1;
		}
	}
#endif

	/*
	 *	Mostly for proxy sockets.
	 */
	sock->other_ipaddr.af = sock->my_ipaddr.af;

/*
 *	Don't screw up other people.
 */
#undef proto_for_port
#undef sock_type

	return 0;
}


static int _listener_free(rad_listen_t *this)
{
	/*
	 *	Other code may have eaten the FD.
	 */
	if (this->fd >= 0) close(this->fd);

	if (master_listen[this->type].free) {
		master_listen[this->type].free(this);
	}

#ifdef WITH_TCP
	if ((this->type == RAD_LISTEN_AUTH)
#ifdef WITH_ACCT
	    || (this->type == RAD_LISTEN_ACCT)
#endif
#ifdef WITH_PROXY
	    || (this->type == RAD_LISTEN_PROXY)
#endif
#ifdef WITH_COMMAND_SOCKET
	    || ((this->type == RAD_LISTEN_COMMAND) &&
		(((fr_command_socket_t *) this->data)->magic != COMMAND_SOCKET_MAGIC))
#endif
		) {

		/*
		 *	Remove the child from the parent tree.
		 */
		if (this->parent) {
			rbtree_deletebydata(this->parent->children, this);
		}

		/*
		 *	Delete / close all of the children, too!
		 */
		if (this->children) {
			rbtree_walk(this->children, RBTREE_DELETE_ORDER, listener_unlink, this);
		}

#ifdef WITH_TLS
		/*
		 *	Note that we do NOT free this->tls, as the
		 *	pointer is parented by its CONF_SECTION.  It
		 *	may be used by multiple listeners.
		 */
		if (this->tls) {
			listen_socket_t *sock = this->data;

			rad_assert(talloc_parent(sock) == this);
			rad_assert(sock->ev == NULL);

			rad_assert(!sock->ssn || (talloc_parent(sock->ssn) == sock));
			rad_assert(!sock->request || (talloc_parent(sock->request) == sock));

			if (sock->home && sock->home->listeners) (void) rbtree_deletebydata(sock->home->listeners, this);

#ifdef HAVE_PTHREAD_H
			pthread_mutex_destroy(&(sock->mutex));
#endif

		}
#endif	/* WITH_TLS */
	}
#endif				/* WITH_TCP */

	return 0;
}


/*
 *	Allocate & initialize a new listener.
 */
static rad_listen_t *listen_alloc(TALLOC_CTX *ctx, RAD_LISTEN_TYPE type)
{
	rad_listen_t *this;

	this = talloc_zero(ctx, rad_listen_t);

	this->type = type;
	this->recv = master_listen[this->type].recv;
	this->send = master_listen[this->type].send;
	this->print = master_listen[this->type].print;

	if (type != RAD_LISTEN_PROXY) {
		this->encode = master_listen[this->type].encode;
		this->decode = master_listen[this->type].decode;
	} else {
		this->send = NULL; /* proxy packets shouldn't call this! */
		this->proxy_send = master_listen[this->type].send;
		this->proxy_encode = master_listen[this->type].encode;
		this->proxy_decode = master_listen[this->type].decode;
	}

	talloc_set_destructor(this, _listener_free);

	this->data = talloc_zero_array(this, uint8_t, master_listen[this->type].inst_size);

	return this;
}

#ifdef WITH_PROXY

/*
 *	Externally visible function for creating a new proxy LISTENER.
 *
 *	Not thread-safe, but all calls to it are protected by the
 *	proxy mutex in event.c
 */
rad_listen_t *proxy_new_listener(TALLOC_CTX *ctx, home_server_t *home, uint16_t src_port)
{
	time_t now;
	rad_listen_t *this;
	listen_socket_t *sock;
	char buffer[256];

	if (!home) return NULL;

	rad_assert(home->virtual_server == NULL); /* we only open real sockets */

	if ((home->limit.max_connections > 0) &&
	    (home->limit.num_connections >= home->limit.max_connections)) {
		RATE_LIMIT(INFO("Home server %s has too many open connections (%d)",
				home->log_name, home->limit.max_connections));
		return NULL;
	}

	now = time(NULL);
	if (home->last_failed_open == now) {
		WARN("Suppressing attempt to open socket to 'down' home server");
		return NULL;
	}

	this = listen_alloc(ctx, RAD_LISTEN_PROXY);

	sock = this->data;
	sock->other_ipaddr = home->ipaddr;
	sock->other_port = home->port;
	sock->home = home;

	sock->my_ipaddr = home->src_ipaddr;
	sock->my_port = src_port;
	sock->proto = home->proto;

	/*
	 *	For error messages.
	 */
	this->print(this, buffer, sizeof(buffer));

#ifdef WITH_TCP
	sock->opened = sock->last_packet = now;

	if (home->proto == IPPROTO_TCP) {
		this->recv = proxy_socket_tcp_recv;

		/*
		 *	Our limit is the smaller of the socket config and this home server config.
		 */
		if (home->limit.lifetime && (home->limit.lifetime < sock->limit.lifetime)) {
			sock->limit.lifetime = home->limit.lifetime;
		}

		if (home->limit.idle_timeout && (home->limit.idle_timeout < sock->limit.idle_timeout)) {
			sock->limit.idle_timeout = home->limit.idle_timeout;

			if (sock->limit.lifetime && (sock->limit.lifetime > sock->limit.idle_timeout)) {
				sock->limit.idle_timeout = 0;
			}

		}

		if (!sock->limit.lifetime && !sock->limit.idle_timeout) sock->limit.idle_timeout = 30;

#ifdef WITH_TLS
		this->nonblock |= home->nonblock;
#endif

		/*
		 *	FIXME: connect() is blocking!
		 *	We do this with the proxy mutex locked, which may
		 *	cause large delays!
		 */
		this->fd = fr_socket_client_tcp(&home->src_ipaddr,
						&home->ipaddr, home->port,
#ifdef WITH_TLS
						this->nonblock
#else
						false
#endif
			);

		/*
		 *	Set max_requests, lifetime, and idle_timeout from the home server.
		 */
		sock->limit = home->limit;
	} else
#endif
		this->fd = fr_socket(&home->src_ipaddr, src_port);

	if (this->fd < 0) {
		this->print(this, buffer,sizeof(buffer));
		ERROR("Failed opening new proxy socket '%s' : %s",
		      buffer, fr_strerror());
		home->last_failed_open = now;
		listen_free(&this);
		return NULL;
	}


#ifdef WITH_TCP
#ifdef SO_KEEPALIVE
	if (home->proto == IPPROTO_TCP) {
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
			ERROR("(TLS) Failed to set SO_KEEPALIVE: %s", fr_syserror(errno));
			goto error;
		}
	}
#endif

#ifdef WITH_TLS
	if ((home->proto == IPPROTO_TCP) && home->tls) {
		DEBUG("(TLS) Trying new outgoing proxy connection to %s", buffer);

#ifdef WITH_RADIUSV11
		this->radiusv11 = home->tls->radiusv11;
#endif

#ifdef TCP_NODELAY
		/*
		 *	Also set TCP_NODELAY, to force the data to be written quickly.
		 */
		if (sock->proto == IPPROTO_TCP) {
			int on = 1;

			if (setsockopt(this->fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
				ERROR("(TLS) Failed to set TCP_NODELAY: %s", fr_syserror(errno));
				goto error;
			}
		}
#endif

		/*
		 *	Set non-blocking if it's configured.
		 */
		if (this->nonblock) {
			if (fr_nonblock(this->fd) < 0) {
				ERROR("(TLS) Failed setting nonblocking for proxy socket '%s' - %s", buffer, fr_strerror());
				goto error;
			}

			rad_assert(home->listeners != NULL);

			if (!rbtree_insert(home->listeners, this)) {
				ERROR("(TLS) Failed adding tracking informtion for proxy socket '%s'", buffer);
				goto error;
			}

		} else {
			/*
			 *	Only set timeouts when the socket is blocking.  This allows blocking
			 *	sockets to still time out when the underlying socket is dead.
			 */
#ifdef SO_RCVTIMEO
			if (sock->limit.read_timeout) {
				struct timeval tv;

				tv.tv_sec = sock->limit.read_timeout;
				tv.tv_usec = 0;

				if (setsockopt(this->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
					ERROR("(TLS) Failed to set read_timeout: %s", fr_syserror(errno));
					goto error;
				}
			}
#endif

#ifdef SO_SNDTIMEO
			if (sock->limit.write_timeout) {
				struct timeval tv;

				tv.tv_sec = sock->limit.write_timeout;
				tv.tv_usec = 0;

				if (setsockopt(this->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
					ERROR("(TLS) Failed to set write_timeout: %s", fr_syserror(errno));
					goto error;
				}
			}
#endif
		}

		/*
		 *	This is blocking.  :(
		 */
		sock->ssn = tls_new_client_session(sock, home->tls, this->fd, &sock->certs);
		if (!sock->ssn) {
			ERROR("(TLS) Failed opening connection on proxy socket '%s'", buffer);
			goto error;
		}

#ifdef WITH_RADIUSV11
		/*
		 *	Must not have alpn_checked yet.  This code only runs for blocking sockets.
		 */
		if (sock->ssn->connected && (fr_radiusv11_client_get_alpn(this) < 0)) {
			goto error;
		}
#endif

		sock->connect_timeout = home->connect_timeout;

		this->recv = proxy_tls_recv;
		this->proxy_send = proxy_tls_send;

#ifdef HAVE_PTHREAD_H
		if (pthread_mutex_init(&sock->mutex, NULL) < 0) {
			rad_assert(0 == 1);
			listen_free(&this);
			return 0;
		}
#endif

		/*
		 *	Make sure that this listener is associated with the home server.
		 *
		 *	Since it's TCP+TLS, this socket can only be associated with one home server.
		 */

#ifdef WITH_COA_TUNNEL
		if (home->recv_coa) {
			RADCLIENT *client;

			this->send_coa = true;

			/*
			 *	Don't set this->send_coa, as we are
			 *	not sending CoA-Request packets to
			 *	this home server.  Instead, we are
			 *	receiving CoA packets from this home
			 *	server.
			 */
			this->send = proxy_tls_send_reply;
			this->encode = master_listen[RAD_LISTEN_AUTH].encode;
			this->decode = master_listen[RAD_LISTEN_AUTH].decode;

			/*
			 *	Automatically create a client for this
			 *	home server.  There MAY be one already
			 *	one for that IP in the configuration
			 *	files, but there's no guarantee that
			 *	it exists.
			 *
			 *	The only real reason to use an
			 *	existing client is to track various
			 *	statistics.
			 */
			sock->client = client = talloc_zero(sock, RADCLIENT);
			client->ipaddr = sock->other_ipaddr;
			client->src_ipaddr = sock->my_ipaddr;
			client->longname = client->shortname = talloc_typed_strdup(client, home->name);
			client->secret = talloc_typed_strdup(client, home->secret);
			client->nas_type = "none";
			client->server = talloc_typed_strdup(client, home->recv_coa_server);
		}
#endif
	}
#endif
#endif
	/*
	 *	Figure out which port we were bound to.
	 */
	if (sock->my_port == 0) {
		struct sockaddr_storage	src;
		socklen_t		sizeof_src = sizeof(src);

		memset(&src, 0, sizeof_src);
		if (getsockname(this->fd, (struct sockaddr *) &src,
				&sizeof_src) < 0) {
			ERROR("Failed getting socket name for '%s': %s",
			      buffer, fr_syserror(errno));
		error:
			close(this->fd);
			home->last_failed_open = now;
#ifdef WITH_TLS
			if (home->listeners && this->nonblock) rbtree_deletebydata(home->listeners, this);
#endif
			listen_free(&this);
			return NULL;
		}

		if (!fr_sockaddr2ipaddr(&src, sizeof_src,
					&sock->my_ipaddr, &sock->my_port)) {
			ERROR("Socket has unsupported address family for '%s'", buffer);
			goto error;
		}

		this->print(this, buffer, sizeof(buffer));
	}

	if (rad_debug_lvl >= 3) {
		DEBUG("Opened new proxy socket '%s'", buffer);
	}

	home->limit.num_connections++;

	return this;
}
#endif

static const FR_NAME_NUMBER listen_compare[] = {
#ifdef WITH_STATS
	{ "status",	RAD_LISTEN_NONE },
#endif
	{ "auth",	RAD_LISTEN_AUTH },
#ifdef WITH_COA_TUNNEL
	{ "auth+coa",	RAD_LISTEN_AUTH },
#endif
#ifdef WITH_ACCOUNTING
	{ "acct",	RAD_LISTEN_ACCT },
	{ "auth+acct",	RAD_LISTEN_AUTH },
#ifdef WITH_COA_TUNNEL
	{ "auth+acct+coa",	RAD_LISTEN_AUTH },
#endif
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
#ifdef WITH_COA
	{ "coa",	RAD_LISTEN_COA },
#endif
	{ NULL, 0 },
};

static int _free_proto_handle(fr_dlhandle *handle)
{
	dlclose(*handle);
	return 0;
}

static rad_listen_t *listen_parse(CONF_SECTION *cs, char const *server)
{
	int		type, rcode;
	char const	*listen_type;
	rad_listen_t	*this;
	CONF_PAIR	*cp;
	char const	*value;
	fr_dlhandle	handle;
	CONF_SECTION	*server_cs;
#ifdef WITH_TCP
	char const	*p;
#endif
	char		buffer[32];

	cp = cf_pair_find(cs, "type");
	if (!cp) {
		cf_log_err_cs(cs,
			   "No type specified in listen section");
		return NULL;
	}

	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err_cp(cp,
			      "Type cannot be empty");
		return NULL;
	}

	snprintf(buffer, sizeof(buffer), "proto_%s", value);
	handle = fr_dlopenext(buffer);
	if (handle) {
		fr_protocol_t	*proto;
		fr_dlhandle	*marker;

		proto = dlsym(handle, buffer);
		if (!proto) {
#if 0
			cf_log_err_cs(cs,
				      "Failed linking to protocol %s : %s\n",
				      value, dlerror());
#endif
			dlclose(handle);
			return NULL;
		}

		type = fr_str2int(listen_compare, value, -1);
		rad_assert(type >= 0); /* shouldn't be able to compile an invalid type */

		memcpy(&master_listen[type], proto, sizeof(*proto));

		/*
		 *	Ensure handle gets closed if config section gets freed
		 */
		marker = talloc(cs, fr_dlhandle);
		*marker = handle;
		talloc_set_destructor(marker, _free_proto_handle);

		if (master_listen[type].magic !=  RLM_MODULE_INIT) {
			ERROR("Failed to load protocol '%s', it has the wrong version.",
			       master_listen[type].name);
			return NULL;
		}
	}

	cf_log_info(cs, "listen {");

	listen_type = NULL;
	rcode = cf_item_parse(cs, "type", FR_ITEM_POINTER(PW_TYPE_STRING, &listen_type), "");
	if (rcode < 0) return NULL;
	if (rcode == 1) {
		cf_log_err_cs(cs,
			   "No type specified in listen section");
		return NULL;
	}

	type = fr_str2int(listen_compare, listen_type, -1);
	if (type < 0) {
		cf_log_err_cs(cs,
			   "Invalid type \"%s\" in listen section.",
			   listen_type);
		return NULL;
	}

	/*
	 *	DHCP and VMPS *must* be loaded dynamically.
	 */
	if (master_listen[type].magic !=  RLM_MODULE_INIT) {
		ERROR("Cannot load protocol '%s', as the required library does not exist",
		      master_listen[type].name);
		return NULL;
	}

	/*
	 *	Allow listen sections in the default config to
	 *	refer to a server.
	 */
	if (!server) {
		rcode = cf_item_parse(cs, "virtual_server", FR_ITEM_POINTER(PW_TYPE_STRING, &server), NULL);
		if (rcode < 0) return NULL;
	}

#ifdef WITH_PROXY
	/*
	 *	We were passed a virtual server, so the caller is
	 *	defining a proxy listener inside of a virtual server.
	 *	This isn't allowed right now.
	 */
	else if (type == RAD_LISTEN_PROXY) {
		ERROR("Error: listen type \"proxy\" Cannot appear in a virtual server section");
		return NULL;
	}
#endif

	/*
	 *	Set up cross-type data.
	 */
	this = listen_alloc(cs, type);
	this->server = server;
	this->fd = -1;

#ifdef WITH_TCP
	/*
	 *	Add special flags '+' for "auth+acct".
	 */
	p = strchr(listen_type, '+');
	if (p) {
		if (strncmp(p + 1, "acct", 4) == 0) {
			this->dual = true;
#ifdef WITH_COA_TUNNEL
			p += 5;
		}

		if (strcmp(p, "+coa") == 0) {
			this->send_coa = true;
#endif
		}
	}
#endif

	/*
	 *	Call per-type parser.
	 */
	if (master_listen[type].parse(cs, this) < 0) {
		listen_free(&this);
		return NULL;
	}

	server_cs = cf_section_sub_find_name2(main_config.config, "server",
					      this->server);
	if (!server_cs && this->server) {
		cf_log_err_cs(cs, "No such server \"%s\"", this->server);
		listen_free(&this);
		return NULL;
	}

#ifdef WITH_COA_TUNNEL
	if (this->send_coa) {
		CONF_SECTION	*coa;

		if (!this->tls) {
			cf_log_err_cs(cs, "TLS is required in order to use \"+coa\"");
			listen_free(&this);
			return NULL;
		}

		/*
		 *	Parse the configuration if it exists.
		 */
		coa = cf_section_sub_find(cs, "coa");
		if (coa) {
			rcode = cf_section_parse(cs, this, coa_config);
			if (rcode < 0) {
				listen_free(&this);
				return NULL;
			}
		}

		/*
		 *	Use the same boundary checks as for home
		 *	server. See realm_home_server_sanitize().
		 */
		FR_INTEGER_BOUND_CHECK("coa_irt", this->coa_irt, >=, 1);
		FR_INTEGER_BOUND_CHECK("coa_irt", this->coa_irt, <=, 5);

		FR_INTEGER_BOUND_CHECK("coa_mrc", this->coa_mrc, <=, 20);

		FR_INTEGER_BOUND_CHECK("coa_mrt", this->coa_mrt, <=, 30);

		FR_INTEGER_BOUND_CHECK("coa_mrd", this->coa_mrd, >=, 5);
		FR_INTEGER_BOUND_CHECK("coa_mrd", this->coa_mrd, <=, 60);
	}
#endif	/* WITH_COA_TUNNEL */

	cf_log_info(cs, "}");

	return this;
}

#ifdef HAVE_PTHREAD_H
/*
 *	A child thread which does NOTHING other than read and process
 *	packets.
 */
static void *recv_thread(void *arg)
{
	rad_listen_t *this = arg;

	while (1) {
		this->recv(this);
	}

	return NULL;
}
#endif


/*
 *	Generate a list of listeners.  Takes an input list of
 *	listeners, too, so we don't close sockets with waiting packets.
 */
int listen_init(CONF_SECTION *config, rad_listen_t **head, bool spawn_flag)
{
	bool		override = false;
	CONF_SECTION	*cs = NULL;
	rad_listen_t	**last;
	rad_listen_t	*this;
	fr_ipaddr_t	server_ipaddr;
	uint16_t	auth_port = 0;

	/*
	 *	We shouldn't be called with a pre-existing list.
	 */
	rad_assert(head && (*head == NULL));

	memset(&server_ipaddr, 0, sizeof(server_ipaddr));

	last = head;
	server_ipaddr.af = AF_UNSPEC;

	/*
	 *	If the port is specified on the command-line,
	 *	it over-rides the configuration file.
	 *
	 *	FIXME: If argv[0] == "vmpsd", then don't listen on auth/acct!
	 */
	if (main_config.port > 0) {
		auth_port = main_config.port;

		/*
		 *	-p X but no -i Y on the command-line.
		 */
		if (main_config.myip.af == AF_UNSPEC) {
			ERROR("The command-line says \"-p %d\", but there is no associated IP address to use",
			      main_config.port);
			return -1;
		}
	}

	/*
	 *	If the IP address was configured on the command-line,
	 *	use that as the "bind_address"
	 */
	if (main_config.myip.af != AF_UNSPEC) {
		listen_socket_t *sock;

		memcpy(&server_ipaddr, &main_config.myip,
		       sizeof(server_ipaddr));
		override = true;

#ifdef WITH_VMPS
		if (strcmp(main_config.name, "vmpsd") == 0) {
			this = listen_alloc(config, RAD_LISTEN_VQP);
			if (!auth_port) auth_port = 1589;
		} else
#endif
			this = listen_alloc(config, RAD_LISTEN_AUTH);

		sock = this->data;

		sock->my_ipaddr = server_ipaddr;
		sock->my_port = auth_port;

		sock->clients = client_list_parse_section(config, false);
		if (!sock->clients) {
			cf_log_err_cs(config,
				   "Failed to find any clients for this listen section");
			listen_free(&this);
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(head);
			ERROR("There appears to be another RADIUS server running on the authentication port %d", sock->my_port);
			listen_free(&this);
			return -1;
		}
		auth_port = sock->my_port;	/* may have been updated in listen_bind */
		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       main_config.name);
			if (!cs) cs = cf_section_sub_find_name2(config, "server",
						       "default");
			if (cs) this->server = cf_section_name2(cs);
		}

		*last = this;
		last = &(this->next);

#ifdef WITH_VMPS
		/*
		 *	No acct for vmpsd
		 */
		if (strcmp(main_config.name, "vmpsd") == 0) goto add_sockets;
#endif

#ifdef WITH_ACCOUNTING
		/*
		 *	Open Accounting Socket.
		 *
		 *	If we haven't already gotten acct_port from
		 *	/etc/services, then make it auth_port + 1.
		 */
		this = listen_alloc(config, RAD_LISTEN_ACCT);
		sock = this->data;

		/*
		 *	Create the accounting socket.
		 *
		 *	The accounting port is always the
		 *	authentication port + 1
		 */
		sock->my_ipaddr = server_ipaddr;
		sock->my_port = auth_port + 1;

		sock->clients = client_list_parse_section(config, false);
		if (!sock->clients) {
			cf_log_err_cs(config,
				   "Failed to find any clients for this listen section");
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			ERROR("There appears to be another RADIUS server running on the accounting port %d", sock->my_port);
			return -1;
		}

		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       main_config.name);
			if (cs) this->server = main_config.name;
		}

		*last = this;
		last = &(this->next);
#endif
	}

	/*
	 *	They specified an IP on the command-line, ignore
	 *	all listen sections except the one in '-n'.
	 */
	if (main_config.myip.af != AF_UNSPEC) {
		CONF_SECTION *subcs;
		char const *name2 = cf_section_name2(cs);

		cs = cf_section_sub_find_name2(config, "server",
					       main_config.name);
		if (!cs) goto add_sockets;

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

		goto add_sockets;
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
		char const *name2 = cf_section_name2(cs);

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

add_sockets:
	/*
	 *	No sockets to receive packets, this is an error.
	 *	proxying is pointless.
	 */
	if (!*head) {
		ERROR("The server is not configured to listen on any ports.  Cannot start");
		return -1;
	}

	/*
	 *	Print out which sockets we're listening on, and
	 *	add them to the event list.
	 */
	for (this = *head; this != NULL; this = this->next) {
#ifdef WITH_TLS
		if (!check_config && !spawn_flag && this->tls) {
			cf_log_err_cs(this->cs, "Threading must be enabled for TLS sockets to function properly");
			cf_log_err_cs(this->cs, "You probably need to do '%s -fxx -l stdout' for debugging",
				      main_config.name);
			return -1;
		}
#endif
		if (!check_config) {
			if (this->workers && !spawn_flag) {
				WARN("Setting 'workers' requires 'synchronous'.  Disabling 'workers'");
				this->workers = 0;
			}

			if (this->workers) {
#ifdef HAVE_PTHREAD_H
				int rcode;
				uint32_t i;
				char buffer[256];

				this->print(this, buffer, sizeof(buffer));

				for (i = 0; i < this->workers; i++) {
					pthread_t id;

					/*
					 *	FIXME: create detached?
					 */
					rcode = pthread_create(&id, 0, recv_thread, this);
					if (rcode != 0) {
						ERROR("Thread create failed: %s",
						      fr_syserror(rcode));
						fr_exit(1);
					}

					DEBUG("Thread %d for %s\n", i, buffer);
				}
#else
				WARN("Setting 'workers' requires 'synchronous'.  Disabling 'workers'");
				this->workers = 0;
#endif

			} else {
				radius_update_listener(this);
			}

		}
	}

	/*
	 *	Haven't defined any sockets.  Die.
	 */
	if (!*head) return -1;

#ifdef WITH_COA_TUNNEL
	if (listen_coa_init() < 0) return -1;
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
		talloc_free(this);
		this = next;
	}

	*head = NULL;
}

#ifdef WITH_STATS
RADCLIENT_LIST *listener_find_client_list(fr_ipaddr_t const *ipaddr, uint16_t port, int proto)
{
	rad_listen_t *this;

	for (this = main_config.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		if ((this->type != RAD_LISTEN_AUTH)
#ifdef WITH_ACCOUNTING
		    && (this->type != RAD_LISTEN_ACCT)
#endif
#ifdef WITH_COA
		    && (this->type != RAD_LISTEN_COA)
#endif
		    ) continue;

		sock = this->data;

		if (sock->my_port != port) continue;
		if (sock->proto != proto) continue;
		if (fr_ipaddr_cmp(ipaddr, &sock->my_ipaddr) != 0) continue;

		return sock->clients;
	}

	return NULL;
}
#endif

rad_listen_t *listener_find_byipaddr(fr_ipaddr_t const *ipaddr, uint16_t port, int proto)
{
	rad_listen_t *this;

	for (this = main_config.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		sock = this->data;

		if (sock->my_port != port) continue;
		if (sock->proto != proto) continue;
		if (fr_ipaddr_cmp(ipaddr, &sock->my_ipaddr) != 0) continue;

		return this;
	}

	/*
	 *	Failed to find a specific one.  Find INADDR_ANY
	 */
	for (this = main_config.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		sock = this->data;

		if (sock->my_port != port) continue;
		if (sock->proto != proto) continue;
		if (!fr_inaddr_any(&sock->my_ipaddr)) continue;

		return this;
	}

	return NULL;
}

#ifdef WITH_COA_TUNNEL
/*
 *	This is easier than putting ifdef's everywhere.  And
 *	realistically, there aren't many systems which have OpenSSL,
 *	but not pthreads.
 */
#ifndef HAVE_PTHREAD_H
#error CoA tunnels require pthreads
#endif

#include <pthread.h>

static rbtree_t *coa_tree = NULL;

/*
 *	We have an RB tree of keys, and within each key, a hash table
 *	of one or more listeners associated with that key.
 */
typedef struct {
	char const     	*key;
	fr_hash_table_t	*ht;

	pthread_mutex_t	mutex;		/* per key, to lower contention */
} coa_key_t;

typedef struct {
	coa_key_t	*coa_key;
	rad_listen_t	*listener;
} coa_entry_t;

static int coa_key_cmp(void const *one, void const *two)
{
	coa_key_t const *a = one;
	coa_key_t const *b = two;

	return strcmp(a->key, b->key);
}

static void coa_key_free(void *data)
{
	coa_key_t *coa_key = data;

	pthread_mutex_destroy(&coa_key->mutex);
	fr_hash_table_free(coa_key->ht);
	talloc_free(coa_key);
}

static uint32_t coa_entry_hash(void const *data)
{
	coa_entry_t const *a = (coa_entry_t const *) data;

	return fr_hash(&a->listener, sizeof(a->listener));
}

static int coa_entry_cmp(void const *one, void const *two)
{
	coa_entry_t const *a = one;
	coa_entry_t const *b = two;

	return memcmp(&a->listener, &b->listener, sizeof(a->listener));
}

/*
 *	Delete the entry, without holding the parents lock.
 */
static void coa_entry_free(void *data)
{
	talloc_free(data);
}

static int coa_entry_destructor(coa_entry_t *entry)
{
	pthread_mutex_lock(&entry->coa_key->mutex);
	fr_hash_table_delete(entry->coa_key->ht, entry);
	pthread_mutex_unlock(&entry->coa_key->mutex);

	return 0;
}

static int listen_coa_init(void)
{
	/*
	 *	We will be looking up listeners by key.  Each key
	 *	points us to a list of listeners.  Each key has it's
	 *	own mutex, so that it's thread-safe.
	 */
	coa_tree = rbtree_create(NULL, coa_key_cmp, coa_key_free, RBTREE_FLAG_LOCK);
	if (!coa_tree) {
		ERROR("Failed creating internal tracking tree for Originating-Realm-Key");
		return -1;
	}

	return 0;
}

void listen_coa_free(void)
{
	/*
	 *	If we are freeing the tree, then all of the listeners
	 *	must have been freed first.
	 */
	rad_assert(rbtree_num_elements(coa_tree) == 0);
	rbtree_free(coa_tree);
	coa_tree = NULL;
}

/*
 *	Adds a listener to the hash of listeners, based on key.
 */
void listen_coa_add(rad_listen_t *this, char const *key)
{
	int tries = 0;
	coa_key_t my_key, *coa_key;
	coa_entry_t *entry;

	rad_assert(this->send_coa);
	rad_assert(this->parent);
	rad_assert(!this->key);

	/*
	 *	Find the key.  If we can't find it, then create it.
	 */
	my_key.key = key;

retry:
	coa_key = rbtree_finddata(coa_tree, &my_key);
	if (!coa_key) {
		coa_key = talloc_zero(NULL, coa_key_t);
		if (!coa_key) return;
		coa_key->key = talloc_strdup(coa_key, key);
		if (!coa_key->key) {
		fail:
			talloc_free(coa_key);
			return;
		}

		/*
		 *	Create the hash table of listeners.
		 */
		coa_key->ht = fr_hash_table_create(coa_entry_hash, coa_entry_cmp, coa_entry_free);
		if (!coa_key->ht) goto fail;

		if (!rbtree_insert(coa_tree, coa_key)) {
			talloc_free(coa_key);

			/*
			 *	The lookups are mutex protected, but
			 *	if there's time between the lookup and
			 *	the insert, another thread may have
			 *	created the node.  In which case we
			 *	try again.
			 */
			if (tries < 3) goto retry;
			tries++;
			return;
		}

		(void) pthread_mutex_init(&coa_key->mutex, NULL);
	}

	/*
	 *	No need to strdup() this, coa_key will only be removed
	 *	after the listener has been removed.
	 */
	if (!this->key) this->key = coa_key->key;

	entry = talloc_zero(this, coa_entry_t);
	if (!entry) return;
	talloc_set_destructor(entry, coa_entry_destructor);

	entry->coa_key = coa_key;
	entry->listener = this;

	/*
	 *	Insert the entry into the hash table.
	 */
	pthread_mutex_lock(&coa_key->mutex);
	fr_hash_table_insert(coa_key->ht, entry);
	pthread_mutex_unlock(&coa_key->mutex);
}

/*
 *	Find an active listener by key.
 *
 *	This function will update request->home_server, and
 *	request->proxy_listener.
 */
int listen_coa_find(REQUEST *request, char const *key)
{
	coa_key_t my_key, *coa_key;
	rad_listen_t *this, *found;
	listen_socket_t *sock;
	fr_hash_iter_t iter;

	/*
	 *	Find the key.  If we can't find it, then error out.
	 */
	memcpy(&my_key.key, &key, sizeof(key)); /* const issues */
	coa_key = rbtree_finddata(coa_tree, &my_key);
	if (!coa_key) return -1;

	/*
	 *	We've found it.  Now find a listener which has free
	 *	IDs.  i.e. where the number of used IDs is less tahn
	 *	256.
	 */
	found = NULL;
	pthread_mutex_lock(&coa_key->mutex);
	for (this = fr_hash_table_iter_init(coa_key->ht, &iter);
	     this != NULL;
	     this = fr_hash_table_iter_next(coa_key->ht, &iter)) {
		if (this->blocked) continue;

		if (this->dead) continue;

		if (!found) {
			if (this->num_ids_used < 256) {
				found = this;
			}

			/*
			 *	Skip listeners which have all used IDs.
			 */
			continue;
		}

		/*
		 *	Try to spread the load across all available
		 *	sockets.
		 */
		if (found->num_ids_used > this->num_ids_used) {
			found = this;
			continue;
		}

		/*
		 *	If they are equal, pick one at random.
		 *
		 *	@todo - pick one with equal probability from
		 *	among the ones with the same IDs used.  This
		 *	algorithm prefers the first one.
		 */
		if (found->num_ids_used == this->num_ids_used) {
			if ((fr_rand() & 0x01) == 0) {
				found = this;
				continue;
			}
		}
	}

	pthread_mutex_unlock(&coa_key->mutex);
	if (!found) return -1;

	request->proxy_listener = found;

	sock = found->data;
	request->home_server = sock->home;
	return 0;
}

/*
 *	Check for an active listener by key.
 */
static bool listen_coa_exists(rad_listen_t *this, char const *key)
{
	coa_key_t my_key, *coa_key;
	coa_entry_t my_entry, *entry;

	/*
	 *	Find the key.  If we can't find it, then error out.
	 */
	memcpy(&my_key.key, &key, sizeof(key)); /* const issues */
	coa_key = rbtree_finddata(coa_tree, &my_key);
	if (!coa_key) return false;

	my_entry.listener = this;
	pthread_mutex_lock(&coa_key->mutex);
	entry = fr_hash_table_finddata(coa_key->ht, &my_entry);
	pthread_mutex_unlock(&coa_key->mutex);

	return (entry != NULL);
}

/*
 *	Delete a listener entry.
 */
static void listen_coa_delete(rad_listen_t *this, char const *key)
{
	coa_key_t my_key, *coa_key;
	coa_entry_t my_entry;

	/*
	 *	Find the key.  If we can't find it, then error out.
	 */
	memcpy(&my_key.key, &key, sizeof(key)); /* const issues */
	coa_key = rbtree_finddata(coa_tree, &my_key);
	if (!coa_key) return;

	my_entry.listener = this;
	pthread_mutex_lock(&coa_key->mutex);
	(void) fr_hash_table_delete(coa_key->ht, &my_entry);
	pthread_mutex_unlock(&coa_key->mutex);
}


static void listener_coa_update(rad_listen_t *this, VALUE_PAIR *vps)
{
	VALUE_PAIR *vp;
	vp_cursor_t cursor;

	fr_cursor_init(&cursor, &vps);

	/*
	 *	Add or delete Operator-Name realms
	 */
	while ((vp = fr_cursor_next_by_num(&cursor, PW_OPERATOR_NAME, 0, TAG_ANY)) != NULL) {
		if (vp->vp_length <= 1) continue;

		if (vp->vp_strvalue[0] == '+') {
			if (listen_coa_exists(this, vp->vp_strvalue)) continue;

			listen_coa_add(this, vp->vp_strvalue);
			continue;
		}

		if (vp->vp_strvalue[0] == '-') {
			listen_coa_delete(this, vp->vp_strvalue);
			continue;
		}
	}
}
#endif
