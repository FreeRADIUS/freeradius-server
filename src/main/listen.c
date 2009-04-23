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
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

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
	if (client->dynamic && (src_port != 0)) {
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
		 *	This really puts them onto a queue for later
		 *	deletion.
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


int listen_socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	size_t len;
	listen_socket_t *sock = this->data;

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len
#define ADDSTRING(_x) strlcpy(buffer, _x, bufsize);FORWARD

	ADDSTRING(this->frs->name);

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
int listen_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
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
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
	int rcode;
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

		fr_suid_up();
		rcode = setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
				   (char *)&ifreq, sizeof(ifreq));
		fr_suid_down();
		if (rcode < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed binding to interface %s: %s",
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

	/*
	 *	May be binding to priviledged ports.
	 */
	fr_suid_up();
	rcode = bind(this->fd, (struct sockaddr *) &salocal, salen);
	fr_suid_down();
	if (rcode < 0) {
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

#define MAX_HANDLES (32)
static int frs_init = 0;
static lt_dlhandle frs_modules[MAX_HANDLES];


/*
 *	Allocate & initialize a new listener.
 */
rad_listen_t *listen_alloc(const char *type_name)
{
	int i;
	rad_listen_t *this;
	const frs_module_t *frs;
	char buffer[256];

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	snprintf(buffer, sizeof(buffer), "frs_%s", type_name);

	if (!frs_init) {
		memset(frs_modules, 0, sizeof(frs_modules));
		frs_init = TRUE;
	}

	frs = NULL;
	for (i = 0; i < MAX_HANDLES; i++) {
		if (!frs_modules[i]) continue;

		frs = lt_dlsym(frs_modules[i], buffer);
		if (frs) break;
	}
	
	if (!frs) {
		lt_dlhandle handle;

		handle = lt_dlopenext(buffer);
		if (!handle) {
			radlog(L_ERR, "Failed opening %s: %s",
			       buffer, lt_dlerror());
			return NULL;
		}
		
		frs = lt_dlsym(handle, buffer);
		if (!frs) {
			lt_dlclose(handle);
			radlog(L_ERR, "Failed linking to %s: %s",
			       buffer, lt_dlerror());
			return NULL;
		}
	
		if (frs->magic != FRS_MODULE_MAGIC_NUMBER) {
			lt_dlclose(handle);
			radlog(L_ERR, "Invalid version in %s\n",
			       buffer);
			return NULL;
		}

		for (i = 0; i < MAX_HANDLES; i++) {
			if (!frs_modules[i]) {
				frs_modules[i] = handle;
				break;
			}
		} /* if we run out, we leak the handle.  Too bad. */
	}

	this->type = frs->type;
	this->frs = frs;
	this->recv = frs->recv;
	this->send = frs->send;
	this->print = frs->print;
	this->encode = frs->encode;
	this->decode = frs->decode;

	switch (this->type) {
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
	/*
	 *	The data here is allocate in the "parse" section.
	 */
	case RAD_LISTEN_COMMAND:
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

	this = listen_alloc("proxy");
	if (!this) return NULL;

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


static rad_listen_t *listen_parse(CONF_SECTION *cs, const char *server)
{
	int		rcode;
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
		if (rcode < 0) {
			free(listen_type);
			return NULL;
		}
	}

	/*
	 *	Set up cross-type data.
	 */
	this = listen_alloc(listen_type);
	if (!this) return NULL;

	free(listen_type);
	this->server = server;
	this->fd = -1;

	/*
	 *	Call per-type parser.
	 */
	if (this->frs->parse(cs, this) < 0) {
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
			this = listen_alloc("vmps");
			if (!this) return 0;	/* FIXME: memleak? */
			if (!auth_port) auth_port = 1589;
		} else
#endif
		{
			this = listen_alloc("auth");
			if (!this) return 0;	/* FIXME: memleak? */
		}

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
		this = listen_alloc("acct");
		if (!this) return 0;	/* FIXME: memleak? */
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
#ifdef WITH_VMPS
			if (this->type == RAD_LISTEN_VQP) {
				sock = this->data;
				if (server_ipaddr.af == AF_UNSPEC) {
					server_ipaddr = sock->ipaddr;
				}
				port = sock->port + 1;
				break;
			}
#endif
		}

		if (port < 0) port = 1024 + (fr_rand() & 0x1ff);

		/*
		 *	Address is still unspecified, use IPv4.
		 */
		if (server_ipaddr.af == AF_UNSPEC) {
			server_ipaddr.af = AF_INET;
			server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_ANY);
		}

		this = listen_alloc("proxy");
		if (!this) return 0;	/* FIXME: memleak? */
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

		if (this->frs->free) {
			this->frs->free(this);
		}
		free(this->data);
		free(this);

		this = next;
	}

	*head = NULL;

	/*
	 *	FIXME: Unlink the handles, too.
	 */
}

rad_listen_t *listener_find_byipaddr(const fr_ipaddr_t *ipaddr, int port)
{
	rad_listen_t *this;

	for (this = mainconfig.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		/*
		 *	FIXME: For TCP, ignore the *secondary*
		 *	listeners associated with the main socket.
		 */
		if ((this->type != RAD_LISTEN_AUTH) &&
		    (this->type != RAD_LISTEN_ACCT)) continue;
		
		sock = this->data;

		if ((sock->port == port) &&
		    (fr_ipaddr_cmp(ipaddr, &sock->ipaddr) == 0)) {
			return this;
		}

		if ((sock->port == port) &&
		    ((sock->ipaddr.af == AF_INET) &&
		     (sock->ipaddr.ipaddr.ip4addr.s_addr == INADDR_ANY))) {
			return this;
		}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
		if ((sock->port == port) &&
		    (sock->ipaddr.af == AF_INET6) &&
		    (IN6_IS_ADDR_UNSPECIFIED(&sock->ipaddr.ipaddr.ip6addr))) {
			return this;
		}
#endif
	}

	return NULL;
}
