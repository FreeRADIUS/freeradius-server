/*
 * client.c	Read clients into memory.
 *
 * Version:     $Id$
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
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>

#ifdef WITH_DYNAMIC_CLIENTS
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#endif

struct radclient_list {
	/*
	 *	FIXME: One set of trees for IPv4, and another for IPv6?
	 */
	rbtree_t	*trees[129]; /* for 0..128, inclusive. */
	uint32_t       	min_prefix;
};


#ifdef WITH_STATS
static rbtree_t		*tree_num = NULL;     /* client numbers 0..N */
static int		tree_num_max = 0;
#endif
static RADCLIENT_LIST	*root_clients = NULL;

#ifdef WITH_DYNAMIC_CLIENTS
static fr_fifo_t	*deleted_clients = NULL;
#endif

/*
 *	Callback for freeing a client.
 */
void client_free(RADCLIENT *client)
{
	if (!client) return;

#ifdef WITH_DYNAMIC_CLIENTS
	if (client->dynamic == 2) {
		time_t now;

		if (!deleted_clients) {
			deleted_clients = fr_fifo_create(1024,
							 (void *) client_free);
			if (!deleted_clients) return; /* MEMLEAK */
		}

		/*
		 *	Mark it as in the fifo, and remember when we
		 *	pushed it.
		 */
		client->dynamic = 3;
		client->created = now = time(NULL); /* re-set it */
		fr_fifo_push(deleted_clients, client);

		/*
		 *	Peek at the head of the fifo.  If it might
		 *	still be in use, return.  Otherwise, pop it
		 *	from the queue and delete it.
		 */
		client = fr_fifo_peek(deleted_clients);
		if ((client->created + 120) >= now) return;

		client = fr_fifo_pop(deleted_clients);
		rad_assert(client != NULL);
	}
#endif

	talloc_free(client);
}

/*
 *	Callback for comparing two clients.
 */
static int client_ipaddr_cmp(void const *one, void const *two)
{
	RADCLIENT const *a = one;
	RADCLIENT const *b = two;
#ifndef WITH_TCP

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
#else
	int rcode;

	rcode = fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
	if (rcode != 0) return rcode;

	/*
	 *	Wildcard match
	 */
	if ((a->proto == IPPROTO_IP) ||
	    (b->proto == IPPROTO_IP)) return 0;

	return (a->proto - b->proto);
#endif
}

#ifdef WITH_STATS
static int client_num_cmp(void const *one, void const *two)
{
	RADCLIENT const *a = one;
	RADCLIENT const *b = two;

	return (a->number - b->number);
}
#endif

/*
 *	Free a RADCLIENT list.
 */
void clients_free(RADCLIENT_LIST *clients)
{
	int i;

	if (!clients) clients = root_clients;
	if (!clients) return;	/* Clients may not have been initialised yet */

	for (i = 0; i <= 128; i++) {
		if (clients->trees[i]) rbtree_free(clients->trees[i]);
		clients->trees[i] = NULL;
	}

	if (clients == root_clients) {
#ifdef WITH_STATS
		if (tree_num) rbtree_free(tree_num);
		tree_num = NULL;
		tree_num_max = 0;
#endif
		root_clients = NULL;
	}

#ifdef WITH_DYNAMIC_CLIENTS
	/*
	 *	FIXME: No fr_fifo_delete()
	 */
#endif

	talloc_free(clients);
}

/*
 *	Return a new, initialized, set of clients.
 */
RADCLIENT_LIST *clients_init(CONF_SECTION *cs)
{
	RADCLIENT_LIST *clients = talloc_zero(cs, RADCLIENT_LIST);

	if (!clients) return NULL;

	clients->min_prefix = 128;

	return clients;
}

/*
 *	Add a client to the tree.
 */
int client_add(RADCLIENT_LIST *clients, RADCLIENT *client)
{
	RADCLIENT *old;
	char buffer[INET6_ADDRSTRLEN + 3];

	if (!client) {
		return 0;
	}

	/*
	 *	Hack to fixup wildcard clients
	 */
	if (is_wildcard(&client->ipaddr)) client->ipaddr.prefix = 0;

	fr_ntop(buffer, sizeof(buffer), &client->ipaddr);
	DEBUG3("Adding client %s (%s) to prefix tree %i", buffer, client->longname, client->ipaddr.prefix);

	/*
	 *	If "clients" is NULL, it means add to the global list,
	 *	unless we're trying to add it to a virtual server...
	 */
	if (!clients) {
		if (client->server != NULL) {
			CONF_SECTION *cs;

			cs = cf_section_sub_find_name2(main_config.config,
						   "server", client->server);
			if (!cs) {
				radlog(L_ERR, "Failed to find virtual server %s",
				       client->server);
				return 0;
			}

			/*
			 *	If the client list already exists, use that.
			 *	Otherwise, create a new client list.
			 */
			clients = cf_data_find(cs, "clients");
			if (!clients) {
				clients = clients_init(cs);
				if (!clients) {
					radlog(L_ERR, "Out of memory");
					return 0;
				}

				if (cf_data_add(cs, "clients", clients, (void *) clients_free) < 0) {
					radlog(L_ERR, "Failed to associate clients with virtual server %s",
					       client->server);
					clients_free(clients);
					return 0;
				}
			}

		} else {
			/*
			 *	Initialize the global list, if not done already.
			 */
			if (!root_clients) {
				root_clients = clients_init(NULL);
				if (!root_clients) return 0;
			}
			clients = root_clients;
		}
	}

	/*
	 *	Create a tree for it.
	 */
	if (!clients->trees[client->ipaddr.prefix]) {
		clients->trees[client->ipaddr.prefix] = rbtree_create(clients, client_ipaddr_cmp, NULL, 0);
		if (!clients->trees[client->ipaddr.prefix]) {
			return 0;
		}
	}

#define namecmp(a) ((!old->a && !client->a) || (old->a && client->a && (strcmp(old->a, client->a) == 0)))

	/*
	 *	Cannot insert the same client twice.
	 */
	old = rbtree_finddata(clients->trees[client->ipaddr.prefix], client);
	if (old) {
		/*
		 *	If it's a complete duplicate, then free the new
		 *	one, and return "OK".
		 */
		if ((fr_ipaddr_cmp(&old->ipaddr, &client->ipaddr) == 0) &&
		    (old->ipaddr.prefix == client->ipaddr.prefix) &&
		    namecmp(longname) && namecmp(secret) &&
		    namecmp(shortname) && namecmp(nas_type) &&
		    namecmp(login) && namecmp(password) && namecmp(server) &&
#ifdef WITH_DYNAMIC_CLIENTS
		    (old->lifetime == client->lifetime) &&
		    namecmp(client_server) &&
#endif
#ifdef WITH_COA
		    namecmp(coa_name) &&
		    (old->coa_server == client->coa_server) &&
		    (old->coa_pool == client->coa_pool) &&
#endif
		    (old->message_authenticator == client->message_authenticator)) {
			WARN("Ignoring duplicate client %s", client->longname);
			client_free(client);
			return 1;
		}

		ERROR("Failed to add duplicate client %s",
		       client->shortname);
		return 0;
	}
#undef namecmp

	/*
	 *	Other error adding client: likely is fatal.
	 */
	if (!rbtree_insert(clients->trees[client->ipaddr.prefix], client)) {
		return 0;
	}

#ifdef WITH_STATS
	if (!tree_num) {
		tree_num = rbtree_create(clients, client_num_cmp, NULL, 0);
	}

#ifdef WITH_DYNAMIC_CLIENTS
	/*
	 *	More catching of clients added by rlm_sql.
	 *
	 *	The sql modules sets the dynamic flag BEFORE calling
	 *	us.  The client_from_request() function sets it AFTER
	 *	calling us.
	 */
	if (client->dynamic && (client->lifetime == 0)) {
		RADCLIENT *network;

		/*
		 *	If there IS an enclosing network,
		 *	inherit the lifetime from it.
		 */
		network = client_find(clients, &client->ipaddr, client->proto);
		if (network) {
			client->lifetime = network->lifetime;
		}
	}
#endif

	client->number = tree_num_max;
	tree_num_max++;
	if (tree_num) rbtree_insert(tree_num, client);
#endif

	if (client->ipaddr.prefix < clients->min_prefix) {
		clients->min_prefix = client->ipaddr.prefix;
	}

	(void) talloc_steal(clients, client); /* reparent it */

	return 1;
}


#ifdef WITH_DYNAMIC_CLIENTS
void client_delete(RADCLIENT_LIST *clients, RADCLIENT *client)
{
	if (!client) return;

	if (!clients) clients = root_clients;

	if (!client->dynamic) return;

	rad_assert(client->ipaddr.prefix <= 128);

	client->dynamic = 2;	/* signal to client_free */

#ifdef WITH_STATS
	rbtree_deletebydata(tree_num, client);
#endif
	rbtree_deletebydata(clients->trees[client->ipaddr.prefix], client);
}
#endif

#ifdef WITH_STATS
/*
 *	Find a client in the RADCLIENTS list by number.
 *	This is a support function for the statistics code.
 */
RADCLIENT *client_findbynumber(RADCLIENT_LIST const *clients, int number)
{
	if (!clients) clients = root_clients;

	if (!clients) return NULL;

	if (number >= tree_num_max) return NULL;

	if (tree_num) {
		RADCLIENT myclient;

		myclient.number = number;

		return rbtree_finddata(tree_num, &myclient);
	}

	return NULL;
}
#else
RADCLIENT *client_findbynumber(UNUSED const RADCLIENT_LIST *clients, UNUSED int number)
{
	return NULL;
}
#endif


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr, int proto)
{
  int32_t i, max_prefix;
	RADCLIENT myclient;

	if (!clients) clients = root_clients;

	if (!clients || !ipaddr) return NULL;

	switch (ipaddr->af) {
	case AF_INET:
		max_prefix = 32;
		break;

	case AF_INET6:
		max_prefix = 128;
		break;

	default :
		return NULL;
	}

	for (i = max_prefix; i >= (int32_t) clients->min_prefix; i--) {
		void *data;

		myclient.ipaddr = *ipaddr;
		myclient.proto = proto;
		fr_ipaddr_mask(&myclient.ipaddr, i);

		if (!clients->trees[i]) continue;

		data = rbtree_finddata(clients->trees[i], &myclient);
		if (data) return data;
	}

	return NULL;
}

/*
 *	Old wrapper for client_find
 */
RADCLIENT *client_find_old(fr_ipaddr_t const *ipaddr)
{
	return client_find(root_clients, ipaddr, IPPROTO_UDP);
}

static fr_ipaddr_t cl_ipaddr;
static char const *cl_srcipaddr = NULL;
static uint32_t cl_prefix;
#ifdef WITH_TCP
static char const *hs_proto = NULL;
#endif

#ifdef WITH_TCP
static CONF_PARSER limit_config[] = {
	{ "max_connections", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.max_connections),   "16" },

	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.lifetime),   "0" },

	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.idle_timeout), "30" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};
#endif

static const CONF_PARSER client_config[] = {
	{ "ipaddr", FR_CONF_POINTER(PW_TYPE_IP_PREFIX, &cl_ipaddr), NULL },
	{ "ipv4addr", FR_CONF_POINTER(PW_TYPE_IPV4_PREFIX, &cl_ipaddr), NULL },
	{ "ipv6addr", FR_CONF_POINTER(PW_TYPE_IPV6_PREFIX, &cl_ipaddr), NULL },
	{ "netmask", FR_CONF_POINTER(PW_TYPE_INTEGER, &cl_prefix), NULL },

	{ "src_ipaddr", FR_CONF_POINTER(PW_TYPE_STRING, &cl_srcipaddr), NULL },

	{ "require_message_authenticator",  FR_CONF_OFFSET(PW_TYPE_BOOLEAN, RADCLIENT, message_authenticator), "no" },

	{ "secret", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, RADCLIENT, secret), NULL },
	{ "shortname", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, shortname), NULL },
	{ "nastype", FR_CONF_OFFSET(PW_TYPE_DEPRECATED | PW_TYPE_STRING, RADCLIENT, nas_type), NULL },
	{ "nas_type", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, nas_type), NULL },
	{ "login", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, login), NULL },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, password), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, server), NULL },
	{ "response_window", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, RADCLIENT, response_window), NULL },

#ifdef WITH_TCP
	{ "proto", FR_CONF_POINTER(PW_TYPE_STRING, &hs_proto), NULL },
	{ "limit", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) limit_config },
#endif

#ifdef WITH_DYNAMIC_CLIENTS
	{ "dynamic_clients", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, client_server), NULL },
	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, lifetime), NULL },
	{ "rate_limit", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, RADCLIENT, rate_limit), NULL },
#endif

#ifdef WITH_COA
	{ "coa_server", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, coa_name), NULL },
#endif

	{ NULL, -1, 0, NULL, NULL }
};


static RADCLIENT *client_parse(CONF_SECTION *cs, int in_server)
{
	RADCLIENT	*c;
	char const	*name2;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs, "Missing client name");
		return NULL;
	}

	/*
	 *	The size is fine.. Let's create the buffer
	 */
	c = talloc_zero(cs, RADCLIENT);
	c->cs = cs;

	memset(&cl_ipaddr, 0, sizeof(cl_ipaddr));
	cl_prefix = 256;
	if (cf_section_parse(cs, c, client_config) < 0) {
		cf_log_err_cs(cs, "Error parsing client section");
	error:
		client_free(c);
#ifdef WITH_TCP
		hs_proto = NULL;
		cl_srcipaddr = NULL;
#endif

		return NULL;
	}

	/*
	 *	Global clients can set servers to use, per-server clients cannot.
	 */
	if (in_server && c->server) {
		cf_log_err_cs(cs, "Clients inside of an server section cannot point to a server");
		goto error;
	}

	/*
	 *	Newer style client definitions with either ipaddr or ipaddr6
	 *	config items.
	 */
	if (cf_pair_find(cs, "ipaddr") || cf_pair_find(cs, "ipv4addr") || cf_pair_find(cs, "ipv6addr")) {
		char buffer[128];

		/*
		 *	Sets ipv4/ipv6 address and prefix.
		 */
		c->ipaddr = cl_ipaddr;

		/*
		 *	Set the long name to be the result of a reverse lookup on the IP address.
		 */
		ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
		c->longname = talloc_typed_strdup(c, buffer);

		/*
		 *	Set the short name to the name2.
		 */
		if (!c->shortname) c->shortname = talloc_typed_strdup(c, name2);
	/*
	 *	No "ipaddr" or "ipv6addr", use old-style "client <ipaddr> {" syntax.
	 */
	} else {
		WARN("No 'ipaddr' or 'ipv4addr' or 'ipv6addr' field found in client %s.  Please fix your configuration",
		     name2);
		WARN("Support for old-style clients will be removed in a future release");

#ifdef WITH_TCP
		if (cf_pair_find(cs, "proto") != NULL) {
			cf_log_err_cs(cs, "Cannot use 'proto' inside of old-style client definition");
			goto error;
		}
#endif
		if (fr_pton(&c->ipaddr, name2, 0, true) < 0) {
			cf_log_err_cs(cs, "Failed parsing client name \"%s\" as ip address or hostname: %s", name2,
				      fr_strerror());
			goto error;
		}

		c->longname = talloc_typed_strdup(c, name2);
		if (!c->shortname) c->shortname = talloc_typed_strdup(c, c->longname);
	}

	/*
	 *	Prefix override (this needs to die)
	 */
	if (cl_prefix != 256) {
		WARN("'netmask' field found in client %s is deprecated, use CIDR notation instead.  "
		     "Please fix your configuration", name2);
		WARN("Support for 'netmask' will be removed in a future release");

		switch (c->ipaddr.af) {
		case AF_INET:
			if (cl_prefix > 32) {
				cf_log_err_cs(cs, "Invalid IPv4 mask length \"%i\".  Should be between 0-32",
					      cl_prefix);
				goto error;
			}
			break;

		case AF_INET6:
			if (cl_prefix > 128) {
				cf_log_err_cs(cs, "Invalid IPv6 mask length \"%i\".  Should be between 0-128",
					      cl_prefix);
				goto error;
			}
			break;

		default:
			rad_assert(0);
		}
		fr_ipaddr_mask(&c->ipaddr, cl_prefix);
	}

	c->proto = IPPROTO_UDP;
	if (hs_proto) {
		if (strcmp(hs_proto, "udp") == 0) {
			hs_proto = NULL;

#ifdef WITH_TCP
		} else if (strcmp(hs_proto, "tcp") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_TCP;
#  ifdef WITH_TLS
		} else if (strcmp(hs_proto, "tls") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_TCP;
			c->tls_required = true;

		} else if (strcmp(hs_proto, "radsec") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_TCP;
			c->tls_required = true;
#  endif
		} else if (strcmp(hs_proto, "*") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_IP; /* fake for dual */
#endif
		} else {
			cf_log_err_cs(cs, "Unknown proto \"%s\".", hs_proto);
			goto error;
		}
	}

	/*
	 *	If a src_ipaddr is specified, when we send the return packet
	 *	we will use this address instead of the src from the
	 *	request.
	 */
	if (cl_srcipaddr) {
#ifdef WITH_UDPFROMTO
		switch (c->ipaddr.af) {
		case AF_INET:
			if (fr_pton4(&c->src_ipaddr, cl_srcipaddr, 0, true, false) < 0) {
				cf_log_err_cs(cs, "Failed parsing src_ipaddr: %s", fr_strerror());
				goto error;
			}
			break;

		case AF_INET6:
			if (fr_pton6(&c->src_ipaddr, cl_srcipaddr, 0, true, false) < 0) {
				cf_log_err_cs(cs, "Failed parsing src_ipaddr: %s", fr_strerror());
				goto error;
			}
			break;
		default:
			rad_assert(0);
		}
#else
		WARN("Server not built with udpfromto, ignoring client src_ipaddr");
#endif
		cl_srcipaddr = NULL;
	}

	/*
	 *	A response_window of zero is OK, and means that it's
	 *	ignored by the rest of the server timers.
	 */
	if (timerisset(&c->response_window)) {
		FR_TIMEVAL_BOUND_CHECK("response_window", &c->response_window, >=, 0, 1000);
		FR_TIMEVAL_BOUND_CHECK("response_window", &c->response_window, <=, 60, 0);
		FR_TIMEVAL_BOUND_CHECK("response_window", &c->response_window, <=, main_config.max_request_time, 0);
	}

#ifdef WITH_DYNAMIC_CLIENTS
	if (c->client_server) {
		c->secret = talloc_typed_strdup(c, "testing123");

		if (((c->ipaddr.af == AF_INET) && (c->ipaddr.prefix == 32)) ||
		    ((c->ipaddr.af == AF_INET6) && (c->ipaddr.prefix == 128))) {
			cf_log_err_cs(cs, "Dynamic clients MUST be a network, not a single IP address");
			goto error;
		}

		return c;
	}
#endif

	if (!c->secret || (c->secret[0] == '\0')) {
#ifdef WITH_DHCP
		char const *value = NULL;
		CONF_PAIR *cp = cf_pair_find(cs, "dhcp");

		if (cp) value = cf_pair_value(cp);

		/*
		 *	Secrets aren't needed for DHCP.
		 */
		if (value && (strcmp(value, "yes") == 0)) return c;
#endif

#ifdef WITH_TLS
		/*
		 *	If the client is TLS only, the secret can be
		 *	omitted.  When omitted, it's hard-coded to
		 *	"radsec".  See RFC 6614.
		 */
		if (c->tls_required) {
			c->secret = talloc_typed_strdup(cs, "radsec");
		} else
#endif

		{
			cf_log_err_cs(cs,
				      "secret must be at least 1 character long");
			goto error;
		}
	}

#ifdef WITH_COA
	/*
	 *	Point the client to the home server pool, OR to the
	 *	home server.  This gets around the problem of figuring
	 *	out which port to use.
	 */
	if (c->coa_name) {
		c->coa_pool = home_pool_byname(c->coa_name, HOME_TYPE_COA);
		if (!c->coa_pool) {
			c->coa_server = home_server_byname(c->coa_name,
							   HOME_TYPE_COA);
		}
		if (!c->coa_pool && !c->coa_server) {
			cf_log_err_cs(cs, "No such home_server or home_server_pool \"%s\"", c->coa_name);
			goto error;
		}
	}
#endif

#ifdef WITH_TCP
	if ((c->proto == IPPROTO_TCP) || (c->proto == IPPROTO_IP)) {
		if ((c->limit.idle_timeout > 0) && (c->limit.idle_timeout < 5))
			c->limit.idle_timeout = 5;
		if ((c->limit.lifetime > 0) && (c->limit.lifetime < 5))
			c->limit.lifetime = 5;
		if ((c->limit.lifetime > 0) && (c->limit.idle_timeout > c->limit.lifetime))
			c->limit.idle_timeout = 0;
	}
#endif

	return c;
}


/*
 *	Create the linked list of clients from the new configuration
 *	type.  This way we don't have to change too much in the other
 *	source-files.
 */
#ifdef WITH_TLS
RADCLIENT_LIST *clients_parse_section(CONF_SECTION *section, bool tls_required)
#else
RADCLIENT_LIST *clients_parse_section(CONF_SECTION *section, UNUSED bool tls_required)
#endif
{
	bool		global = false, in_server = false;
	CONF_SECTION	*cs;
	RADCLIENT	*c;
	RADCLIENT_LIST	*clients;

	/*
	 *	Be forgiving.  If there's already a clients, return
	 *	it.  Otherwise create a new one.
	 */
	clients = cf_data_find(section, "clients");
	if (clients) return clients;

	clients = clients_init(section);
	if (!clients) return NULL;

	if (cf_top_section(section) == section) global = true;

	if (strcmp("server", cf_section_name1(section)) == 0) in_server = true;

	/*
	 *	Associate the clients structure with the section.
	 */
	if (cf_data_add(section, "clients", clients, NULL) < 0) {
		cf_log_err_cs(section,
			   "Failed to associate clients with section %s",
		       cf_section_name1(section));
		clients_free(clients);
		return NULL;
	}

	for (cs = cf_subsection_find_next(section, NULL, "client");
	     cs != NULL;
	     cs = cf_subsection_find_next(section, cs, "client")) {
		c = client_parse(cs, in_server);
		if (!c) {
			return NULL;
		}

#ifdef WITH_TLS
		/*
		 *	TLS clients CANNOT use non-TLS listeners.
		 *	non-TLS clients CANNOT use TLS listeners.
		 */
		if (tls_required != c->tls_required) {
			cf_log_err_cs(cs, "Client does not have the same TLS configuration as the listener");
			client_free(c);
			clients_free(clients);
			return NULL;
		}
#endif

		/*
		 *	FIXME: Add the client as data via cf_data_add,
		 *	for migration issues.
		 */

#ifdef WITH_DYNAMIC_CLIENTS
#ifdef HAVE_DIRENT_H
		if (c->client_server) {
			char const *value;
			CONF_PAIR *cp;
			DIR		*dir;
			struct dirent	*dp;
			struct stat stat_buf;
			char buf2[2048];

			/*
			 *	Find the directory where individual
			 *	client definitions are stored.
			 */
			cp = cf_pair_find(cs, "directory");
			if (!cp) goto add_client;

			value = cf_pair_value(cp);
			if (!value) {
				cf_log_err_cs(cs,
					   "The \"directory\" entry must not be empty");
				client_free(c);
				return NULL;
			}

			DEBUG("including dynamic clients in %s", value);

			dir = opendir(value);
			if (!dir) {
				cf_log_err_cs(cs, "Error reading directory %s: %s", value, fr_syserror(errno));
				client_free(c);
				return NULL;
			}

			/*
			 *	Read the directory, ignoring "." files.
			 */
			while ((dp = readdir(dir)) != NULL) {
				char const *p;
				RADCLIENT *dc;

				if (dp->d_name[0] == '.') continue;

				/*
				 *	Check for valid characters
				 */
				for (p = dp->d_name; *p != '\0'; p++) {
					if (isalpha((int)*p) ||
					    isdigit((int)*p) ||
					    (*p == ':') ||
					    (*p == '.')) continue;
						break;
				}
				if (*p != '\0') continue;

				snprintf(buf2, sizeof(buf2), "%s/%s",
					 value, dp->d_name);

				if ((stat(buf2, &stat_buf) != 0) ||
				    S_ISDIR(stat_buf.st_mode)) continue;

				dc = client_read(buf2, in_server, true);
				if (!dc) {
					cf_log_err_cs(cs,
						   "Failed reading client file \"%s\"", buf2);
					client_free(c);
					closedir(dir);
					return NULL;
				}

				/*
				 *	Validate, and add to the list.
				 */
				if (!client_validate(clients, c, dc)) {

					client_free(c);
					closedir(dir);
					return NULL;
				}
			} /* loop over the directory */
			closedir(dir);
		}
#endif /* HAVE_DIRENT_H */

	add_client:
#endif /* WITH_DYNAMIC_CLIENTS */
		if (!client_add(clients, c)) {
			cf_log_err_cs(cs,
				   "Failed to add client %s",
				   cf_section_name2(cs));
			client_free(c);
			return NULL;
		}

	}

	/*
	 *	Replace the global list of clients with the new one.
	 *	The old one is still referenced from the original
	 *	configuration, and will be freed when that is freed.
	 */
	if (global) {
		root_clients = clients;
	}

	return clients;
}

#ifdef WITH_DYNAMIC_CLIENTS
/*
 *	We overload this structure a lot.
 */
static const CONF_PARSER dynamic_config[] = {
	{ "FreeRADIUS-Client-IP-Address", FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, RADCLIENT, ipaddr), NULL },
	{ "FreeRADIUS-Client-IPv6-Address", FR_CONF_OFFSET(PW_TYPE_IPV6_ADDR, RADCLIENT, ipaddr), NULL },
	{ "FreeRADIUS-Client-IP-Prefix", FR_CONF_OFFSET(PW_TYPE_IPV4_PREFIX, RADCLIENT, ipaddr), NULL },
	{ "FreeRADIUS-Client-IPv6-Prefix", FR_CONF_OFFSET(PW_TYPE_IPV6_PREFIX, RADCLIENT, ipaddr), NULL },
	{ "FreeRADIUS-Client-Src-IP-Address", FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, RADCLIENT, src_ipaddr), NULL },
	{ "FreeRADIUS-Client-Src-IPv6-Address", FR_CONF_OFFSET(PW_TYPE_IPV6_ADDR, RADCLIENT, src_ipaddr), NULL },

	{ "FreeRADIUS-Client-Require-MA", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, RADCLIENT, message_authenticator), NULL },

	{ "FreeRADIUS-Client-Secret",  FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, secret), "" },
	{ "FreeRADIUS-Client-Shortname",  FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, shortname), "" },
	{ "FreeRADIUS-Client-NAS-Type",  FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, nas_type), NULL },
	{ "FreeRADIUS-Client-Virtual-Server",  FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, server), NULL },

	{ NULL, -1, 0, NULL, NULL }
};


bool client_validate(RADCLIENT_LIST *clients, RADCLIENT *master, RADCLIENT *c)
{
	char buffer[128];

	/*
	 *	No virtual server defined.  Inherit the parent's
	 *	definition.
	 */
	if (master->server && !c->server) {
		c->server = talloc_typed_strdup(c, master->server);
	}

	/*
	 *	If the client network isn't global (not tied to a
	 *	virtual server), then ensure that this clients server
	 *	is the same as the enclosing networks virtual server.
	 */
	if (master->server &&
	     (strcmp(master->server, c->server) != 0)) {
		DEBUG("- Cannot add client %s: Virtual server %s is not the same as the virtual server for the network",
		      ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)), c->server);

		goto error;
	}

	if (!client_add(clients, c)) {
		DEBUG("- Cannot add client %s: Internal error", ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)));

		goto error;
	}

	/*
	 *	Initialize the remaining fields.
	 */
	c->dynamic = true;
	c->lifetime = master->lifetime;
	c->created = time(NULL);
	c->longname = talloc_typed_strdup(c, c->shortname);

	DEBUG("- Added client %s with shared secret %s",
	      ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)),
	      c->secret);

	return true;

error:
	client_free(c);
	return false;
}

/** Add a client from a result set (LDAP, SQL, et al)
 *
 * @param ctx Talloc context.
 * @param identifier Client IP Address / IPv4 subnet / IPv6 subnet / FQDN.
 * @param secret Client secret.
 * @param shortname Client friendly name.
 * @param type NAS-Type.
 * @param server Virtual-Server to associate clients with.
 * @param require_ma If true all packets from client must include a message-authenticator.
 * @return The new client, or NULL on error.
 */
RADCLIENT *client_from_query(TALLOC_CTX *ctx, char const *identifier, char const *secret, char const *shortname,
			     char const *type, char const *server, bool require_ma)
{
	RADCLIENT *c;
	char buffer[128];

	rad_assert(identifier);
	rad_assert(secret);

	c = talloc_zero(ctx, RADCLIENT);

	if (fr_pton(&c->ipaddr, identifier, 0, true) < 0) {
		ERROR("%s", fr_strerror());
		talloc_free(c);

		return NULL;
	}

#ifdef WITH_DYNAMIC_CLIENTS
	c->dynamic = true;
#endif
	ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
	c->longname = talloc_typed_strdup(c, buffer);

	/*
	 *	Other values (secret, shortname, nas_type, virtual_server)
	 */
	c->secret = talloc_typed_strdup(c, secret);
	if (shortname) c->shortname = talloc_typed_strdup(c, shortname);
	if (type) c->nas_type = talloc_typed_strdup(c, type);
	if (server) c->server = talloc_typed_strdup(c, server);
	c->message_authenticator = require_ma;

	return c;
}

RADCLIENT *client_from_request(RADCLIENT_LIST *clients, REQUEST *request)
{
	int i, *pi;
	char **p;
	RADCLIENT *c;
	char buffer[128];

	if (!clients || !request) return NULL;

	c = talloc_zero(clients, RADCLIENT);
	c->cs = request->client->cs;
	c->ipaddr.af = AF_UNSPEC;
	c->src_ipaddr.af = AF_UNSPEC;

	for (i = 0; dynamic_config[i].name != NULL; i++) {
		DICT_ATTR const *da;
		VALUE_PAIR *vp;

		da = dict_attrbyname(dynamic_config[i].name);
		if (!da) {
			DEBUG("- Cannot add client %s: attribute \"%s\"is not in the dictionary",
			      ip_ntoh(&request->packet->src_ipaddr,
				      buffer, sizeof(buffer)),
			      dynamic_config[i].name);
		error:
			client_free(c);
			return NULL;
		}

		vp = pairfind(request->config_items, da->attr, da->vendor, TAG_ANY);
		if (!vp) {
			/*
			 *	Not required.  Skip it.
			 */
			if (!dynamic_config[i].dflt) continue;

			DEBUG("- Cannot add client %s: Required attribute \"%s\" is missing.",
			      ip_ntoh(&request->packet->src_ipaddr,
				      buffer, sizeof(buffer)),
			      dynamic_config[i].name);
			goto error;
		}

		switch (dynamic_config[i].type) {
		case PW_TYPE_IPV4_ADDR:
			if (da->attr == PW_FREERADIUS_CLIENT_IP_ADDRESS) {
				c->ipaddr.af = AF_INET;
				c->ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				c->ipaddr.prefix = 32;
			} else if (da->attr == PW_FREERADIUS_CLIENT_SRC_IP_ADDRESS) {
#ifdef WITH_UDPFROMTO
				c->src_ipaddr.af = AF_INET;
				c->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
#else
				WARN("Server not built with udpfromto, ignoring FreeRADIUS-Client-Src-IP-Address");
#endif
			}

			break;

		case PW_TYPE_IPV6_ADDR:
			if (da->attr == PW_FREERADIUS_CLIENT_IPV6_ADDRESS) {
				c->ipaddr.af = AF_INET6;
				c->ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				c->ipaddr.prefix = 128;
			} else if (da->attr == PW_FREERADIUS_CLIENT_SRC_IPV6_ADDRESS) {
#ifdef WITH_UDPFROMTO
				c->src_ipaddr.af = AF_INET6;
				c->src_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
#else
				WARN("Server not built with udpfromto, ignoring FreeRADIUS-Client-Src-IPv6-Address");
#endif
			}

			break;

		case PW_TYPE_IPV4_PREFIX:
			if (da->attr == PW_FREERADIUS_CLIENT_IP_PREFIX) {
				c->ipaddr.af = AF_INET;
				memcpy(&c->ipaddr.ipaddr.ip4addr.s_addr, &(vp->vp_ipv4prefix[2]), sizeof(c->ipaddr.ipaddr.ip4addr.s_addr));
				fr_ipaddr_mask(&c->ipaddr, (vp->vp_ipv4prefix[1] & 0x3f));
			}

			break;

		case PW_TYPE_IPV6_PREFIX:
			if (da->attr == PW_FREERADIUS_CLIENT_IPV6_PREFIX) {
				c->ipaddr.af = AF_INET6;
				memcpy(&c->ipaddr.ipaddr.ip6addr, &(vp->vp_ipv6prefix[2]), sizeof(c->ipaddr.ipaddr.ip6addr));
				fr_ipaddr_mask(&c->ipaddr, vp->vp_ipv6prefix[1]);
			}

			break;

		case PW_TYPE_STRING:
			p = (char **) ((char *) c + dynamic_config[i].offset);
			if (*p) talloc_free(*p);
			if (vp->vp_strvalue[0]) {
				*p = talloc_typed_strdup(c->cs, vp->vp_strvalue);
			} else {
				*p = NULL;
			}
			break;

		case PW_TYPE_BOOLEAN:
			pi = (int *) ((bool *) ((char *) c + dynamic_config[i].offset));
			*pi = vp->vp_integer;
			break;

		default:
			goto error;
		}
	}

	if (c->ipaddr.af == AF_UNSPEC) {
		DEBUG("- Cannot add client %s: No IP address was specified.",
		      ip_ntoh(&request->packet->src_ipaddr,
			      buffer, sizeof(buffer)));

		goto error;
	}

	{
		fr_ipaddr_t addr;

		/*
		 *	Need to apply the same mask as we set for the client
		 *	else clients created with FreeRADIUS-Client-IPv6-Prefix
		 *	or FreeRADIUS-Client-IPv4-Prefix will fail this check.
		 */
		addr = request->packet->src_ipaddr;
		fr_ipaddr_mask(&addr, c->ipaddr.prefix);
		if (fr_ipaddr_cmp(&addr, &c->ipaddr) != 0) {
			char buf2[128];

			DEBUG("- Cannot add client %s: IP address %s do not match",
			      ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)),
			      ip_ntoh(&c->ipaddr, buf2, sizeof(buf2)));
			goto error;
		}
	}

	if (!c->secret || !*c->secret) {
		DEBUG("- Cannot add client %s: No secret was specified.",
		      ip_ntoh(&request->packet->src_ipaddr,
			      buffer, sizeof(buffer)));
		goto error;
	}

	if (!client_validate(clients, request->client, c)) {
		return NULL;
	}

	if ((c->src_ipaddr.af != AF_UNSPEC) && (c->src_ipaddr.af != c->ipaddr.af)) {
		DEBUG("- Cannot add client %s: Client IP and src address are different IP version.",
		      ip_ntoh(&request->packet->src_ipaddr,
			      buffer, sizeof(buffer)));

		goto error;
	}

	return c;
}

/*
 *	Read a client definition from the given filename.
 */
RADCLIENT *client_read(char const *filename, int in_server, int flag)
{
	char const *p;
	RADCLIENT *c;
	CONF_SECTION *cs;
	char buffer[256];

	if (!filename) return NULL;

	cs = cf_file_read(filename);
	if (!cs) return NULL;

	cs = cf_section_sub_find(cs, "client");
	if (!cs) {
		ERROR("No \"client\" section found in client file");
		return NULL;
	}

	c = client_parse(cs, in_server);
	if (!c) return NULL;

	p = strrchr(filename, FR_DIR_SEP);
	if (p) {
		p++;
	} else {
		p = filename;
	}

	if (!flag) return c;

	/*
	 *	Additional validations
	 */
	ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
	if (strcmp(p, buffer) != 0) {
		DEBUG("Invalid client definition in %s: IP address %s does not match name %s", filename, buffer, p);
		client_free(c);
		return NULL;
	}

	return c;
}
#endif

