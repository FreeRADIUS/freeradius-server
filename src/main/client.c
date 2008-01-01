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

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/radius_snmp.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>

struct radclient_list {
	/*
	 *	FIXME: One set of trees for IPv4, and another for IPv6?
	 */
	rbtree_t	*trees[129]; /* for 0..128, inclusive. */
	int		min_prefix;
};


#ifdef WITH_SNMP
static rbtree_t		*tree_num;	/* client numbers 0..N */
static int		tree_num_max;
#endif
static RADCLIENT_LIST	*root_clients;

/*
 *	Callback for freeing a client.
 */
void client_free(RADCLIENT *client)
{
	free(client->longname);
	free(client->secret);
	free(client->shortname);
	free(client->nastype);
	free(client->login);
	free(client->password);

#ifdef WITH_SNMP
	free(client->auth);
	free(client->acct);
#endif

	free(client);
}


/*
 *	Callback for comparing two clients.
 */
static int client_ipaddr_cmp(const void *one, const void *two)
{
	const RADCLIENT *a = one;
	const RADCLIENT *b = two;

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}

#ifdef WITH_SNMP
static int client_num_cmp(const void *one, const void *two)
{
	const RADCLIENT *a = one;
	const RADCLIENT *b = two;

	return (a->number - b->number);
}
#endif

/*
 *	Free a RADCLIENT list.
 */
void clients_free(RADCLIENT_LIST *clients)
{
	int i;

	if (!clients) return;

	for (i = 0; i <= 128; i++) {
		if (clients->trees[i]) rbtree_free(clients->trees[i]);
		clients->trees[i] = NULL;
	}

	if (clients == root_clients) {
#ifdef WITH_SNMP
		if (tree_num) rbtree_free(tree_num);
		tree_num = NULL;
		tree_num_max = 0;
#endif
		root_clients = NULL;
	}

	free(clients);
}

/*
 *	Return a new, initialized, set of clients.
 */
RADCLIENT_LIST *clients_init(void)
{
	RADCLIENT_LIST *clients = calloc(1, sizeof(RADCLIENT_LIST));

	if (!clients) return NULL;

	clients->min_prefix = 128;

	return clients;
}


/*
 *	Sanity check a client.
 */
static int client_sane(RADCLIENT *client)
{
	switch (client->ipaddr.af) {
	case AF_INET:
		if (client->prefix > 32) {
			return 0;
		}

		/*
		 *	Zero out the subnet bits.
		 */
		if (client->prefix < 32) {
			uint32_t mask = ~0;

			mask <<= (32 - client->prefix);
			client->ipaddr.ipaddr.ip4addr.s_addr &= htonl(mask);
		}
		break;

	case AF_INET6:
		if (client->prefix > 128) return 0;

		if (client->prefix < 128) {
			int i;
			uint32_t mask, *addr;

			addr = (uint32_t *) &client->ipaddr.ipaddr.ip6addr;

			for (i = client->prefix; i < 128; i += 32) {
				mask = ~0;
				mask <<= ((128 - i) & 0x1f);
				addr[i / 32] &= mask;
			}
		}
		break;

	default:
		return 0;
	}

	return 1;
}


/*
 *	Add a client to the tree.
 */
int client_add(RADCLIENT_LIST *clients, RADCLIENT *client)
{
	if (!client) {
		return 0;
	}

	/*
	 *	If "clients" is NULL, it means add to the global list.
	 */
	if (!clients) {
		/*
		 *	Initialize it, if not done already.
		 */
		if (!root_clients) {
			root_clients = clients_init();
			if (!root_clients) return 0;
		}
		clients = root_clients;
	}

	if ((client->prefix < 0) || (client->prefix > 128)) {
		return 0;
	}

	if (!client_sane(client)) return 0;

	/*
	 *	Create a tree for it.
	 */
	if (!clients->trees[client->prefix]) {
		clients->trees[client->prefix] = rbtree_create(client_ipaddr_cmp,
							       (void *) client_free, 0);
		if (!clients->trees[client->prefix]) {
			return 0;
		}
	}

	/*
	 *	Duplicate?
	 */
	if (!rbtree_insert(clients->trees[client->prefix], client)) {
		return 0;
	}

#ifdef WITH_SNMP
	if (!tree_num) {
		tree_num = rbtree_create(client_num_cmp, NULL, 0);
	}


	/*
	 *	Catch clients added by rlm_sql.
	 */
	if (!client->auth) {
		client->auth = rad_malloc(sizeof(*client->auth));
		memset(client->auth, 0, sizeof(*client->auth));
	}

	if (!client->acct) {
		client->acct = rad_malloc(sizeof(*client->acct));
		memset(client->acct, 0, sizeof(*client->acct));
	}


	client->number = tree_num_max;
	tree_num_max++;
	if (tree_num) rbtree_insert(tree_num, client);
#endif

	if (client->prefix < clients->min_prefix) {
		clients->min_prefix = client->prefix;
	}

	return 1;
}


/*
 *	Find a client in the RADCLIENTS list by number.
 *	This is a support function for the SNMP code.
 */
RADCLIENT *client_findbynumber(const RADCLIENT_LIST *clients,
			       int number)
{
#ifdef WITH_SNMP
	if (!clients) clients = root_clients;

	if (!clients) return NULL;

	if (number >= tree_num_max) return NULL;

	if (tree_num) {
		RADCLIENT myclient;

		myclient.number = number;

		return rbtree_finddata(tree_num, &myclient);
	}
#else
	clients = clients;	/* -Wunused */
	number = number;	/* -Wunused */
#endif
	return NULL;
}


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(const RADCLIENT_LIST *clients,
		       const fr_ipaddr_t *ipaddr)
{
	int i, max_prefix;
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

	for (i = max_prefix; i >= clients->min_prefix; i--) {
		void *data;

		myclient.prefix = i;
		myclient.ipaddr = *ipaddr;
		client_sane(&myclient);	/* clean up the ipaddress */

		if (!clients->trees[i]) continue;

		data = rbtree_finddata(clients->trees[i], &myclient);
		if (data) {
			return data;
		}
	}

	return NULL;
}


/*
 *	Old wrapper for client_find
 */
RADCLIENT *client_find_old(const fr_ipaddr_t *ipaddr)
{
	return client_find(root_clients, ipaddr);
}


/*
 *	Find the name of a client (prefer short name).
 */
const char *client_name(const RADCLIENT_LIST *clients,
			const fr_ipaddr_t *ipaddr)
{
	/* We don't call this unless we should know about the client. */
	RADCLIENT *cl;
	char host_ipaddr[128];

	if ((cl = client_find(clients, ipaddr)) != NULL) {
		if (cl->shortname && cl->shortname[0])
			return cl->shortname;
		else
			return cl->longname;
	}

	/*
	 * this isn't normally reachable, but if a loggable event happens just
	 * after a client list change and a HUP, then we may not know this
	 * information any more.
	 *
	 * If you see lots of these, then there's something wrong.
	 */
	radlog(L_ERR, "Trying to look up name of unknown client %s.\n",
	       ip_ntoh(ipaddr, host_ipaddr, sizeof(host_ipaddr)));

	return "UNKNOWN-CLIENT";
}

const char *client_name_old(const fr_ipaddr_t *ipaddr)
{
	return client_name(root_clients, ipaddr);
}

static struct in_addr cl_ip4addr;
static struct in6_addr cl_ip6addr;

static const CONF_PARSER client_config[] = {
	{ "ipaddr",  PW_TYPE_IPADDR,
	  0, &cl_ip4addr,  NULL },
	{ "ipv6addr",  PW_TYPE_IPV6ADDR,
	  0, &cl_ip6addr, NULL },
	{ "netmask",  PW_TYPE_INTEGER,
	  offsetof(RADCLIENT, prefix), 0, NULL },

	{ "require_message_authenticator",  PW_TYPE_BOOLEAN,
	  offsetof(RADCLIENT, message_authenticator), 0, "no" },

	{ "secret",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, secret), 0, NULL },
	{ "shortname",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, shortname), 0, NULL },
	{ "nastype",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, nastype), 0, NULL },
	{ "login",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, login), 0, NULL },
	{ "password",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, password), 0, NULL },
	{ "virtual_server",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, server), 0, NULL },
	{ "server",  PW_TYPE_STRING_PTR, /* compatability with 2.0-pre */
	  offsetof(RADCLIENT, server), 0, NULL },

	{ NULL, -1, 0, NULL, NULL }
};


static RADCLIENT *client_parse(CONF_SECTION *cs, int global)
{
	RADCLIENT	*c;
	const char	*name2;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Missing client name");
		return NULL;
	}

	/*
	 * The size is fine.. Let's create the buffer
	 */
	c = rad_malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));
	c->cs = cs;

#ifdef WITH_SNMP
	c->auth = rad_malloc(sizeof(*c->auth));
	memset(c->auth, 0, sizeof(*c->auth));

	c->acct = rad_malloc(sizeof(*c->acct));
	memset(c->acct, 0, sizeof(*c->acct));
#endif

	memset(&cl_ip4addr, 0, sizeof(cl_ip4addr));
	memset(&cl_ip6addr, 0, sizeof(cl_ip6addr));
	c->prefix = -1;

	if (cf_section_parse(cs, c, client_config) < 0) {
		client_free(c);
		cf_log_err(cf_sectiontoitem(cs),
			   "Error parsing client section.");
		return NULL;
	}

	/*
	 *	Global clients can set servers to use,
	 *	per-server clients cannot.
	 */
	if (!global && c->server) {
		client_free(c);
		cf_log_err(cf_sectiontoitem(cs),
			   "Clients inside of an server section cannot point to a server.");
		return NULL;
	}
		
	/*
	 *	No "ipaddr" or "ipv6addr", use old-style
	 *	"client <ipaddr> {" syntax.
	 */
	if (!cf_pair_find(cs, "ipaddr") &&
	    !cf_pair_find(cs, "ipv6addr")) {
		char *prefix_ptr;

		prefix_ptr = strchr(name2, '/');

		/*
		 *	Look for prefixes.
		 */
		if (prefix_ptr) {
			c->prefix = atoi(prefix_ptr + 1);
			if ((c->prefix < 0) || (c->prefix > 128)) {
				client_free(c);
				cf_log_err(cf_sectiontoitem(cs),
					   "Invalid Prefix value '%s' for IP.",
					   prefix_ptr + 1);
				return NULL;
			}
			/* Replace '/' with '\0' */
			*prefix_ptr = '\0';
		}
			
		/*
		 *	Always get the numeric representation of IP
		 */
		if (ip_hton(name2, AF_UNSPEC, &c->ipaddr) < 0) {
			client_free(c);
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed to look up hostname %s: %s",
				   name2, librad_errstr);
			return NULL;
		}

		if (prefix_ptr) *prefix_ptr = '/';
		c->longname = strdup(name2);

		if (!c->shortname) c->shortname = strdup(c->longname);

	} else {
		char buffer[1024];

		/*
		 *	Figure out which one to use.
		 */
		if (cf_pair_find(cs, "ipaddr")) {
			c->ipaddr.af = AF_INET;
			c->ipaddr.ipaddr.ip4addr = cl_ip4addr;

			if ((c->prefix < -1) || (c->prefix > 32)) {
				client_free(c);
				cf_log_err(cf_sectiontoitem(cs),
					   "Netmask must be between 0 and 32");
				return NULL;
			}
				
		} else if (cf_pair_find(cs, "ipv6addr")) {
			c->ipaddr.af = AF_INET6;
			c->ipaddr.ipaddr.ip6addr = cl_ip6addr;
				
			if ((c->prefix < -1) || (c->prefix > 128)) {
				client_free(c);
				cf_log_err(cf_sectiontoitem(cs),
					   "Netmask must be between 0 and 128");
				return NULL;
			}
		} else {
			cf_log_err(cf_sectiontoitem(cs),
				   "No IP address defined for the client");
			client_free(c);
			return NULL;
		}

		ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
		c->longname = strdup(buffer);

		/*
		 *	Set the short name to the name2
		 */
		if (!c->shortname) c->shortname = strdup(name2);
	}

	if (c->prefix < 0) switch (c->ipaddr.af) {
	case AF_INET:
		c->prefix = 32;
		break;
	case AF_INET6:
		c->prefix = 128;
		break;
	default:
		break;
	}

	return c;
}

/*
 *	Create the linked list of clients from the new configuration
 *	type.  This way we don't have to change too much in the other
 *	source-files.
 */
RADCLIENT_LIST *clients_parse_section(CONF_SECTION *section)
{
	int		global = FALSE;
	CONF_SECTION	*cs;
	RADCLIENT	*c;
	RADCLIENT_LIST	*clients;

	/*
	 *	Be forgiving.  If there's already a clients, return
	 *	it.  Otherwise create a new one.
	 */
	clients = cf_data_find(section, "clients");
	if (clients) return clients;

	clients = clients_init();
	if (!clients) return NULL;

	if (cf_top_section(section) == section) global = TRUE;

	/*
	 *	Associate the clients structure with the section, where
	 *	it will be freed once the section is freed.
	 */
	if (cf_data_add(section, "clients", clients, (void *) clients_free) < 0) {
		cf_log_err(cf_sectiontoitem(section),
			   "Failed to associate clients with section %s",
		       cf_section_name1(section));
		clients_free(clients);
		return NULL;
	}

	for (cs = cf_subsection_find_next(section, NULL, "client");
	     cs != NULL;
	     cs = cf_subsection_find_next(section, cs, "client")) {
		c = client_parse(cs, global);
		if (!c) {
			return NULL;
		}

		/*
		 *	FIXME: Add the client as data via cf_data_add,
		 *	for migration issues.
		 */

		if (!client_add(clients, c)) {
			cf_log_err(cf_sectiontoitem(cs),
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
