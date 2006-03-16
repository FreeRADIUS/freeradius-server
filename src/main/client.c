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
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include <freeradius-devel/autoconf.h>

#include <sys/stat.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/conffile.h>
#include <freeradius-devel/rad_assert.h>

struct radclient_list {
	/*
	 *	FIXME: One set of trees for IPv4, and another for IPv6?
	 */
	rbtree_t	*trees[129]; /* for 0..128, inclusive. */
	int		min_prefix;
#ifdef WITH_SNMP
	rbtree_t	*num;	/* client numbers 0..N */
	int		max;
#endif
};

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
	
	free(client);
}


/*
 *	Callback for comparing two clients.
 */
static int client_ipaddr_cmp(const void *one, const void *two)
{
	const RADCLIENT *a = one;
	const RADCLIENT *b = two;

	if (a->ipaddr.af < b->ipaddr.af) return -1;
	if (a->ipaddr.af > b->ipaddr.af) return +1;

	rad_assert(a->prefix == b->prefix);

	switch (a->ipaddr.af) {
	case AF_INET:
		return memcmp(&a->ipaddr.ipaddr.ip4addr,
			      &b->ipaddr.ipaddr.ip4addr,
			      sizeof(a->ipaddr.ipaddr.ip4addr));
		break;

	case AF_INET6:
		return memcmp(&a->ipaddr.ipaddr.ip6addr,
			      &b->ipaddr.ipaddr.ip6addr,
			      sizeof(a->ipaddr.ipaddr.ip6addr));
		break;

	default:
		break;
	}

	/*
	 *	Something bad happened...
	 */
	rad_assert("Internal sanity check failed");
	return -1;
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
#ifdef WITH_SNMP
	if (clients->num) rbtree_free(clients->num);
#endif
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
	if (!clients || !client) {
		return 0;
	}

	if (client->prefix < 0) {
		return 0;
	}

	if (!client_sane(client)) return 0;

	/*
	 *	Create a tree for it.
	 */
	if (!clients->trees[client->prefix]) {
		clients->trees[client->prefix] = rbtree_create(client_ipaddr_cmp,
							       client_free, 0);
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
	if (!clients->num) rbtree_create(client_num_cmp, NULL, 0);

	client->number = clients->max;
	clients->max++;
	if (clients->num) rbtree_insert(clients->num, client);
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
	if (!clients) return NULL;

	if (clients->num) {
		RADCLIENT myclient;
		
		myclient.number = number;
		
		return rbtree_finddata(clients->num, &myclient);
	}
#endif
	return NULL;
}


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(const RADCLIENT_LIST *clients,
		       const lrad_ipaddr_t *ipaddr)
{
	int i, max_prefix;
	RADCLIENT myclient;

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
RADCLIENT *client_find_old(const lrad_ipaddr_t *ipaddr)
{
	return client_find(mainconfig.clients, ipaddr);
}


/*
 *	Find the name of a client (prefer short name).
 */
const char *client_name(const RADCLIENT_LIST *clients,
			const lrad_ipaddr_t *ipaddr)
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

const char *client_name_old(const lrad_ipaddr_t *ipaddr)
{
	return client_name(mainconfig.clients, ipaddr);
}

static const CONF_PARSER client_config[] = {
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

	{ NULL, -1, 0, NULL, NULL }
};


/*
 *	Create the linked list of clients from the new configuration
 *	type.  This way we don't have to change too much in the other
 *	source-files.
 */
RADCLIENT_LIST *clients_parse_section(const char *filename,
				      CONF_SECTION *section)
{
	CONF_SECTION	*cs;
	RADCLIENT	*c;
	char		*hostnm, *prefix_ptr = NULL;
	const char	*name2;
	RADCLIENT_LIST	*clients;

	/*
	 *	Be forgiving.  If there's already a clients, return
	 *	it.  Otherwise create a new one.
	 */
	clients = cf_data_find(section, "clients");
	if (clients) return clients;

	clients = clients_init();
	if (!clients) return NULL;

	/*
	 *	Associate the clients structure with the section, where
	 *	it will be freed once the section is freed.
	 */
	if (cf_data_add(section, "clients", clients, clients_free) < 0) {
		radlog(L_ERR, "%s[%d]: Failed to associate clients with section %s",
		       filename, cf_section_lineno(section),
		       cf_section_name1(section));
		clients_free(clients);
		return NULL;
	}

	for (cs = cf_subsection_find_next(section, NULL, "client");
	     cs != NULL;
	     cs = cf_subsection_find_next(section, cs, "client")) {
		name2 = cf_section_name2(cs);
		if (!name2) {
			radlog(L_CONS|L_ERR, "%s[%d]: Missing client name",
			       filename, cf_section_lineno(cs));
			return NULL;
		}
		/*
		 * Check the lengths, we don't want any core dumps
		 */
		hostnm = name2;
		prefix_ptr = strchr(hostnm, '/');

		/*
		 * The size is fine.. Let's create the buffer
		 */
		c = rad_malloc(sizeof(RADCLIENT));
		memset(c, 0, sizeof(RADCLIENT));

		if (cf_section_parse(cs, c, client_config) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Error parsing client section.",
			       filename, cf_section_lineno(cs));
			return NULL;
		}

		/*
		 * Look for prefixes.
		 */
		c->prefix = -1;
		if (prefix_ptr) {
			c->prefix = atoi(prefix_ptr + 1);
			if ((c->prefix < 0) || (c->prefix > 128)) {
				radlog(L_ERR, "%s[%d]: Invalid Prefix value '%s' for IP.",
						filename, cf_section_lineno(cs), prefix_ptr + 1);
				return NULL;
			}
			/* Replace '/' with '\0' */
			*prefix_ptr = '\0';
		}

		/*
		 * Always get the numeric representation of IP
		 */
		if (ip_hton(hostnm, AF_UNSPEC, &c->ipaddr) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s: %s",
			       filename, cf_section_lineno(cs),
			       hostnm, librad_errstr);
			return NULL;
		} else {
			char buffer[256];
			ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
			c->longname = strdup(buffer);
		}

		/*
		 *	This makes later life easier.
		 */
		if (!c->shortname) c->shortname = strdup(c->longname);

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

		/*
		 *	FIXME: Add the client as data via cf_data_add,
		 *	for migration issues.
		 */

		if (!client_add(clients, c)) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to add client %s",
			       filename, cf_section_lineno(cs), hostnm);
			client_free(c);
			return NULL;
		}
	}

	return clients;
}
