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
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2000  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2000  Alan DeKok <aland@ox.org>
 */

static const char rcsid[] = "$Id$";

#include "autoconf.h"

#include <sys/stat.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>

#include "radiusd.h"
#include "conffile.h"
#include "rad_assert.h"

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


/*
 *	Free a RADCLIENT list.
 */
void clients_free(rbtree_t **client_trees)
{
	int i;

	if (!client_trees) return;

	for (i = 0; i <= 128; i++) {
		if (client_trees[i]) rbtree_free(client_trees[i]);
		client_trees[i] = NULL;
	}
}

/*
 *	Return a new, initialized, set of clients.
 */
rbtree_t **clients_init(void)
{
	rbtree_t **client_trees = calloc(sizeof(rbtree_t *), 129);

	if (!client_trees) return NULL;

	return client_trees;
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
			client->ipaddr.ipaddr.ip4addr.s_addr &= mask;
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
int client_add(rbtree_t **client_trees, RADCLIENT *client)
{
	if (!client_trees || !client) {
		return 0;
	}

	if (client->prefix < 0) {
		return 0;
	}

	if (!client_sane(client)) return 0;

	/*
	 *	Create a tree for it.
	 */
	if (!client_trees[client->prefix]) {
		client_trees[client->prefix] = rbtree_create(client_ipaddr_cmp,
							     client_free, 0);
		if (!client_trees[client->prefix]) {
			return 0;
		}
	}

	if (rbtree_finddata(client_trees[client->prefix], client)) {
		fprintf(stderr, "FUCK %s:%d\n", __FILE__, __LINE__);
	}

	/*
	 *	Duplicate?
	 */
	if (!rbtree_insert(client_trees[client->prefix], client)) {
		return 0;
	}

	return 1;
}

/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(const rbtree_t **client_trees,
		       const lrad_ipaddr_t *ipaddr)
{
	int i, max_prefix;
	RADCLIENT myclient;

	if (!client_trees || !ipaddr) return NULL;

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

	for (i = max_prefix; i >= 0; i--) {
		void *data;

		myclient.prefix = i;
		myclient.ipaddr = *ipaddr;
		client_sane(&myclient);	/* clean up the ipaddress */

		if (!client_trees[i]) continue;
		
		data = rbtree_finddata(client_trees[i], &myclient);
		if (data) {
			fprintf(stderr, "FOUND at %d\n", i);
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
	return client_find(mainconfig.client_trees, ipaddr);
}


/*
 *	Read the clients file.
 */
int read_clients_file(rbtree_t **client_trees, const char *file)
{
	FILE *fp;
	RADCLIENT *c;
	char buffer[256];
	char hostnm[256];
	char secret[256];
	char shortnm[256];
	int prefix = 0;
	int lineno = 0;
	char *p;
	int got_clients = FALSE;

	if ((fp = fopen(file, "r")) == NULL) {
		/* The clients file is no longer required.  All configuration
		   information is read from radiusd.conf and friends.  If
		   clients exists it will be used, but if it doesn't no harm
		   done. */
		return 0;
	}

	while(fgets(buffer, 256, fp) != NULL) {
		lineno++;
		if (!feof(fp) && (strchr(buffer, '\n') == NULL)) {
			radlog(L_ERR, "%s[%d]: line too long", file, lineno);
			return -1;
		}

		/*
		 *	Skip whitespace.
		 */
		p = buffer;
		while (*p &&
				((*p == ' ') || (*p == '\t')))
			p++;

		/*
		 *	Skip comments and blank lines.
		 */
		if ((*p == '#') || (*p == '\n') || (*p == '\r'))
			continue;

		if (!getword(&p, hostnm, sizeof(hostnm)) ||
				!getword(&p, secret, sizeof(secret))) {
			radlog(L_ERR, "%s[%d]: unexpected end of line",
					file, lineno);
			return -1;
		}

		(void)getword(&p, shortnm, sizeof(shortnm));

		/*
		 *	Look for a mask in the hostname
		 */
		p = strchr(hostnm, '/');

		if (p) {
			*p = '\0';
			p++;

			prefix = atoi(p);
			if ((prefix < 0) || (prefix > 128)) {
				radlog(L_ERR, "%s[%d]: Invalid value '%s' for IP network mask.",
				       file, lineno, p);
				return -1;
			}
		}

		/*
		 *	It should be OK now, let's create the buffer.
		 */
		got_clients = TRUE;
		c = rad_malloc(sizeof(RADCLIENT));
		memset(c, 0, sizeof(*c));

		if (ip_hton(hostnm, AF_UNSPEC, &c->ipaddr) < 0) {
			radlog(L_CONS|L_ERR, "%s[%d]: Failed to look up hostname %s",
					file, lineno, hostnm);
			return -1;
		}
		c->prefix = prefix;
		c->secret = strdup(secret);
		c->shortname = strdup(shortnm);

		switch (c->ipaddr.af) {
		case AF_INET :
			if ((prefix < 0) || (prefix > 32)) {
				radlog(L_ERR, "%s[%d]: Invalid value '%s' for IP network mask.",
				       file, lineno, p);
				return -1;
			}

			if (prefix) {
				hostnm[strlen(hostnm)] = '/';
				/* Long Name includes prefix too */
				c->longname = strdup(hostnm);
			} else {

				/*
				 * Only do DNS lookups for machines.  Just print
				 * the network as the long name.
				 */
				ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
				c->longname = strdup(buffer);

			}
			/*
			 *	Pull information over from the NAS.
			 */
			NAS *nas;
			nas = nas_find(c->ipaddr.ipaddr.ip4addr.s_addr);
			if (nas) {
				/*
				 *	No short name in the
				 *	'clients' file, try
				 *	copying one over from
				 *	the 'naslist' file.
				 */
				if (!c->shortname) {
					c->shortname = strdup(nas->shortname);
				}
				
				/*
				 *  Copy the nastype over, too.
				 */
				c->nastype = strdup(nas->nastype);
			}
			break;

		case AF_INET6 :
			if (prefix) {
				hostnm[strlen(hostnm)] = '/';
				c->longname = strdup(hostnm);
			} else {

				/*
				 * Only do DNS lookups for machines.  Just print
				 * the network as the long name.
				 */
				ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
				c->longname = strdup(buffer);
			}
			/* TODO: NAS info as in IPv4 above */
			break;
		default :
			break;
		}

		/*
		 *	Failed to add the client: ignore the error
		 *	and continue.
		 */
		if (!client_add(client_trees, c)) {
			client_free(c);
		}
	}
	fclose(fp);

	if (got_clients) {
		radlog(L_INFO, "Using deprecated clients file.  Support for this will go away soon.");
	}

	return 0;
}


/*
 *	Find the name of a client (prefer short name).
 */
const char *client_name(const rbtree_t **client_trees,
			const lrad_ipaddr_t *ipaddr)
{
	/* We don't call this unless we should know about the client. */
	RADCLIENT *cl;
	char host_ipaddr[128];

	if ((cl = client_find(client_trees, ipaddr)) != NULL) {
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
	return client_name(mainconfig.client_trees, ipaddr);
}
