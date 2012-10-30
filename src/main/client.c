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
	int		min_prefix;
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

	free(client->longname);
	free(client->secret);
	free(client->shortname);
	free(client->nastype);
	free(client->login);
	free(client->password);
	free(client->server);

#ifdef WITH_DYNAMIC_CLIENTS
	free(client->client_server);
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
		if (client->prefix == 0) {
			memset(&client->ipaddr.ipaddr.ip4addr, 0,
			       sizeof(client->ipaddr.ipaddr.ip4addr));

		} else if (client->prefix < 32) {
			uint32_t mask = ~0;

			mask <<= (32 - client->prefix);
			client->ipaddr.ipaddr.ip4addr.s_addr &= htonl(mask);
		}
		break;

	case AF_INET6:
		if (client->prefix > 128) return 0;

		if (client->prefix == 0) {
			memset(&client->ipaddr.ipaddr.ip6addr, 0,
			       sizeof(client->ipaddr.ipaddr.ip6addr));

		} else if (client->prefix < 128) {
			uint32_t mask, *addr;

			addr = (uint32_t *) &client->ipaddr.ipaddr.ip6addr;

			if ((client->prefix & 0x1f) == 0) {
				mask = 0;
			} else {
				mask = ~ ((uint32_t) 0);
				mask <<= (32 - (client->prefix & 0x1f));
				mask = htonl(mask);
			}

			switch (client->prefix >> 5) {
			case 0:
				addr[0] &= mask;
				mask = 0;
				/* FALL-THROUGH */
			case 1:
				addr[1] &= mask;
				mask = 0;
				/* FALL-THROUGH */
			case 2:
				addr[2] &= mask;
				mask = 0;
				/* FALL-THROUGH */
			case 3:
				addr[3] &= mask;
			  break;
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
	RADCLIENT *old;

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

#define namecmp(a) ((!old->a && !client->a) || (old->a && client->a && (strcmp(old->a, client->a) == 0)))

	/*
	 *	Cannot insert the same client twice.
	 */
	old = rbtree_finddata(clients->trees[client->prefix], client);
	if (old) {
		/*
		 *	If it's a complete duplicate, then free the new
		 *	one, and return "OK".
		 */
		if ((fr_ipaddr_cmp(&old->ipaddr, &client->ipaddr) == 0) &&
		    (old->prefix == client->prefix) &&
		    namecmp(longname) && namecmp(secret) &&
		    namecmp(shortname) && namecmp(nastype) &&
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
			DEBUG("WARNING: Ignoring duplicate client %s", client->longname);
			client_free(client);
			return 1;
		}

		radlog(L_ERR, "Failed to add duplicate client %s",
		       client->shortname);
		return 0;
	}
#undef namecmp

	/*
	 *	Other error adding client: likely is fatal.
	 */
	if (!rbtree_insert(clients->trees[client->prefix], client)) {
		return 0;
	}

#ifdef WITH_STATS
	if (!tree_num) {
		tree_num = rbtree_create(client_num_cmp, NULL, 0);
	}

#ifdef WITH_DYNAMIC_CLIENTS
	/*
	 *	More catching of clients added by rlm_sql.
	 *
	 *	The sql modules sets the dynamic flag BEFORE calling
	 *	us.  The client_create() function sets it AFTER
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

	if (client->prefix < clients->min_prefix) {
		clients->min_prefix = client->prefix;
	}

	return 1;
}


#ifdef WITH_DYNAMIC_CLIENTS
void client_delete(RADCLIENT_LIST *clients, RADCLIENT *client)
{
	if (!client) return;

	if (!clients) clients = root_clients;

	if (!client->dynamic) return;

	rad_assert((client->prefix >= 0) && (client->prefix <= 128));

	client->dynamic = 2;	/* signal to client_free */

#ifdef WITH_STATS
	rbtree_deletebydata(tree_num, client);
#endif
	rbtree_deletebydata(clients->trees[client->prefix], client);
}
#endif


/*
 *	Find a client in the RADCLIENTS list by number.
 *	This is a support function for the statistics code.
 */
RADCLIENT *client_findbynumber(const RADCLIENT_LIST *clients,
			       int number)
{
#ifdef WITH_STATS
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
		       const fr_ipaddr_t *ipaddr, int proto)
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
		myclient.proto = proto;
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
	return client_find(root_clients, ipaddr, IPPROTO_UDP);
}

static struct in_addr cl_ip4addr;
static struct in6_addr cl_ip6addr;
#ifdef WITH_TCP
static char *hs_proto = NULL;
#endif

#ifdef WITH_TCP
static CONF_PARSER limit_config[] = {
	{ "max_connections", PW_TYPE_INTEGER,
	  offsetof(RADCLIENT, limit.max_connections), NULL,   "16" },

	{ "lifetime", PW_TYPE_INTEGER,
	  offsetof(RADCLIENT, limit.lifetime), NULL,   "0" },

	{ "idle_timeout", PW_TYPE_INTEGER,
	  offsetof(RADCLIENT, limit.idle_timeout), NULL,   "30" },

	{ NULL, -1, 0, NULL, NULL }		/* end the list */
};
#endif

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

#ifdef WITH_TCP
	{ "proto",  PW_TYPE_STRING_PTR,
	  0, &hs_proto, NULL },

	{ "limit", PW_TYPE_SUBSECTION, 0, NULL, (const void *) limit_config },
#endif

#ifdef WITH_DYNAMIC_CLIENTS
	{ "dynamic_clients",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, client_server), 0, NULL },
	{ "lifetime",  PW_TYPE_INTEGER,
	  offsetof(RADCLIENT, lifetime), 0, NULL },
	{ "rate_limit",  PW_TYPE_BOOLEAN,
	  offsetof(RADCLIENT, rate_limit), 0, NULL },
#endif

#ifdef WITH_COA
	{ "coa_server",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, coa_name), 0, NULL },
#endif

	{ NULL, -1, 0, NULL, NULL }
};


static RADCLIENT *client_parse(CONF_SECTION *cs, int in_server)
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

	memset(&cl_ip4addr, 0, sizeof(cl_ip4addr));
	memset(&cl_ip6addr, 0, sizeof(cl_ip6addr));
	c->prefix = -1;

	if (cf_section_parse(cs, c, client_config) < 0) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Error parsing client section.");
	error:
		client_free(c);
#ifdef WITH_TCP
		free(hs_proto);
		hs_proto = NULL;
#endif

		return NULL;
	}

	/*
	 *	Global clients can set servers to use,
	 *	per-server clients cannot.
	 */
	if (in_server && c->server) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Clients inside of an server section cannot point to a server.");
		goto error;
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
				cf_log_err(cf_sectiontoitem(cs),
					   "Invalid Prefix value '%s' for IP.",
					   prefix_ptr + 1);
				goto error;
			}
			/* Replace '/' with '\0' */
			*prefix_ptr = '\0';
		}
			
		/*
		 *	Always get the numeric representation of IP
		 */
		if (ip_hton(name2, AF_UNSPEC, &c->ipaddr) < 0) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed to look up hostname %s: %s",
				   name2, fr_strerror());
			goto error;
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
				cf_log_err(cf_sectiontoitem(cs),
					   "Netmask must be between 0 and 32");
				goto error;
			}
				
		} else if (cf_pair_find(cs, "ipv6addr")) {
			c->ipaddr.af = AF_INET6;
			c->ipaddr.ipaddr.ip6addr = cl_ip6addr;
				
			if ((c->prefix < -1) || (c->prefix > 128)) {
				cf_log_err(cf_sectiontoitem(cs),
					   "Netmask must be between 0 and 128");
				goto error;
			}
		} else {
			cf_log_err(cf_sectiontoitem(cs),
				   "No IP address defined for the client");
			goto error;
		}

		ip_ntoh(&c->ipaddr, buffer, sizeof(buffer));
		c->longname = strdup(buffer);

		/*
		 *	Set the short name to the name2
		 */
		if (!c->shortname) c->shortname = strdup(name2);

		c->proto = IPPROTO_UDP;
#ifdef WITH_TCP
		if (hs_proto) {
			if (strcmp(hs_proto, "udp") == 0) {
				free(hs_proto);
				hs_proto = NULL;
				
			} else if (strcmp(hs_proto, "tcp") == 0) {
				free(hs_proto);
				hs_proto = NULL;
				c->proto = IPPROTO_TCP;
				
			} else if (strcmp(hs_proto, "*") == 0) {
				free(hs_proto);
				hs_proto = NULL;
				c->proto = IPPROTO_IP; /* fake for dual */
				
			} else {
				cf_log_err(cf_sectiontoitem(cs),
					   "Unknown proto \"%s\".", hs_proto);
				goto error;
			}
		}
#endif
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

#ifdef WITH_DYNAMIC_CLIENTS
	if (c->client_server) {
		free(c->secret);
		c->secret = strdup("testing123");

		if (((c->ipaddr.af == AF_INET) &&
		     (c->prefix == 32)) ||
		    ((c->ipaddr.af == AF_INET6) &&
		     (c->prefix == 128))) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Dynamic clients MUST be a network, not a single IP address.");
			goto error;
		}

		return c;
	}
#endif

	if (!c->secret || !*c->secret) {
#ifdef WITH_DHCP
		const char *value = NULL;
		CONF_PAIR *cp = cf_pair_find(cs, "dhcp");

		if (cp) value = cf_pair_value(cp);

		/*
		 *	Secrets aren't needed for DHCP.
		 */
		if (value && (strcmp(value, "yes") == 0)) return c;

#endif
		cf_log_err(cf_sectiontoitem(cs),
			   "secret must be at least 1 character long");
		goto error;
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
			cf_log_err(cf_sectiontoitem(cs), "No such home_server or home_server_pool \"%s\"", c->coa_name);
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
RADCLIENT_LIST *clients_parse_section(CONF_SECTION *section)
{
	int		global = FALSE, in_server = FALSE;
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

	if (strcmp("server", cf_section_name1(section)) == 0) in_server = TRUE;

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
		c = client_parse(cs, in_server);
		if (!c) {
			return NULL;
		}

		/*
		 *	FIXME: Add the client as data via cf_data_add,
		 *	for migration issues.
		 */

#ifdef WITH_DYNAMIC_CLIENTS
#ifdef HAVE_DIRENT_H
		if (c->client_server) {
			const char *value;
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
				cf_log_err(cf_sectiontoitem(cs),
					   "The \"directory\" entry must not be empty");
				client_free(c);
				return NULL;
			}

			DEBUG("including dynamic clients in %s", value);
			
			dir = opendir(value);
			if (!dir) {
				cf_log_err(cf_sectiontoitem(cs), "Error reading directory %s: %s", value, strerror(errno));
				client_free(c);
				return NULL;
			}
			
			/*
			 *	Read the directory, ignoring "." files.
			 */
			while ((dp = readdir(dir)) != NULL) {
				const char *p;
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

				dc = client_read(buf2, in_server, TRUE);
				if (!dc) {
					cf_log_err(cf_sectiontoitem(cs),
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
#endif /* WITH_DYNAMIC_CLIENTS */

	add_client:
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

#ifdef WITH_DYNAMIC_CLIENTS
/*
 *	We overload this structure a lot.
 */
static const CONF_PARSER dynamic_config[] = {
	{ "FreeRADIUS-Client-IP-Address",  PW_TYPE_IPADDR,
	  offsetof(RADCLIENT, ipaddr), 0, NULL },
	{ "FreeRADIUS-Client-IPv6-Address",  PW_TYPE_IPV6ADDR,
	  offsetof(RADCLIENT, ipaddr), 0, NULL },

	{ "FreeRADIUS-Client-Require-MA",  PW_TYPE_BOOLEAN,
	  offsetof(RADCLIENT, message_authenticator), NULL, NULL },

	{ "FreeRADIUS-Client-Secret",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, secret), 0, "" },
	{ "FreeRADIUS-Client-Shortname",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, shortname), 0, "" },
	{ "FreeRADIUS-Client-NAS-Type",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, nastype), 0, NULL },
	{ "FreeRADIUS-Client-Virtual-Server",  PW_TYPE_STRING_PTR,
	  offsetof(RADCLIENT, server), 0, NULL },

	{ NULL, -1, 0, NULL, NULL }
};


int client_validate(RADCLIENT_LIST *clients, RADCLIENT *master, RADCLIENT *c)
{
	char buffer[128];

	/*
	 *	No virtual server defined.  Inherit the parent's
	 *	definition.
	 */
	if (master->server && !c->server) {
		c->server = strdup(master->server);
	}

	/*
	 *	If the client network isn't global (not tied to a
	 *	virtual server), then ensure that this clients server
	 *	is the same as the enclosing networks virtual server.
	 */
	if (master->server &&
	     (strcmp(master->server, c->server) != 0)) {
		DEBUG("- Cannot add client %s: Virtual server %s is not the same as the virtual server for the network.",
		      ip_ntoh(&c->ipaddr,
			      buffer, sizeof(buffer)),
		      c->server);

		goto error;
	}

	if (!client_add(clients, c)) {
		DEBUG("- Cannot add client %s: Internal error",
		      ip_ntoh(&c->ipaddr,
			      buffer, sizeof(buffer)));

		goto error;
	}

	/*
	 *	Initialize the remaining fields.
	 */
	c->dynamic = TRUE;
	c->lifetime = master->lifetime;
	c->created = time(NULL);
	c->longname = strdup(c->shortname);

	DEBUG("- Added client %s with shared secret %s",
	      ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)),
	      c->secret);

	return 1;

 error:
	client_free(c);
	return 0;
}


RADCLIENT *client_create(RADCLIENT_LIST *clients, REQUEST *request)
{
	int i, *pi;
	char **p;
	RADCLIENT *c;
	char buffer[128];

	if (!clients || !request) return NULL;

	c = rad_malloc(sizeof(*c));
	memset(c, 0, sizeof(*c));
	c->cs = request->client->cs;
	c->ipaddr.af = AF_UNSPEC;

	for (i = 0; dynamic_config[i].name != NULL; i++) {
		DICT_ATTR *da;
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

		vp = pairfind(request->config_items, da->attr, da->vendor);
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
		case PW_TYPE_IPADDR:
			c->ipaddr.af = AF_INET;
			c->ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
			c->prefix = 32;
			break;

		case PW_TYPE_IPV6ADDR:
			c->ipaddr.af = AF_INET6;
			c->ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
			c->prefix = 128;
			break;

		case PW_TYPE_STRING_PTR:
			p = (char **) ((char *) c + dynamic_config[i].offset);
			if (*p) free(*p);
			if (vp->vp_strvalue[0]) {
				*p = strdup(vp->vp_strvalue);
			} else {
				*p = NULL;
			}
			break;

		case PW_TYPE_BOOLEAN:
			pi = (int *) ((char *) c + dynamic_config[i].offset);
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

	if (fr_ipaddr_cmp(&request->packet->src_ipaddr, &c->ipaddr) != 0) {
		char buf2[128];

		DEBUG("- Cannot add client %s: IP address %s do not match",
		      ip_ntoh(&request->packet->src_ipaddr,
			      buffer, sizeof(buffer)),
		      ip_ntoh(&c->ipaddr,
			      buf2, sizeof(buf2)));		      
		goto error;
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

	return c;
}

/*
 *	Read a client definition from the given filename.
 */
RADCLIENT *client_read(const char *filename, int in_server, int flag)
{
	const char *p;
	RADCLIENT *c;
	CONF_SECTION *cs;
	char buffer[256];

	if (!filename) return NULL;

	cs = cf_file_read(filename);
	if (!cs) return NULL;
	
	cs = cf_section_sub_find(cs, "client");
	if (!cs) {
		radlog(L_ERR, "No \"client\" section found in client file");
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
