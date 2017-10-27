/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 * @file main/client.c
 * @brief Manage clients allowed to communicate with the server.
 *
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok <aland@ox.org>
 * @copyright 2000 Miquel van Smoorenburg <miquels@cistron.nl>
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
			deleted_clients = fr_fifo_create(NULL, 1024, (void (*)(void *))client_free);
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
		rad_assert(client != NULL);

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
void client_list_free(RADCLIENT_LIST *clients)
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
RADCLIENT_LIST *client_list_init(CONF_SECTION *cs)
{
	RADCLIENT_LIST *clients = talloc_zero(cs, RADCLIENT_LIST);

	if (!clients) return NULL;

	clients->min_prefix = 128;

	return clients;
}

/** Add a client to a RADCLIENT_LIST
 *
 * @param clients list to add client to, may be NULL if global client list is being used.
 * @param client to add.
 * @return true on success, false on failure.
 */
bool client_add(RADCLIENT_LIST *clients, RADCLIENT *client)
{
	RADCLIENT *old;
	char buffer[INET6_ADDRSTRLEN + 3];

	if (!client) return false;

	/*
	 *	Hack to fixup wildcard clients
	 *
	 *	If the IP is all zeros, with a 32 or 128 bit netmask
	 *	assume the user meant to configure 0.0.0.0/0 instead
	 *	of 0.0.0.0/32 - which would require the src IP of
	 *	the client to be all zeros.
	 */
	if (fr_inaddr_any(&client->ipaddr) == 1) switch (client->ipaddr.af) {
	case AF_INET:
		if (client->ipaddr.prefix == 32) client->ipaddr.prefix = 0;
		break;

	case AF_INET6:
		if (client->ipaddr.prefix == 128) client->ipaddr.prefix = 0;
		break;

	default:
		rad_assert(0);
	}

	fr_ntop(buffer, sizeof(buffer), &client->ipaddr);
	DEBUG3("Adding client %s (%s) to prefix tree %i", buffer, client->longname, client->ipaddr.prefix);

	/*
	 *	If the client also defines a server, do that now.
	 */
	if (client->defines_coa_server) if (!realm_home_server_add(client->coa_server)) return false;

	/*
	 *	If "clients" is NULL, it means add to the global list,
	 *	unless we're trying to add it to a virtual server...
	 */
	if (!clients) {
		if (client->server != NULL) {
			CONF_SECTION *cs;
			CONF_SECTION *subcs;

			cs = cf_section_sub_find_name2(main_config.config, "server", client->server);
			if (!cs) {
				ERROR("Failed to find virtual server %s", client->server);
				return false;
			}

			/*
			 *	If this server has no "listen" section, add the clients
			 *	to the global client list.
			 */
			subcs = cf_section_sub_find(cs, "listen");
			if (!subcs) goto global_clients;

			/*
			 *	If the client list already exists, use that.
			 *	Otherwise, create a new client list.
			 */
			clients = cf_data_find(cs, "clients");
			if (!clients) {
				clients = client_list_init(cs);
				if (!clients) {
					ERROR("Out of memory");
					return false;
				}

				if (cf_data_add(cs, "clients", clients, (void (*)(void *)) client_list_free) < 0) {
					ERROR("Failed to associate clients with virtual server %s", client->server);
					client_list_free(clients);
					return false;
				}
			}

		} else {
		global_clients:
			/*
			 *	Initialize the global list, if not done already.
			 */
			if (!root_clients) {
				root_clients = client_list_init(NULL);
				if (!root_clients) return false;
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
			return false;
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
			return true;
		}

		ERROR("Failed to add duplicate client %s", client->shortname);
		return false;
	}
#undef namecmp

	/*
	 *	Other error adding client: likely is fatal.
	 */
	if (!rbtree_insert(clients->trees[client->ipaddr.prefix], client)) {
		return false;
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
	 *	us.  The client_afrom_request() function sets it AFTER
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

	return true;
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
static uint32_t cl_netmask;
static char const *cl_srcipaddr = NULL;
static char const *hs_proto = NULL;

#ifdef WITH_TCP
static CONF_PARSER limit_config[] = {
	{ "max_connections", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.max_connections),   "16" },

	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.lifetime),   "0" },

	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, RADCLIENT, limit.idle_timeout), "30" },

	CONF_PARSER_TERMINATOR
};
#endif

static const CONF_PARSER client_config[] = {
	{ "ipaddr", FR_CONF_POINTER(PW_TYPE_COMBO_IP_PREFIX, &cl_ipaddr), NULL },
	{ "ipv4addr", FR_CONF_POINTER(PW_TYPE_IPV4_PREFIX, &cl_ipaddr), NULL },
	{ "ipv6addr", FR_CONF_POINTER(PW_TYPE_IPV6_PREFIX, &cl_ipaddr), NULL },

	{ "netmask", FR_CONF_POINTER(PW_TYPE_INTEGER, &cl_netmask), NULL },

	{ "src_ipaddr", FR_CONF_POINTER(PW_TYPE_STRING, &cl_srcipaddr), NULL },

	{ "require_message_authenticator",  FR_CONF_OFFSET(PW_TYPE_BOOLEAN, RADCLIENT, message_authenticator), "no" },

	{ "secret", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, RADCLIENT, secret), NULL },
	{ "shortname", FR_CONF_OFFSET(PW_TYPE_STRING, RADCLIENT, shortname), NULL },

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

	CONF_PARSER_TERMINATOR
};

/** Create the linked list of clients from the new configuration type
 *
 */
#ifdef WITH_TLS
RADCLIENT_LIST *client_list_parse_section(CONF_SECTION *section, bool tls_required)
#else
RADCLIENT_LIST *client_list_parse_section(CONF_SECTION *section, UNUSED bool tls_required)
#endif
{
	bool		global = false, in_server = false;
	CONF_SECTION	*cs;
	RADCLIENT	*c = NULL;
	RADCLIENT_LIST	*clients = NULL;

	/*
	 *	Be forgiving.  If there's already a clients, return
	 *	it.  Otherwise create a new one.
	 */
	clients = cf_data_find(section, "clients");
	if (clients) return clients;

	clients = client_list_init(section);
	if (!clients) return NULL;

	if (cf_top_section(section) == section) global = true;

	if (strcmp("server", cf_section_name1(section)) == 0) in_server = true;

	for (cs = cf_subsection_find_next(section, NULL, "client");
	     cs;
	     cs = cf_subsection_find_next(section, cs, "client")) {
		c = client_afrom_cs(cs, cs, in_server, false);
		if (!c) {
		error:
			client_free(c);
			client_list_free(clients);
			return NULL;
		}

#ifdef WITH_TLS
		/*
		 *	TLS clients CANNOT use non-TLS listeners.
		 *	non-TLS clients CANNOT use TLS listeners.
		 */
		if (tls_required != c->tls_required) {
			cf_log_err_cs(cs, "Client does not have the same TLS configuration as the listener");
			goto error;
		}
#endif

		/*
		 *	FIXME: Add the client as data via cf_data_add,
		 *	for migration issues.
		 */

#ifdef WITH_DYNAMIC_CLIENTS
#ifdef HAVE_DIRENT_H
		if (c->client_server) {
			char const	*value;
			CONF_PAIR	*cp;
			DIR		*dir;
			struct dirent	*dp;
			struct stat	stat_buf;
			char		buf2[2048];

			/*
			 *	Find the directory where individual
			 *	client definitions are stored.
			 */
			cp = cf_pair_find(cs, "directory");
			if (!cp) goto add_client;

			value = cf_pair_value(cp);
			if (!value) {
				cf_log_err_cs(cs, "The \"directory\" entry must not be empty");
				goto error;
			}

			DEBUG("including dynamic clients in %s", value);

			dir = opendir(value);
			if (!dir) {
				cf_log_err_cs(cs, "Error reading directory %s: %s", value, fr_syserror(errno));
				goto error;
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

				snprintf(buf2, sizeof(buf2), "%s/%s", value, dp->d_name);

				if ((stat(buf2, &stat_buf) != 0) || S_ISDIR(stat_buf.st_mode)) continue;

				dc = client_read(buf2, in_server, true);
				if (!dc) {
					cf_log_err_cs(cs, "Failed reading client file \"%s\"", buf2);
					closedir(dir);
					goto error;
				}

				/*
				 *	Validate, and add to the list.
				 */
				if (!client_add_dynamic(clients, c, dc)) {
					closedir(dir);
					goto error;
				}
			} /* loop over the directory */
			closedir(dir);
		}
#endif /* HAVE_DIRENT_H */

	add_client:
#endif /* WITH_DYNAMIC_CLIENTS */
		if (!client_add(clients, c)) {
			cf_log_err_cs(cs, "Failed to add client %s", cf_section_name2(cs));
			goto error;
		}

	}

	/*
	 *	Associate the clients structure with the section.
	 */
	if (cf_data_add(section, "clients", clients, NULL) < 0) {
		cf_log_err_cs(section, "Failed to associate clients with section %s", cf_section_name1(section));
		client_list_free(clients);
		return NULL;
	}

	/*
	 *	Replace the global list of clients with the new one.
	 *	The old one is still referenced from the original
	 *	configuration, and will be freed when that is freed.
	 */
	if (global) root_clients = clients;

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

	CONF_PARSER_TERMINATOR
};

/** Add a dynamic client
 *
 */
bool client_add_dynamic(RADCLIENT_LIST *clients, RADCLIENT *master, RADCLIENT *c)
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
	if (master->server && (strcmp(master->server, c->server) != 0)) {
		ERROR("Cannot add client %s/%i: Virtual server %s is not the same as the virtual server for the network",
		      ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)), c->ipaddr.prefix, c->server);

		goto error;
	}

	if (!client_add(clients, c)) {
		ERROR("Cannot add client %s/%i: Internal error",
		      ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)), c->ipaddr.prefix);

		goto error;
	}

	/*
	 *	Initialize the remaining fields.
	 */
	c->dynamic = true;
	c->lifetime = master->lifetime;
	c->created = time(NULL);
	c->longname = talloc_typed_strdup(c, c->shortname);

	if (rad_debug_lvl <= 2) {
		INFO("Adding client %s/%i",
		     ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)), c->ipaddr.prefix);
	} else {
		INFO("Adding client %s/%i with shared secret \"%s\"",
		     ip_ntoh(&c->ipaddr, buffer, sizeof(buffer)), c->ipaddr.prefix, c->secret);
	}
	return true;

error:
	client_free(c);
	return false;
}

/** Create a client CONF_SECTION using a mapping section to map values from a result set to client attributes
 *
 * If we hit a CONF_SECTION we recurse and process its CONF_PAIRS too.
 *
 * @note Caller should free CONF_SECTION passed in as out, on error.
 *	 Contents of that section will be in an undefined state.
 *
 * @param[in,out] out Section to perform mapping on. Either the root of the client config, or a parent section
 *	(when this function is called recursively).
 *	Should be alloced with cf_section_alloc, or if there's a separate template section, the
 *	result of calling cf_section_dup on that section.
 * @param[in] map section.
 * @param[in] func to call to retrieve CONF_PAIR values. Must return a talloced buffer containing the value.
 * @param[in] data to pass to func, usually a result pointer.
 * @return 0 on success else -1 on error.
 */
int client_map_section(CONF_SECTION *out, CONF_SECTION const *map, client_value_cb_t func, void *data)
{
	CONF_ITEM const *ci;

	for (ci = cf_item_find_next(map, NULL);
	     ci != NULL;
	     ci = cf_item_find_next(map, ci)) {
	     	CONF_PAIR const *cp;
	     	CONF_PAIR *old;
	     	char *value;
		char const *attr;

		/*
		 *	Recursively process map subsection
		 */
		if (cf_item_is_section(ci)) {
			CONF_SECTION *cs, *cc;

			cs = cf_item_to_section(ci);
			/*
			 *	Use pre-existing section or alloc a new one
			 */
			cc = cf_section_sub_find_name2(out, cf_section_name1(cs), cf_section_name2(cs));
			if (!cc) {
				cc = cf_section_alloc(out, cf_section_name1(cs), cf_section_name2(cs));
				cf_section_add(out, cc);
				if (!cc) return -1;
			}

			if (client_map_section(cc, cs, func, data) < 0) return -1;
			continue;
		}

		cp = cf_item_to_pair(ci);
		attr = cf_pair_attr(cp);

		/*
		 *	The callback can return 0 (success) and not provide a value
		 *	in which case we skip the mapping pair.
		 *
		 *	Or return -1 in which case we error out.
		 */
		if (func(&value, cp, data) < 0) {
			cf_log_err_cs(out, "Failed performing mapping \"%s\" = \"%s\"", attr, cf_pair_value(cp));
			return -1;
		}
		if (!value) continue;

		/*
		 *	Replace an existing CONF_PAIR
		 */
		old = cf_pair_find(out, attr);
		if (old) {
			cf_pair_replace(out, old, value);
			talloc_free(value);
			continue;
		}

		/*
		 *	...or add a new CONF_PAIR
		 */
		cp = cf_pair_alloc(out, attr, value, T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
		if (!cp) {
			cf_log_err_cs(out, "Failed allocing pair \"%s\" = \"%s\"", attr, value);
			talloc_free(value);
			return -1;
		}
		talloc_free(value);
		cf_item_add(out, cf_pair_to_item(cp));
	}

	return 0;
}

/** Allocate a new client from a config section
 *
 * @param ctx to allocate new clients in.
 * @param cs to process as a client.
 * @param in_server Whether the client should belong to a specific virtual server.
 * @param with_coa If true and coa_server or coa_pool aren't specified automatically,
 *	create a coa home_server section and add it to the client CONF_SECTION.
 * @return new RADCLIENT struct.
 */
RADCLIENT *client_afrom_cs(TALLOC_CTX *ctx, CONF_SECTION *cs, bool in_server, bool with_coa)
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
	c = talloc_zero(ctx, RADCLIENT);
	c->cs = cs;

	memset(&cl_ipaddr, 0, sizeof(cl_ipaddr));
	cl_netmask = 255;

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
	 *	Allow the old method to specify "netmask".  Just using "1.2.3.4" means it's a /32.
	 */
	if (cl_netmask != 255) {
		if ((cl_ipaddr.prefix != cl_netmask) &&
		    (((cl_ipaddr.af == AF_INET) && cl_ipaddr.prefix != 32) ||
		     ((cl_ipaddr.af == AF_INET6) && cl_ipaddr.prefix != 128))) {
			cf_log_err_cs(cs, "Clients cannot use 'ipaddr/mask' and 'netmask' at the same time.");
			goto error;
		}

		cl_ipaddr.prefix = cl_netmask;
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
		WARN("No 'ipaddr' or 'ipv4addr' or 'ipv6addr' field found in client %s. "
		     "Please fix your configuration", name2);
		WARN("Support for old-style clients will be removed in a future release");

#ifdef WITH_TCP
		if (cf_pair_find(cs, "proto") != NULL) {
			cf_log_err_cs(cs, "Cannot use 'proto' inside of old-style client definition");
			goto error;
		}
#endif
		if (fr_pton(&c->ipaddr, name2, -1, AF_UNSPEC, true) < 0) {
			cf_log_err_cs(cs, "Failed parsing client name \"%s\" as ip address or hostname: %s", name2,
				      fr_strerror());
			goto error;
		}

		c->longname = talloc_typed_strdup(c, name2);
		if (!c->shortname) c->shortname = talloc_typed_strdup(c, c->longname);
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
			if (fr_pton4(&c->src_ipaddr, cl_srcipaddr, -1, true, false) < 0) {
				cf_log_err_cs(cs, "Failed parsing src_ipaddr: %s", fr_strerror());
				goto error;
			}
			break;

		case AF_INET6:
			if (fr_pton6(&c->src_ipaddr, cl_srcipaddr, -1, true, false) < 0) {
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
			cf_log_err_cs(cs, "secret must be at least 1 character long");
			goto error;
		}
	}

#ifdef WITH_COA
	{
		CONF_PAIR *cp;

		/*
		 *	Point the client to the home server pool, OR to the
		 *	home server.  This gets around the problem of figuring
		 *	out which port to use.
		 */
		cp = cf_pair_find(cs, "coa_server");
		if (cp) {
			c->coa_name = cf_pair_value(cp);
			c->coa_pool = home_pool_byname(c->coa_name, HOME_TYPE_COA);
			if (!c->coa_pool) {
				c->coa_server = home_server_byname(c->coa_name, HOME_TYPE_COA);
			}
			if (!c->coa_pool && !c->coa_server) {
				cf_log_err_cs(cs, "No such home_server or home_server_pool \"%s\"", c->coa_name);
				goto error;
			}
		/*
		 *	If we're implicitly adding a CoA home server for
		 *	every client, or there's a server subsection,
		 *	create a home server CONF_SECTION and then parse
		 *	it into a home_server_t.
		 */
		} else if (with_coa || cf_section_sub_find(cs, "coa_server")) {
			CONF_SECTION *server;
			home_server_t *home;

			if (((c->ipaddr.af == AF_INET) && (c->ipaddr.prefix != 32)) ||
			    ((c->ipaddr.af == AF_INET6) && (c->ipaddr.prefix != 128))) {
			 	WARN("Subnets not supported for home servers.  "
			 	     "Not adding client %s as home_server", name2);
				goto done_coa;
			}

			server = home_server_cs_afrom_client(cs);
			if (!server) goto error;

			/*
			 *	Must be allocated in the context of the client,
			 *	as allocating using the context of the
			 *	realm_config_t without a mutex, by one of the
			 *	workers, would be bad.
			 */
			home = home_server_afrom_cs(NULL, NULL, server);
			if (!home) {
				talloc_free(server);
				goto error;
			}

			rad_assert(home->type == HOME_TYPE_COA);

			c->coa_server = home;
			c->defines_coa_server = true;
		}
	}
done_coa:
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

/** Add a client from a result set (SQL)
 *
 * @todo This function should die. SQL should use client_afrom_cs.
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
RADCLIENT *client_afrom_query(TALLOC_CTX *ctx, char const *identifier, char const *secret,
			      char const *shortname, char const *type, char const *server, bool require_ma)
{
	RADCLIENT *c;
	char buffer[128];

	c = talloc_zero(ctx, RADCLIENT);

	if (fr_pton(&c->ipaddr, identifier, -1, AF_UNSPEC, true) < 0) {
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

/** Create a new client, consuming all attributes in the control list of the request
 *
 * @param clients list to add new client to.
 * @param request Fake request.
 * @return a new client on success, else NULL on error.
 */
RADCLIENT *client_afrom_request(RADCLIENT_LIST *clients, REQUEST *request)
{
	static int	cnt;
	int		i, *pi;
	char		**p;
	RADCLIENT	*c;
	CONF_PAIR	*cp = NULL;
	char		buffer[128];

	vp_cursor_t	cursor;
	VALUE_PAIR	*vp = NULL;

	if (!clients || !request) return NULL;

	snprintf(buffer, sizeof(buffer), "dynamic%i", cnt++);

	c = talloc_zero(clients, RADCLIENT);
	c->cs = cf_section_alloc(NULL, "client", buffer);
	talloc_steal(c, c->cs);
	c->ipaddr.af = AF_UNSPEC;
	c->src_ipaddr.af = AF_UNSPEC;

	fr_cursor_init(&cursor, &request->config);

	RDEBUG2("Converting control list to client fields");
	RINDENT();
	for (i = 0; dynamic_config[i].name != NULL; i++) {
		DICT_ATTR const *da;
		char *strvalue = NULL;

		da = dict_attrbyname(dynamic_config[i].name);
		if (!da) {
			RERROR("Cannot add client %s: attribute \"%s\" is not in the dictionary",
			       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)),
			       dynamic_config[i].name);
		error:
			REXDENT();
			talloc_free(vp);
			client_free(c);
			return NULL;
		}

		fr_cursor_first(&cursor);
		if (!fr_cursor_next_by_da(&cursor, da, TAG_ANY)) {
			/*
			 *	Not required.  Skip it.
			 */
			if (!dynamic_config[i].dflt) continue;

			RERROR("Cannot add client %s: Required attribute \"%s\" is missing",
			       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)),
			       dynamic_config[i].name);
			goto error;
		}
		vp = fr_cursor_remove(&cursor);

		/*
		 *	Freed at the same time as the vp.
		 */
		strvalue = vp_aprints_value(vp, vp, '\'');

		switch (dynamic_config[i].type) {
		case PW_TYPE_IPV4_ADDR:
			if (da->attr == PW_FREERADIUS_CLIENT_IP_ADDRESS) {
				c->ipaddr.af = AF_INET;
				c->ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				c->ipaddr.prefix = 32;
				cp = cf_pair_alloc(c->cs, "ipv4addr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			} else if (da->attr == PW_FREERADIUS_CLIENT_SRC_IP_ADDRESS) {
#ifdef WITH_UDPFROMTO
				RDEBUG2("src_ipaddr = %s", strvalue);
				c->src_ipaddr.af = AF_INET;
				c->src_ipaddr.ipaddr.ip4addr.s_addr = vp->vp_ipaddr;
				c->src_ipaddr.prefix = 32;
				cp = cf_pair_alloc(c->cs, "src_ipaddr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
#else
				RWARN("Server not built with udpfromto, ignoring FreeRADIUS-Client-Src-IP-Address");
#endif
			}

			break;

		case PW_TYPE_IPV6_ADDR:
			if (da->attr == PW_FREERADIUS_CLIENT_IPV6_ADDRESS) {
				c->ipaddr.af = AF_INET6;
				c->ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				c->ipaddr.prefix = 128;
				cp = cf_pair_alloc(c->cs, "ipv6addr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			} else if (da->attr == PW_FREERADIUS_CLIENT_SRC_IPV6_ADDRESS) {
#ifdef WITH_UDPFROMTO
				c->src_ipaddr.af = AF_INET6;
				c->src_ipaddr.ipaddr.ip6addr = vp->vp_ipv6addr;
				c->src_ipaddr.prefix = 128;
				cp = cf_pair_alloc(c->cs, "src_addr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
#else
				RWARN("Server not built with udpfromto, ignoring FreeRADIUS-Client-Src-IPv6-Address");
#endif
			}

			break;

		case PW_TYPE_IPV4_PREFIX:
			if (da->attr == PW_FREERADIUS_CLIENT_IP_PREFIX) {
				c->ipaddr.af = AF_INET;
				memcpy(&c->ipaddr.ipaddr.ip4addr, &vp->vp_ipv4prefix[2],
				       sizeof(c->ipaddr.ipaddr.ip4addr.s_addr));
				fr_ipaddr_mask(&c->ipaddr, (vp->vp_ipv4prefix[1] & 0x3f));
				cp = cf_pair_alloc(c->cs, "ipv4addr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			}

			break;

		case PW_TYPE_IPV6_PREFIX:
			if (da->attr == PW_FREERADIUS_CLIENT_IPV6_PREFIX) {
				c->ipaddr.af = AF_INET6;
				memcpy(&c->ipaddr.ipaddr.ip6addr, &vp->vp_ipv6prefix[2],
				       sizeof(c->ipaddr.ipaddr.ip6addr));
				fr_ipaddr_mask(&c->ipaddr, vp->vp_ipv6prefix[1]);
				cp = cf_pair_alloc(c->cs, "ipv6addr", strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
			}

			break;

		case PW_TYPE_STRING:
		{
			CONF_PARSER const *parse;

			/*
			 *	Cache pointer to CONF_PAIR buffer in RADCLIENT struct
			 */
			p = (char **) ((char *) c + dynamic_config[i].offset);
			if (*p) TALLOC_FREE(*p);
			if (!vp->vp_strvalue[0]) break;

			/*
			 *	We could reuse the CONF_PAIR buff, this just keeps things
			 *	consistent between client_afrom_cs, and client_afrom_query.
			 */
			*p = talloc_strdup(c, strvalue);

			/*
			 *	This is fairly nasty... In order to figure out the CONF_PAIR
			 *	name associated with a field, find offsets that match between
			 *	the dynamic_config CONF_PARSER table, and the client_config
			 *	CONF_PARSER table.
			 *
			 *	This is so that things that expect to find CONF_PAIRs in the
			 *	client CONF_SECTION for fields like 'nas_type' can.
			 */
			for (parse = client_config; parse->name; parse++) {
				if (parse->offset == dynamic_config[i].offset) break;
			}

			if (!parse) break;

			cp = cf_pair_alloc(c->cs, parse->name, strvalue, T_OP_SET, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
		}
			break;

		case PW_TYPE_BOOLEAN:
		{
			CONF_PARSER const *parse;

			pi = (int *) ((bool *) ((char *) c + dynamic_config[i].offset));
			*pi = vp->vp_integer;

			/*
			 *	Same nastiness as above.
			 */
			for (parse = client_config; parse->name; parse++) {
				if (parse->offset == dynamic_config[i].offset) break;
			}
			if (!parse) break;

			cp = cf_pair_alloc(c->cs, parse->name, strvalue, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
		}
			break;

		default:
			goto error;
		}

		if (!cp) {
			RERROR("Error creating equivalent conf pair for %s", vp->da->name);
			goto error;
		}

		if (cf_pair_attr_type(cp) == T_SINGLE_QUOTED_STRING) {
			RDEBUG2("%s = '%s'", cf_pair_attr(cp), cf_pair_value(cp));
		} else {
			RDEBUG2("%s = %s", cf_pair_attr(cp), cf_pair_value(cp));
		}
		cf_pair_add(c->cs, cp);

		talloc_free(vp);
	}

	fr_cursor_first(&cursor);
	vp = fr_cursor_remove(&cursor);
	if (vp) {
		do {
			char *value;

			value = vp_aprints_value(vp, vp, '\'');
			if (!value) {
				ERROR("Failed stringifying value of &control:%s", vp->da->name);
				goto error;
			}

			if (vp->da->type == PW_TYPE_STRING) {
				RDEBUG2("%s = '%s'", vp->da->name, value);
				cp = cf_pair_alloc(c->cs, vp->da->name, value, T_OP_SET,
						   T_BARE_WORD, T_SINGLE_QUOTED_STRING);
			} else {
				RDEBUG2("%s = %s", vp->da->name, value);
				cp = cf_pair_alloc(c->cs, vp->da->name, value, T_OP_SET,
						   T_BARE_WORD, T_BARE_WORD);
			}
			cf_pair_add(c->cs, cp);

			talloc_free(vp);
		} while ((vp = fr_cursor_remove(&cursor)));
	}
	REXDENT();

	if (c->ipaddr.af == AF_UNSPEC) {
		RERROR("Cannot add client %s: No IP address was specified.",
		       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)));

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

			RERROR("Cannot add client %s: Not in specified subnet %s/%i",
			       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)),
			       ip_ntoh(&c->ipaddr, buf2, sizeof(buf2)), c->ipaddr.prefix);
			goto error;
		}
	}

	if (!c->secret || !*c->secret) {
		RERROR("Cannot add client %s: No secret was specified",
		       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)));
		goto error;
	}

	if (!client_add_dynamic(clients, request->client, c)) {
		return NULL;
	}

	if ((c->src_ipaddr.af != AF_UNSPEC) && (c->src_ipaddr.af != c->ipaddr.af)) {
		RERROR("Cannot add client %s: Client IP and src address are different IP version",
		       ip_ntoh(&request->packet->src_ipaddr, buffer, sizeof(buffer)));

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

	cs = cf_section_alloc(NULL, "main", NULL);
	if (!cs) return NULL;

	if (cf_file_read(cs, filename) < 0) {
		talloc_free(cs);
		return NULL;
	}

	cs = cf_section_sub_find(cs, "client");
	if (!cs) {
		ERROR("No \"client\" section found in client file");
		return NULL;
	}

	c = client_afrom_cs(cs, cs, in_server, false);
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
		ERROR("Invalid client definition in %s: IP address %s does not match name %s", filename, buffer, p);
		client_free(c);
		return NULL;
	}

	return c;
}
#endif

