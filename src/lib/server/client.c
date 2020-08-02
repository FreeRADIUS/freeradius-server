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
 * @file src/lib/server/client.c
 * @brief Manage clients allowed to communicate with the server.
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2000,2006 The FreeRADIUS server project
 * @copyright 2000 Alan DeKok (aland@freeradius.org)
 * @copyright 2000 Miquel van Smoorenburg (miquels@cistron.nl)
 */
RCSID("$Id$")

#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/server/cf_file.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/client.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/virtual_servers.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/trie.h>

#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>

//#define WITH_TRIE (1)

/** Group of clients
 *
 */
struct rad_client_list {
	char const	*name;			//!< Name of the client list.
#ifdef WITH_TRIE
	fr_trie_t	*v4_udp;
	fr_trie_t	*v6_udp;
	fr_trie_t	*v4_tcp;
	fr_trie_t	*v6_tcp;
#else
	rbtree_t	*tree[129];
#endif
};

static RADCLIENT_LIST	*root_clients = NULL;	//!< Global client list.

#ifndef WITH_TRIE
static int client_cmp(void const *one, void const *two)
{
	int rcode;
	RADCLIENT const *a = one;
	RADCLIENT const *b = two;

	rcode = fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
	if (rcode != 0) return rcode;

	/*
	 *	0 is "wildcard", or "both" protocols
	 */
	if ((a->proto == IPPROTO_IP) || (b->proto == IPPROTO_IP)) return 0;

	return a->proto - b->proto;
}

#endif

void client_list_free(void)
{
	TALLOC_FREE(root_clients);
}

/** Free a client
 *
 *  It's up to the caller to ensure that it's deleted from any RADCLIENT_LIST.
 */
void client_free(RADCLIENT *client)
{
	if (!client) return;

	talloc_free(client);
}

/** Return a new client list
 *
 * @note The container won't contain any clients.
 *
 * @return
 *	- New client list on success.
 *	- NULL on error (OOM).
 */
RADCLIENT_LIST *client_list_init(CONF_SECTION *cs)
{
	RADCLIENT_LIST *clients = talloc_zero(cs, RADCLIENT_LIST);

	if (!clients) return NULL;

	clients->name = talloc_strdup(clients, cs ? cf_section_name1(cs) : "root");

#ifdef WITH_TRIE
	clients->v4_udp = fr_trie_alloc(clients);
	if (!clients->v4_udp) {
		talloc_free(clients);
		return NULL;
	}

	clients->v6_udp = fr_trie_alloc(clients);
	if (!clients->v6_udp) {
		talloc_free(clients);
		return NULL;
	}

	clients->v4_tcp = fr_trie_alloc(clients);
	if (!clients->v4_tcp) {
		talloc_free(clients);
		return NULL;
	}

	clients->v6_tcp = fr_trie_alloc(clients);
	if (!clients->v6_tcp) {
		talloc_free(clients);
		return NULL;
	}
#endif	/* WITH_TRIE */

	return clients;
}

#ifdef WITH_TRIE
/*
 *	@todo - either support client definitions where "proto = *",
 *	or udpate this code to allow for that.  i.e. we create yet
 *	another set of v4/v6 tries, for "proto = *" clients.  And then
 *	do lookups there, too.  Or, just unify the udp/tcp tries, and
 *	instead do post-processing?  Though those two clients can have
 *	different secrets... and the trie code doesn't allow 2
 *	fr_trie_user_t nodes in a row.  So we would have to instead
 *	handle that ourselves, with a wrapper around the RADCLIENT
 *	structure that does udp/tcp/wildcard demultiplexing
 */
static fr_trie_t *clients_trie(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr,
			       int proto)
{
	if (ipaddr->af == AF_INET) {
		if (proto == IPPROTO_TCP) return clients->v4_tcp;

		return clients->v4_udp;
	}

	fr_assert(ipaddr->af == AF_INET6);

	if (proto == IPPROTO_TCP) return clients->v6_tcp;

	return clients->v6_udp;
}
#endif	/* WITH_TRIE */

/** Add a client to a RADCLIENT_LIST
 *
 * @param clients list to add client to, may be NULL if global client list is being used.
 * @param client to add.
 * @return
 *	- true on success.
 *	- false on failure.
 */
bool client_add(RADCLIENT_LIST *clients, RADCLIENT *client)
{
#ifdef WITH_TRIE
	fr_trie_t *trie;
#else
#endif
	RADCLIENT *old;
	char buffer[FR_IPADDR_PREFIX_STRLEN];

	if (!client) return false;

	/*
	 *	Hack to fixup wildcard clients
	 *
	 *	If the IP is all zeros, with a 32 or 128 bit netmask
	 *	assume the user meant to configure 0.0.0.0/0 instead
	 *	of 0.0.0.0/32 - which would require the src IP of
	 *	the client to be all zeros.
	 */
	if (fr_ipaddr_is_inaddr_any(&client->ipaddr) == 1) switch (client->ipaddr.af) {
	case AF_INET:
		if (client->ipaddr.prefix == 32) client->ipaddr.prefix = 0;
		break;

	case AF_INET6:
		if (client->ipaddr.prefix == 128) client->ipaddr.prefix = 0;
		break;

	default:
		fr_assert(0);
	}

	fr_inet_ntop_prefix(buffer, sizeof(buffer), &client->ipaddr);
	DEBUG3("Adding client %s (%s) to prefix tree %i", buffer, client->longname, client->ipaddr.prefix);

	/*
	 *	If "clients" is NULL, it means add to the global list,
	 *	unless we're trying to add it to a virtual server...
	 */
	if (!clients) {
		if (client->server != NULL) {
			CONF_SECTION *cs;
			CONF_SECTION *subcs;

			if (!client->cs) {
				ERROR("Failed to find configuration section in client.  Ignoring 'virtual_server' directive");
				return false;
			}

			cs = cf_section_find(cf_root(client->cs), "server", client->server);
			if (!cs) {
				ERROR("Failed to find virtual server %s", client->server);
				return false;
			}

			/*
			 *	If this server has no "listen" section, add the clients
			 *	to the global client list.
			 */
			subcs = cf_section_find(cs, "listen", NULL);
			if (!subcs) goto global_clients;

			/*
			 *	If the client list already exists, use that.
			 *	Otherwise, create a new client list.
			 */
			clients = cf_data_value(cf_data_find(cs, RADCLIENT_LIST, NULL));
			if (!clients) {
				clients = client_list_init(cs);
				if (!clients) {
					ERROR("Out of memory");
					return false;
				}

				if (!cf_data_add(cs, clients, NULL, true)) {
					ERROR("Failed to associate clients with virtual server %s", client->server);
					talloc_free(clients);
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

#define namecmp(a) ((!old->a && !client->a) || (old->a && client->a && (strcmp(old->a, client->a) == 0)))

#ifdef WITH_TRIE
	trie = clients_trie(clients, &client->ipaddr, client->proto);

	/*
	 *	Cannot insert the same client twice.
	 */
	old = fr_trie_match(trie, &client->ipaddr.addr, client->ipaddr.prefix);

#else  /* WITH_TRIE */

	if (!clients->tree[client->ipaddr.prefix]) {
		clients->tree[client->ipaddr.prefix] = rbtree_talloc_alloc(clients, client_cmp, RADCLIENT,
									    NULL, RBTREE_FLAG_NONE);
		if (!clients->tree[client->ipaddr.prefix]) {
			return false;
		}
	}

	old = rbtree_finddata(clients->tree[client->ipaddr.prefix], client);
#endif
	if (old) {
		/*
		 *	If it's a complete duplicate, then free the new
		 *	one, and return "OK".
		 */
		if (namecmp(longname) && namecmp(secret) &&
		    namecmp(shortname) && namecmp(nas_type) &&
		    namecmp(server) &&
		    (old->message_authenticator == client->message_authenticator)) {
			WARN("Ignoring duplicate client %s", client->longname);
			client_free(client);
			return true;
		}

		ERROR("Failed to add duplicate client %s", client->shortname);
		client_free(client);
		return false;
	}
#undef namecmp

#ifdef WITH_TRIE
	/*
	 *	Other error adding client: likely is fatal.
	 */
	if (fr_trie_insert(trie, &client->ipaddr.addr, client->ipaddr.prefix, client) < 0) {
		client_free(client);
		return false;
	}
#else
	if (!rbtree_insert(clients->tree[client->ipaddr.prefix], client)) {
		client_free(client);
		return false;
	}
#endif

	/*
	 *	@todo - do we want to do this for dynamic clients?
	 */
	(void) talloc_steal(clients, client); /* reparent it */

	return true;
}


void client_delete(RADCLIENT_LIST *clients, RADCLIENT *client)
{
#ifdef WITH_TRIE
	fr_trie_t *trie;
#endif

	if (!client) return;

	if (!clients) clients = root_clients;

	fr_assert(client->ipaddr.prefix <= 128);

#ifdef WITH_TRIE
	trie = clients_trie(clients, &client->ipaddr, client->proto);

	/*
	 *	Don't free the client.  The caller is responsible for that.
	 */
	(void) fr_trie_remove(trie, &client->ipaddr.addr, client->ipaddr.prefix);
#else

	if (!clients->tree[client->ipaddr.prefix]) return;

	(void) rbtree_deletebydata(clients->tree[client->ipaddr.prefix], client);
#endif
}

RADCLIENT *client_findbynumber(UNUSED const RADCLIENT_LIST *clients, UNUSED int number)
{
	return NULL;
}


/*
 *	Find a client in the RADCLIENTS list.
 */
RADCLIENT *client_find(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr, int proto)
{
#ifdef WITH_TRIE
	fr_trie_t *trie;
#else
	int i, max;
	RADCLIENT my_client, *client;
#endif

	if (!clients) clients = root_clients;

	if (!clients || !ipaddr) return NULL;

#ifdef WITH_TRIE
	trie = clients_trie(clients, ipaddr, proto);

	return fr_trie_lookup(trie, &ipaddr->addr, ipaddr->prefix);
#else

	if (proto == AF_INET) {
		max = 32;
	} else {
		max = 128;
	}

	if (max > ipaddr->prefix) max = ipaddr->prefix;

	my_client.proto = proto;
	for (i = max; i >= 0; i--) {
		if (!clients->tree[i]) continue;

		my_client.ipaddr = *ipaddr;
		fr_ipaddr_mask(&my_client.ipaddr, i);
		client = rbtree_finddata(clients->tree[i], &my_client);
		if (client) {
			return client;
		}
	}

	return NULL;
#endif
}

static fr_ipaddr_t cl_ipaddr;
static char const *cl_srcipaddr = NULL;
static char const *hs_proto = NULL;

static CONF_PARSER limit_config[] = {
	{ FR_CONF_OFFSET("max_connections", FR_TYPE_UINT32, RADCLIENT, limit.max_connections), .dflt = "16" },

	{ FR_CONF_OFFSET("lifetime", FR_TYPE_UINT32, RADCLIENT, limit.lifetime), .dflt = "0" },

	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_UINT32, RADCLIENT, limit.idle_timeout), .dflt = "30" },
	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER client_config[] = {
	{ FR_CONF_POINTER("ipaddr", FR_TYPE_COMBO_IP_PREFIX, &cl_ipaddr) },
	{ FR_CONF_POINTER("ipv4addr", FR_TYPE_IPV4_PREFIX, &cl_ipaddr) },
	{ FR_CONF_POINTER("ipv6addr", FR_TYPE_IPV6_PREFIX, &cl_ipaddr) },

	{ FR_CONF_POINTER("src_ipaddr", FR_TYPE_STRING, &cl_srcipaddr) },

	{ FR_CONF_OFFSET("require_message_authenticator", FR_TYPE_BOOL, RADCLIENT, message_authenticator), .dflt = "no" },

	{ FR_CONF_OFFSET("secret", FR_TYPE_STRING | FR_TYPE_SECRET, RADCLIENT, secret) },
	{ FR_CONF_OFFSET("shortname", FR_TYPE_STRING, RADCLIENT, shortname) },

	{ FR_CONF_OFFSET("nas_type", FR_TYPE_STRING, RADCLIENT, nas_type) },

	{ FR_CONF_OFFSET("virtual_server", FR_TYPE_STRING, RADCLIENT, server) },
	{ FR_CONF_OFFSET("response_window", FR_TYPE_TIME_DELTA, RADCLIENT, response_window) },

	{ FR_CONF_OFFSET("track_connections", FR_TYPE_BOOL, RADCLIENT, use_connected) },

	{ FR_CONF_POINTER("proto", FR_TYPE_STRING, &hs_proto) },
	{ FR_CONF_POINTER("limit", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) limit_config },

	CONF_PARSER_TERMINATOR
};

/** Create a list of clients from a client section
 *
 * Iterates over all client definitions in the specified section, adding them to a client list.
 */
#ifdef WITH_TLS
#define TLS_UNUSED
#else
#define TLS_UNUSED UNUSED
#endif

RADCLIENT_LIST *client_list_parse_section(CONF_SECTION *section, int proto, TLS_UNUSED bool tls_required)
{
	bool		global = false;
	CONF_SECTION	*cs = NULL;
	RADCLIENT	*c = NULL;
	RADCLIENT_LIST	*clients = NULL;
	CONF_SECTION	*server_cs = NULL;

	/*
	 *	Be forgiving.  If there's already a clients, return
	 *	it.  Otherwise create a new one.
	 */
	clients = cf_data_value(cf_data_find(section, RADCLIENT_LIST, NULL));
	if (clients) return clients;

	/*
	 *	Parent the client list from the section.
	 */
	clients = client_list_init(section);
	if (!clients) return NULL;

	/*
	 *	If the section is hung off the config root, this is
	 *	the global client list, else it's virtual server
	 *	specific client list.
	 */
	if (cf_root(section) == section) global = true;

	if (strcmp("server", cf_section_name1(section)) == 0) server_cs = section;

	/*
	 *	Iterate over all the clients in the section, adding
	 *	them to the client list.
	 */
	while ((cs = cf_section_find_next(section, cs, "client", CF_IDENT_ANY))) {
		/*
		 *	Check this before parsing the client.
		 */
		if (proto) {
			CONF_PAIR *cp;
			int client_proto = IPPROTO_UDP;

			cp = cf_pair_find(cs, "proto");
			if (cp) {
				char const *value = cf_pair_value(cp);

				if (!value) {
					cf_log_err(cs, "'proto' field must have a value");
					talloc_free(clients);
					return NULL;
				}

				if (strcmp(value, "udp") == 0) {
					/* do nothing */

				} else if (strcmp(value, "tcp") == 0) {
					client_proto = IPPROTO_TCP;
#ifdef WITH_TLS
				} else if (strcmp(value, "tls") == 0) {
					client_proto = IPPROTO_TCP;
#endif
				} else if (strcmp(value, "*") == 0) {
					client_proto = IPPROTO_IP; /* fake for dual */
				} else {
					cf_log_err(cs, "Unknown proto \"%s\".", value);
					talloc_free(clients);
					return NULL;
				}
			}

			/*
			 *	We don't have "proto = *", so the
			 *	protocol MUST match what the caller
			 *	asked for.  Otherwise, we ignore the
			 *	client.
			 */
			if ((client_proto != IPPROTO_IP) && (proto != client_proto)) continue;
		}


		c = client_afrom_cs(cs, cs, server_cs);
		if (!c) {
		error:
			client_free(c);
			talloc_free(clients);
			return NULL;
		}

#ifdef WITH_TLS
		/*
		 *	TLS clients CANNOT use non-TLS listeners.
		 *	non-TLS clients CANNOT use TLS listeners.
		 */
		if (tls_required != c->tls_required) {
			cf_log_err(cs, "Client does not have the same TLS configuration as the listener");
			goto error;
		}
#endif

		if (!client_add(clients, c)) {
			cf_log_err(cs, "Failed to add client %s", cf_section_name2(cs));
			goto error;
		}

	}

	/*
	 *	Associate the clients structure with the section.
	 */
	if (!cf_data_add(section, clients, NULL, false)) {
		cf_log_err(section, "Failed to associate clients with section %s", cf_section_name1(section));
		talloc_free(clients);
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
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int client_map_section(CONF_SECTION *out, CONF_SECTION const *map, client_value_cb_t func, void *data)
{
	CONF_ITEM const *ci;

	for (ci = cf_item_next(map, NULL);
	     ci != NULL;
	     ci = cf_item_next(map, ci)) {
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
			cc = cf_section_find(out, cf_section_name1(cs), cf_section_name2(cs));
			if (!cc) {
				cc = cf_section_alloc(out, out, cf_section_name1(cs), cf_section_name2(cs));
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
			cf_log_err(out, "Failed performing mapping \"%s\" = \"%s\"", attr, cf_pair_value(cp));
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
			cf_log_err(out, "Failed allocing pair \"%s\" = \"%s\"", attr, value);
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
 * @param server_cs The virtual server that this client belongs to.
 * @return new RADCLIENT struct.
 */
RADCLIENT *client_afrom_cs(TALLOC_CTX *ctx, CONF_SECTION *cs, CONF_SECTION *server_cs)
{
	RADCLIENT	*c;
	char const	*name2;
	CONF_PAIR	*cp;

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err(cs, "Missing client name");
		return NULL;
	}

	/*
	 *	The size is fine.. Let's create the buffer
	 */
	c = talloc_zero(ctx, RADCLIENT);
	c->cs = cs;

	memset(&cl_ipaddr, 0, sizeof(cl_ipaddr));
	if (cf_section_rules_push(cs, client_config) < 0) return NULL;

	if (cf_section_parse(c, c, cs) < 0) {
		cf_log_err(cs, "Error parsing client section");
	error:
		client_free(c);
		hs_proto = NULL;
		cl_srcipaddr = NULL;
		return NULL;
	}

	/*
	 *	Allow for binary secrets.
	 */
	cp = cf_pair_find(cs, "secret");
	if (cp && (cf_pair_operator(cp) == T_BARE_WORD)) {
		char const *value;

		value = cf_pair_value(cp);
		if ((value[0] == '0') && (value[1] == 'x')) {
			size_t bin_len, hex_len, converted;
			uint8_t *bin;

			/*
			 *	'0x...' plus trailing NUL.
			 */
			hex_len = talloc_array_length(value) - 3;
			bin_len = (hex_len / 2) + 1;
			MEM(bin = talloc_array(c, uint8_t, bin_len));
			converted = fr_hex2bin(NULL,
					       &FR_DBUFF_TMP(bin, bin_len),
					       &FR_SBUFF_IN(value + 2, hex_len), false);
			if (converted < (bin_len - 1)) {
				cf_log_err(cs, "Invalide hex string in shared secret");
				goto error;
			}

			talloc_const_free(c->secret);
			c->secret = (char const *) bin;
		}
	}

	/*
	 *	Find the virtual server for this client.
	 */
	if (c->server) {
		if (server_cs) {
			cf_log_err(cs, "Clients inside of a 'server' section cannot point to a server");
			goto error;
		}

		c->server_cs = virtual_server_find(c->server);
		if (!c->server_cs) {
			cf_log_err(cs, "Failed to find virtual server %s", c->server);
			goto error;
		}

	} else if (server_cs) {
		c->server = cf_section_name2(server_cs);
		c->server_cs = server_cs;

	} /* else don't set c->server or c->server_cs, we will use listener->server */

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
		fr_inet_ntoh(&c->ipaddr, buffer, sizeof(buffer));
		c->longname = talloc_typed_strdup(c, buffer);

		/*
		 *	Set the short name to the name2.
		 */
		if (!c->shortname) c->shortname = talloc_typed_strdup(c, name2);
	/*
	 *	No "ipaddr" or "ipv6addr", use old-style "client <ipaddr> {" syntax.
	 */
	} else {
		cf_log_err(cs, "No 'ipaddr' or 'ipv4addr' or 'ipv6addr' configuration "
			      "directive found in client %s", name2);
		goto error;
	}

	c->proto = IPPROTO_UDP;
	if (hs_proto) {
		if (strcmp(hs_proto, "udp") == 0) {
			hs_proto = NULL;

		} else if (strcmp(hs_proto, "tcp") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_TCP;
#ifdef WITH_TLS
		} else if (strcmp(hs_proto, "tls") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_TCP;
			c->tls_required = true;

#endif
		} else if (strcmp(hs_proto, "*") == 0) {
			hs_proto = NULL;
			c->proto = IPPROTO_IP; /* fake for dual */
		} else {
			cf_log_err(cs, "Unknown proto \"%s\".", hs_proto);
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
			if (fr_inet_pton4(&c->src_ipaddr, cl_srcipaddr, -1, true, false, true) < 0) {
				cf_log_perr(cs, "Failed parsing src_ipaddr");
				goto error;
			}
			break;

		case AF_INET6:
			if (fr_inet_pton6(&c->src_ipaddr, cl_srcipaddr, -1, true, false, true) < 0) {
				cf_log_perr(cs, "Failed parsing src_ipaddr");
				goto error;
			}
			break;
		default:
			cf_log_err(cs, "ipaddr was not defined");
			goto error;
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
	if (c->response_window) {
		FR_TIME_DELTA_BOUND_CHECK("response_window", c->response_window, >=, fr_time_delta_from_usec(1000));
		FR_TIME_DELTA_BOUND_CHECK("response_window", c->response_window, <=, fr_time_delta_from_sec(60));
		FR_TIME_DELTA_BOUND_CHECK("response_window", c->response_window, <=, main_config->max_request_time);
	}

#ifdef WITH_TLS
	/*
	 *	If the client is TLS only, the secret can be
	 *	omitted.  When omitted, it's hard-coded to
	 *	"radsec".  See RFC 6614.
	 */
	if (c->tls_required) {
		c->secret = talloc_typed_strdup(cs, "radsec");
	}
#endif

	if ((c->proto == IPPROTO_TCP) || (c->proto == IPPROTO_IP)) {
		if ((c->limit.idle_timeout > 0) && (c->limit.idle_timeout < 5))
			c->limit.idle_timeout = 5;
		if ((c->limit.lifetime > 0) && (c->limit.lifetime < 5))
			c->limit.lifetime = 5;
		if ((c->limit.lifetime > 0) && (c->limit.idle_timeout > c->limit.lifetime))
			c->limit.idle_timeout = 0;
	}

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
 * @return
 *	- New client.
 *	- NULL on error.
 */
RADCLIENT *client_afrom_query(TALLOC_CTX *ctx, char const *identifier, char const *secret,
			      char const *shortname, char const *type, char const *server, bool require_ma)
{
	RADCLIENT *c;
	char buffer[128];

	c = talloc_zero(ctx, RADCLIENT);

	if (fr_inet_pton(&c->ipaddr, identifier, -1, AF_UNSPEC, true, true) < 0) {
		PERROR("Failed parsing client IP");
		talloc_free(c);

		return NULL;
	}

	fr_inet_ntoh(&c->ipaddr, buffer, sizeof(buffer));
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
 * @param ctx the talloc context
 * @param request containing the client attributes.
 * @return
 *	- New client on success.
 *	- NULL on error.
 */
RADCLIENT *client_afrom_request(TALLOC_CTX *ctx, REQUEST *request)
{
	static int	cnt;
	CONF_SECTION	*cs;
	char		src_buf[128], buffer[256];
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp;
	RADCLIENT	*c;

	if (!request) return NULL;

	fr_value_box_snprint(src_buf, sizeof(src_buf), fr_box_ipaddr(request->packet->src_ipaddr), 0);

	snprintf(buffer, sizeof(buffer), "dynamic_%i_%s", cnt++, src_buf);

	cs = cf_section_alloc(ctx, NULL, "client", buffer);

	fr_cursor_init(&cursor, &request->control);

	RDEBUG2("Converting &request:control to client {...} section");
	RINDENT();

	for (vp = fr_cursor_init(&cursor, &request->control);
	     vp != NULL;
	     vp = fr_cursor_next(&cursor)) {
		CONF_PAIR	*cp = NULL;
		char const	*value;
		char const	*attr;

		if (!fr_dict_attr_is_top_level(vp->da)) continue;

		switch (vp->da->attr) {
		case FR_FREERADIUS_CLIENT_IP_ADDRESS:
			attr = "ipv4addr";
			value = fr_inet_ntop(buffer, sizeof(buffer), &vp->vp_ip);
			break;

		case FR_FREERADIUS_CLIENT_IP_PREFIX:
			attr = "ipv4addr";
			value = fr_inet_ntop_prefix(buffer, sizeof(buffer), &vp->vp_ip);
			break;

		case FR_FREERADIUS_CLIENT_IPV6_ADDRESS:
			attr = "ipv6addr";
			value = fr_inet_ntop(buffer, sizeof(buffer), &vp->vp_ip);
			break;

		case FR_FREERADIUS_CLIENT_IPV6_PREFIX:
			attr = "ipv6addr";
			value = fr_inet_ntop_prefix(buffer, sizeof(buffer), &vp->vp_ip);
			break;

		case FR_FREERADIUS_CLIENT_SECRET:
			attr = "secret";
			value = vp->vp_strvalue;
			break;

		case FR_FREERADIUS_CLIENT_NAS_TYPE:
			attr = "nas_type";
			value = vp->vp_strvalue;
			break;

		case FR_FREERADIUS_CLIENT_SHORTNAME:
			attr = "shortname";
			value = vp->vp_strvalue;
			break;

		case FR_FREERADIUS_CLIENT_TRACK_CONNECTIONS:
			attr = "track_connections";
			if (vp->vp_bool) {
				value = "true";
			} else {
				value = "false";
			}
			break;

		default:
			RERROR("Ignoring attribute %s", vp->da->name);
			continue;
		}

		cp = cf_pair_alloc(cs, attr, value, T_OP_SET, T_BARE_WORD, T_BARE_WORD);
		if (!cp) {
			RERROR("Error creating equivalent conf pair for %s", vp->da->name);
			goto error;
		}

		RDEBUG2("%s = %s", cf_pair_attr(cp), cf_pair_value(cp));
		cf_pair_add(cs, cp);
	}

	REXDENT();

	/*
	 *	@todo - allow for setting a DIFFERENT virtual server,
	 *	src IP, protocol, etc.  This should all be in TLVs..
	 */
	c = client_afrom_cs(cs, cs, request->server_cs);
	if (!c) {
	error:
		talloc_free(cs);
		return NULL;
	}

	return c;
}

/** Read a single client from a file
 *
 * This function supports asynchronous runtime loading of clients.
 *
 * @param[in] filename		To read clients from.
 * @param[in] server_cs		of virtual server clients should be added to.
 * @param[in] check_dns		Check reverse lookup of IP address matches filename.
 * @return
 *	- The new client on success.
 *	- NULL on failure.
 */
RADCLIENT *client_read(char const *filename, CONF_SECTION *server_cs, bool check_dns)
{
	char const	*p;
	RADCLIENT	*c;
	CONF_SECTION	*cs;
	char buffer[256];

	if (!filename) return NULL;

	cs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!cs) return NULL;

	if ((cf_file_read(cs, filename) < 0) || (cf_section_pass2(cs) < 0)) {
		talloc_free(cs);
		return NULL;
	}

	cs = cf_section_find(cs, "client", CF_IDENT_ANY);
	if (!cs) {
		ERROR("No \"client\" section found in client file");
		return NULL;
	}

	c = client_afrom_cs(cs, cs, server_cs);
	if (!c) return NULL;
	talloc_steal(cs, c);

	p = strrchr(filename, FR_DIR_SEP);
	if (p) {
		p++;
	} else {
		p = filename;
	}

	if (!check_dns) return c;

	/*
	 *	Additional validations
	 */
	fr_inet_ntoh(&c->ipaddr, buffer, sizeof(buffer));
	if (strcmp(p, buffer) != 0) {
		ERROR("Invalid client definition in %s: IP address %s does not match name %s", filename, buffer, p);
		client_free(c);
		return NULL;
	}

	return c;
}
