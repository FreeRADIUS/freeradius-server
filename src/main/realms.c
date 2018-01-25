/*
 * realms.c	Realm handling code
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
 * Copyright 2007  The FreeRADIUS server project
 * Copyright 2007  Alan DeKok <aland@deployingradius.com>
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/realms.h>
#include <freeradius-devel/rad_assert.h>

#include <sys/stat.h>

#include <ctype.h>
#include <fcntl.h>

static rbtree_t *realms_byname = NULL;
#ifdef WITH_TCP
bool home_servers_udp = false;
#endif

#ifdef HAVE_REGEX
typedef struct realm_regex realm_regex_t;

/** Regular expression associated with a realm
 *
 */
struct realm_regex {
	REALM		*realm;		//!< The realm this regex matches.
	regex_t		*preg;		//!< The pre-compiled regular expression.
	realm_regex_t	*next;		//!< The next realm in the list of regular expressions.
};
static realm_regex_t *realms_regex = NULL;
#endif /* HAVE_REGEX */

struct realm_config {
	CONF_SECTION		*cs;
	uint32_t		dead_time;
	uint32_t		retry_count;
	uint32_t		retry_delay;
	bool			dynamic;
	bool			fallback;
	bool			wake_all_if_all_dead;
};

static const FR_NAME_NUMBER home_server_types[] = {
	{ "auth",		HOME_TYPE_AUTH },
	{ "acct",		HOME_TYPE_ACCT },
	{ "auth+acct",		HOME_TYPE_AUTH_ACCT },
	{ "coa",		HOME_TYPE_COA },
	{ NULL, 0 }
};

static const FR_NAME_NUMBER home_ping_check[] = {
	{ "none",		HOME_PING_CHECK_NONE },
	{ "status-server",	HOME_PING_CHECK_STATUS_SERVER },
	{ "request",		HOME_PING_CHECK_REQUEST },
	{ NULL, 0 }
};

static const FR_NAME_NUMBER home_proto[] = {
	{ "UDP",		IPPROTO_UDP },
	{ "TCP",		IPPROTO_TCP },
	{ NULL, 0 }
};


static realm_config_t *realm_config = NULL;

#ifdef WITH_PROXY
static rbtree_t	*home_servers_byaddr = NULL;
static rbtree_t	*home_servers_byname = NULL;
#ifdef WITH_STATS
static int home_server_max_number = 0;
static rbtree_t	*home_servers_bynumber = NULL;
#endif

static rbtree_t	*home_pools_byname = NULL;

/*
 *  Map the proxy server configuration parameters to variables.
 */
static const CONF_PARSER proxy_config[] = {
	{ "retry_delay", FR_CONF_OFFSET(PW_TYPE_INTEGER, realm_config_t, retry_delay), STRINGIFY(RETRY_DELAY)  },

	{ "retry_count", FR_CONF_OFFSET(PW_TYPE_INTEGER, realm_config_t, retry_count), STRINGIFY(RETRY_COUNT)  },

	{ "default_fallback", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, realm_config_t, fallback), "no" },

	{ "dynamic", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, realm_config_t, dynamic), NULL },

	{ "dead_time", FR_CONF_OFFSET(PW_TYPE_INTEGER, realm_config_t, dead_time), STRINGIFY(DEAD_TIME)  },

	{ "wake_all_if_all_dead", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, realm_config_t, wake_all_if_all_dead), "no" },
	CONF_PARSER_TERMINATOR
};
#endif

static int realm_name_cmp(void const *one, void const *two)
{
	REALM const *a = one;
	REALM const *b = two;

	return strcasecmp(a->name, b->name);
}


#ifdef WITH_PROXY
static void home_server_free(void *data)
{
	home_server_t *home = talloc_get_type_abort(data, home_server_t);

	talloc_free(home);
}

static int home_server_name_cmp(void const *one, void const *two)
{
	home_server_t const *a = one;
	home_server_t const *b = two;

	if (a->type < b->type) return -1;
	if (a->type > b->type) return +1;

	return strcasecmp(a->name, b->name);
}

static int home_server_addr_cmp(void const *one, void const *two)
{
	int rcode;
	home_server_t const *a = one;
	home_server_t const *b = two;

	if (a->server && !b->server) return -1;
	if (!a->server && b->server) return +1;
	if (a->server && b->server) {
		rcode = a->type - b->type;
		if (rcode != 0) return rcode;
		return strcmp(a->server, b->server);
	}

	if (a->port < b->port) return -1;
	if (a->port > b->port) return +1;

#ifdef WITH_TCP
	if (a->proto < b->proto) return -1;
	if (a->proto > b->proto) return +1;
#endif

	rcode = fr_ipaddr_cmp(&a->src_ipaddr, &b->src_ipaddr);
	if (rcode != 0) return rcode;

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}

#ifdef WITH_STATS
static int home_server_number_cmp(void const *one, void const *two)
{
	home_server_t const *a = one;
	home_server_t const *b = two;

	return (a->number - b->number);
}
#endif

static int home_pool_name_cmp(void const *one, void const *two)
{
	home_pool_t const *a = one;
	home_pool_t const *b = two;

	if (a->server_type < b->server_type) return -1;
	if (a->server_type > b->server_type) return +1;

	return strcasecmp(a->name, b->name);
}


static size_t xlat_cs(CONF_SECTION *cs, char const *fmt, char *out, size_t outlen)
{
	char const *value = NULL;

	if (!fmt) {
		DEBUG("No configuration item requested.  Ignoring.");

		*out = '\0';
		return 0;
	}

	/*
	 *	Instance name
	 */
	if (strcmp(fmt, "instance") == 0) {
		value = cf_section_name2(cs);
		if (!value) {
			*out = '\0';
			return 0;
		}
	} else {
		CONF_PAIR *cp;

		cp = cf_pair_find(cs, fmt);
		if (!cp || !(value = cf_pair_value(cp))) {
			*out = '\0';
			return 0;
		}
	}

	strlcpy(out, value, outlen);

	return strlen(out);
}


/*
 *	Xlat for %{home_server:foo}
 */
static ssize_t xlat_home_server(UNUSED void *instance, REQUEST *request,
				char const *fmt, char *out, size_t outlen)
{
	if (!request->home_server) {
		RWDEBUG("No home_server associated with this request");

		*out = '\0';
		return 0;
	}

	if (!fmt) {
		RWDEBUG("No configuration item requested.  Ignoring.");

		*out = '\0';
		return 0;
	}

	if (strcmp(fmt, "state") == 0) {
		char const *state;

		switch (request->home_server->state) {
		case HOME_STATE_ALIVE:
			state = "alive";
			break;

		case HOME_STATE_ZOMBIE:
			state = "zombie";
			break;

		case HOME_STATE_IS_DEAD:
			state = "dead";
			break;

		default:
			state = "unknown";
			break;
		}

		strlcpy(out, state, outlen);
		return strlen(out);
	}

	return xlat_cs(request->home_server->cs, fmt, out, outlen);
}


/*
 *	Xlat for %{home_server_pool:foo}
 */
static ssize_t xlat_server_pool(UNUSED void *instance, REQUEST *request,
				char const *fmt, char *out, size_t outlen)
{
	if (!request->home_pool) {
		RWDEBUG("No home_pool associated with this request");

		*out = '\0';
		return 0;
	}

	if (!fmt) {
		RWDEBUG("No configuration item requested.  Ignoring.");

		*out = '\0';
		return 0;
	}

	if (strcmp(fmt, "state") == 0) {
		char const *state;

		if (request->home_pool->in_fallback) {
			state = "fallback";

		} else {
			state = "alive";
		}

		strlcpy(out, state, outlen);
		return strlen(out);
	}

	return xlat_cs(request->home_pool->cs, fmt, out, outlen);
}
#endif

void realms_free(void)
{
#ifdef WITH_PROXY
#  ifdef WITH_STATS
	rbtree_free(home_servers_bynumber);
	home_servers_bynumber = NULL;
#  endif

	rbtree_free(home_servers_byname);
	home_servers_byname = NULL;

	rbtree_free(home_servers_byaddr);
	home_servers_byaddr = NULL;

	rbtree_free(home_pools_byname);
	home_pools_byname = NULL;
#endif

	rbtree_free(realms_byname);
	realms_byname = NULL;

	realm_pool_free(NULL);

	talloc_free(realm_config);
	realm_config = NULL;
}


#ifdef WITH_PROXY
static CONF_PARSER limit_config[] = {
	{ "max_connections", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, limit.max_connections), "16" },
	{ "max_requests", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, limit.max_requests), "0" },
	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, limit.lifetime), "0" },
	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, limit.idle_timeout), "0" },
	CONF_PARSER_TERMINATOR
};

#ifdef WITH_COA
static CONF_PARSER home_server_coa[] = {
	{ "irt",  FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, coa_irt), STRINGIFY(2) },
	{ "mrt",  FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, coa_mrt), STRINGIFY(16) },
	{ "mrc",  FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, coa_mrc), STRINGIFY(5) },
	{ "mrd",  FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, coa_mrd), STRINGIFY(30) },
	CONF_PARSER_TERMINATOR
};
#endif

static CONF_PARSER home_server_config[] = {
	{ "ipaddr", FR_CONF_OFFSET(PW_TYPE_COMBO_IP_ADDR, home_server_t, ipaddr), NULL },
	{ "ipv4addr", FR_CONF_OFFSET(PW_TYPE_IPV4_ADDR, home_server_t, ipaddr), NULL },
	{ "ipv6addr", FR_CONF_OFFSET(PW_TYPE_IPV6_ADDR, home_server_t, ipaddr), NULL },
	{ "virtual_server", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, home_server_t, server), NULL },

	{ "port", FR_CONF_OFFSET(PW_TYPE_SHORT, home_server_t, port), "0" },

	{ "type", FR_CONF_OFFSET(PW_TYPE_STRING, home_server_t, type_str), NULL },

#ifdef WITH_TCP
	{ "proto", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, home_server_t, proto_str), NULL },
#endif

	{ "secret", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_SECRET, home_server_t, secret), NULL },

	{ "src_ipaddr", FR_CONF_OFFSET(PW_TYPE_STRING, home_server_t, src_ipaddr_str), NULL },

	{ "response_window", FR_CONF_OFFSET(PW_TYPE_TIMEVAL, home_server_t, response_window), "30" },
	{ "response_timeouts", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, max_response_timeouts), "1" },
	{ "max_outstanding", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, max_outstanding), "65536" },

	{ "zombie_period", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, zombie_period), "40" },

	{ "status_check",  FR_CONF_OFFSET(PW_TYPE_STRING, home_server_t, ping_check_str), "none" },
	{ "ping_check", FR_CONF_OFFSET(PW_TYPE_STRING, home_server_t, ping_check_str), NULL },

	{ "ping_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, ping_interval), "30" },
	{ "check_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, ping_interval), NULL },

	{ "check_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, ping_timeout), "4" },
	{ "status_check_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, ping_timeout), NULL },

	{ "num_answers_to_alive", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, num_pings_to_alive), "3" },
	{ "revive_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, revive_interval), "300" },

	{ "username", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, home_server_t, ping_user_name), NULL },
	{ "password", FR_CONF_OFFSET(PW_TYPE_STRING | PW_TYPE_NOT_EMPTY, home_server_t, ping_user_password), NULL },

#ifdef WITH_STATS
	{ "historic_average_window", FR_CONF_OFFSET(PW_TYPE_INTEGER, home_server_t, ema.window), NULL },
#endif

	{ "limit", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) limit_config },

#ifdef WITH_COA
	{ "coa", FR_CONF_POINTER(PW_TYPE_SUBSECTION, NULL), (void const *) home_server_coa },
#endif

	CONF_PARSER_TERMINATOR
};


static void null_free(UNUSED void *data)
{
}

/*
 *	Ensure that all of the parameters in the home server are OK.
 */
void realm_home_server_sanitize(home_server_t *home, CONF_SECTION *cs)
{
	CONF_SECTION *parent = NULL;

	FR_INTEGER_BOUND_CHECK("max_outstanding", home->max_outstanding, >=, 8);
	FR_INTEGER_BOUND_CHECK("max_outstanding", home->max_outstanding, <=, 65536*16);

	FR_INTEGER_BOUND_CHECK("ping_interval", home->ping_interval, >=, 6);
	FR_INTEGER_BOUND_CHECK("ping_interval", home->ping_interval, <=, 120);

	FR_TIMEVAL_BOUND_CHECK("response_window", &home->response_window, >=, 0, 1000);
	FR_TIMEVAL_BOUND_CHECK("response_window", &home->response_window, <=,
			       main_config.max_request_time, 0);
	FR_TIMEVAL_BOUND_CHECK("response_window", &home->response_window, <=, 60, 0);

	FR_INTEGER_BOUND_CHECK("response_timeouts", home->max_response_timeouts, >=, 1);
	FR_INTEGER_BOUND_CHECK("response_timeouts", home->max_response_timeouts, <=, 1000);

	/*
	 *	Track the minimum response window, so that we can
	 *	correctly set the timers in process.c
	 */
	if (timercmp(&main_config.init_delay, &home->response_window, >)) {
		main_config.init_delay = home->response_window;
	}

	FR_INTEGER_BOUND_CHECK("zombie_period", home->zombie_period, >=, 1);
	FR_INTEGER_BOUND_CHECK("zombie_period", home->zombie_period, <=, 120);
	FR_INTEGER_BOUND_CHECK("zombie_period", home->zombie_period, >=, (uint32_t) home->response_window.tv_sec);

	FR_INTEGER_BOUND_CHECK("num_pings_to_alive", home->num_pings_to_alive, >=, 3);
	FR_INTEGER_BOUND_CHECK("num_pings_to_alive", home->num_pings_to_alive, <=, 10);

	FR_INTEGER_BOUND_CHECK("check_timeout", home->ping_timeout, >=, 1);
	FR_INTEGER_BOUND_CHECK("check_timeout", home->ping_timeout, <=, 10);

	FR_INTEGER_BOUND_CHECK("revive_interval", home->revive_interval, >=, 60);
	FR_INTEGER_BOUND_CHECK("revive_interval", home->revive_interval, <=, 3600);

#ifdef WITH_COA
	FR_INTEGER_BOUND_CHECK("coa_irt", home->coa_irt, >=, 1);
	FR_INTEGER_BOUND_CHECK("coa_irt", home->coa_irt, <=, 5);

	FR_INTEGER_BOUND_CHECK("coa_mrc", home->coa_mrc, <=, 20);

	FR_INTEGER_BOUND_CHECK("coa_mrt", home->coa_mrt, <=, 30);

	FR_INTEGER_BOUND_CHECK("coa_mrd", home->coa_mrd, >=, 5);
	FR_INTEGER_BOUND_CHECK("coa_mrd", home->coa_mrd, <=, 60);
#endif

	FR_INTEGER_BOUND_CHECK("max_connections", home->limit.max_connections, <=, 1024);

#ifdef WITH_TCP
	/*
	 *	UDP sockets can't be connection limited.
	 */
	if (home->proto != IPPROTO_TCP) home->limit.max_connections = 0;
#endif

	if ((home->limit.idle_timeout > 0) && (home->limit.idle_timeout < 5))
		home->limit.idle_timeout = 5;
	if ((home->limit.lifetime > 0) && (home->limit.lifetime < 5))
		home->limit.lifetime = 5;
	if ((home->limit.lifetime > 0) && (home->limit.idle_timeout > home->limit.lifetime))
		home->limit.idle_timeout = 0;

	/*
	 *	Make sure that this is set.
	 */
	if (home->src_ipaddr.af == AF_UNSPEC) {
		home->src_ipaddr.af = home->ipaddr.af;
	}

	parent = cf_item_parent(cf_section_to_item(cs));
	if (parent && strcmp(cf_section_name1(parent), "server") == 0) {
		home->parent_server = cf_section_name2(parent);
	}
}

/** Insert a new home server into the various internal lookup trees
 *
 * @param home server to add.
 * @param cs That defined the home server.
 * @return true on success else false.
 */
static bool home_server_insert(home_server_t *home, CONF_SECTION *cs)
{
	if (home->name && !rbtree_insert(home_servers_byname, home)) {
		cf_log_err_cs(cs, "Internal error %d adding home server %s", __LINE__, home->log_name);
		return false;
	}

	if (!home->server && !rbtree_insert(home_servers_byaddr, home)) {
		rbtree_deletebydata(home_servers_byname, home);
		cf_log_err_cs(cs, "Internal error %d adding home server %s", __LINE__, home->log_name);
		return false;
	}

#ifdef WITH_STATS
	home->number = home_server_max_number++;
	if (!rbtree_insert(home_servers_bynumber, home)) {
		rbtree_deletebydata(home_servers_byname, home);
		if (home->ipaddr.af != AF_UNSPEC) {
			rbtree_deletebydata(home_servers_byname, home);
		}
		cf_log_err_cs(cs, "Internal error %d adding home server %s", __LINE__, home->log_name);
		return false;
	}
#endif

	return true;
}

/** Add an already allocate home_server_t to the various trees
 *
 * @param home server to add.
 * @return true on success, else false on error.
 */
bool realm_home_server_add(home_server_t *home)
{
	/*
	 *	The structs aren't mutex protected.  Refuse to destroy
	 *	the server.
	 */
	if (event_loop_started && !realm_config->dynamic) {
		ERROR("Failed to add dynamic home server, \"dynamic = yes\" must be set in proxy.conf");
		return false;
	}

	if (home->name && (rbtree_finddata(home_servers_byname, home) != NULL)) {
		cf_log_err_cs(home->cs, "Duplicate home server name %s", home->name);
		return false;
	}

	if (!home->server && (rbtree_finddata(home_servers_byaddr, home) != NULL)) {
		char buffer[INET6_ADDRSTRLEN + 3];

		inet_ntop(home->ipaddr.af, &home->ipaddr.ipaddr, buffer, sizeof(buffer));

		cf_log_err_cs(home->cs, "Duplicate home server address%s%s%s: %s:%s%s/%i",
			      home->name ? " (already in use by " : "",
			      home->name ? home->name : "",
			      home->name ? ")" : "",
			      buffer,
			      fr_int2str(home_proto, home->proto, "<INVALID>"),
#ifdef WITH_TLS
			      home->tls ? "+tls" : "",
#else
			      "",
#endif
			      home->port);

		return false;
	}

	if (!home_server_insert(home, home->cs)) return false;

	/*
	 *	Dual home servers cause us to auto-create an
	 *	accounting server for UDP sockets, and leave
	 *	everything alone for TLS sockets.
	 */
	if (home->dual
#ifdef WITH_TLS
	    && !home->tls
#endif
) {
		home_server_t *home2 = talloc(talloc_parent(home), home_server_t);

		memcpy(home2, home, sizeof(*home2));

		home2->type = HOME_TYPE_ACCT;
		home2->dual = true;
		home2->port++;

		home2->ping_user_password = NULL;
		home2->cs = home->cs;
		home2->parent_server = home->parent_server;

		if (!home_server_insert(home2, home->cs)) {
			talloc_free(home2);
			return false;
		}
	}

	/*
	 *	Mark it as already processed
	 */
	cf_data_add(home->cs, "home_server", (void *)null_free, null_free);

	return true;
}

/** Alloc a new home server defined by a CONF_SECTION
 *
 * @param ctx to allocate home_server_t in.
 * @param rc Realm config, may be NULL in which case the global realm_config will be used.
 * @param cs Configuration section containing home server parameters.
 * @return a new home_server_t alloced in the context of the realm_config, or NULL on error.
 */
home_server_t *home_server_afrom_cs(TALLOC_CTX *ctx, realm_config_t *rc, CONF_SECTION *cs)
{
	home_server_t	*home;
	CONF_SECTION	*tls;

	if (!rc) rc = realm_config; /* Use the global config */

	home = talloc_zero(ctx, home_server_t);
	home->name = cf_section_name2(cs);
	home->log_name = talloc_typed_strdup(home, home->name);
	home->cs = cs;
	home->state = HOME_STATE_UNKNOWN;
	home->proto = IPPROTO_UDP;

	/*
	 *	Parse the configuration into the home server
	 *	struct.
	 */
	if (cf_section_parse(cs, home, home_server_config) < 0) goto error;

	/*
	 *	It has an IP address, it must be a remote server.
	 */
	if (cf_pair_find(cs, "ipaddr") || cf_pair_find(cs, "ipv4addr") || cf_pair_find(cs, "ipv6addr")) {
		if (fr_inaddr_any(&home->ipaddr) == 1) {
			cf_log_err_cs(cs, "Wildcard '*' addresses are not permitted for home servers");
			goto error;
		}

		if (!home->log_name) {
			char buffer[INET6_ADDRSTRLEN + 3];

			fr_ntop(buffer, sizeof(buffer), &home->ipaddr);

			home->log_name = talloc_asprintf(home, "%s:%i", buffer, home->port);
		}
	/*
	 *	If it has a 'virtual_Server' config item, it's
	 *	a loopback into a virtual server.
	 */
	} else if (cf_pair_find(cs, "virtual_server") != NULL) {
		home->ipaddr.af = AF_UNSPEC;	/* mark ipaddr as unused */

		if (!home->server) {
			cf_log_err_cs(cs, "Invalid value for virtual_server");
			goto error;
		}

		/*
		 *	Try and find a 'server' section off the root of
		 *	the config with a name that matches the
		 *	virtual_server.
		 */
		if (!cf_section_sub_find_name2(rc->cs, "server", home->server)) {
			cf_log_err_cs(cs, "No such server %s", home->server);
			goto error;
		}

		home->secret = "";
		home->log_name = talloc_typed_strdup(home, home->server);
	/*
	 *	Otherwise it's an invalid config section and we
	 *	raise an error.
	 */
	} else {
		cf_log_err_cs(cs, "No ipaddr, ipv4addr, ipv6addr, or virtual_server defined "
			      "for home server");
	error:
		talloc_free(home);
		return false;
	}

 	{
 		home_type_t type = HOME_TYPE_AUTH_ACCT;

 		if (home->type_str) type = fr_str2int(home_server_types, home->type_str, HOME_TYPE_INVALID);

		home->type = type;

 		switch (type) {
 		case HOME_TYPE_AUTH_ACCT:
			home->dual = true;
			break;

		case HOME_TYPE_AUTH:
		case HOME_TYPE_ACCT:
			break;

#ifdef WITH_COA
 		case HOME_TYPE_COA:
			if (home->server != NULL) {
				cf_log_err_cs(cs, "Home servers of type \"coa\" cannot point to a virtual server");
				goto error;
			}
			break;
#endif

  		case HOME_TYPE_INVALID:
 			cf_log_err_cs(cs, "Invalid type \"%s\" for home server %s", home->type_str, home->log_name);
 			goto error;
 		}
 	}

 	{
 		home_ping_check_t type = HOME_PING_CHECK_NONE;

 		if (home->ping_check_str) type = fr_str2int(home_ping_check, home->ping_check_str,
 							    HOME_PING_CHECK_INVALID);

 		switch (type) {
 		case HOME_PING_CHECK_STATUS_SERVER:
 		case HOME_PING_CHECK_NONE:
 			break;

 		case HOME_PING_CHECK_REQUEST:
			if (!home->ping_user_name) {
				cf_log_err_cs(cs, "You must supply a 'username' to enable status_check=request");
				goto error;
			}

			if (((home->type == HOME_TYPE_AUTH) ||
			     (home->type == HOME_TYPE_AUTH_ACCT)) && !home->ping_user_password) {
				cf_log_err_cs(cs, "You must supply a 'password' to enable status_check=request");
				goto error;
			}

 			break;

 		case HOME_PING_CHECK_INVALID:
 			cf_log_err_cs(cs, "Invalid status_check \"%s\" for home server %s",
 				      home->ping_check_str, home->log_name);
 			goto error;
 		}

		home->ping_check = type;
 	}

	{
		int proto = IPPROTO_UDP;

		if (home->proto_str) proto = fr_str2int(home_proto, home->proto_str, -1);

		switch (proto) {
		case IPPROTO_UDP:
#ifdef WITH_TCP
			home_servers_udp = true;
#endif
			break;

		case IPPROTO_TCP:
#ifndef WITH_TCP
			cf_log_err_cs(cs, "Server not built with support for RADIUS over TCP");
			goto error;
#endif
			if (home->ping_check != HOME_PING_CHECK_NONE) {
				cf_log_err_cs(cs, "Only 'status_check = none' is allowed for home "
					      "servers with 'proto = tcp'");
				goto error;
			}
			break;

		default:
			cf_log_err_cs(cs, "Unknown proto \"%s\"", home->proto_str);
			goto error;
		}

		home->proto = proto;
	}

	if (!home->server && rbtree_finddata(home_servers_byaddr, home)) {
		cf_log_err_cs(cs, "Duplicate home server");
		goto error;
	}

	/*
	 *	Check the TLS configuration.
	 */
	tls = cf_section_sub_find(cs, "tls");
#ifndef WITH_TLS
	if (tls) {
		cf_log_err_cs(cs, "TLS transport is not available in this executable");
		goto error;
	}
#endif

	/*
	 *	If were doing RADSEC (tls+tcp) the secret should default
	 *	to radsec, else a secret must be set.
	 */
	if (!home->secret) {
#ifdef WITH_TLS
		if (tls && (home->proto == IPPROTO_TCP)) {
			home->secret = "radsec";
		} else
#endif
		{
			cf_log_err_cs(cs, "No shared secret defined for home server %s", home->log_name);
			goto error;
		}
	}

	/*
	 *	Virtual servers have some TLS restrictions.
	 */
	if (home->server) {
		if (tls) {
			cf_log_err_cs(cs, "Virtual home_servers cannot have a \"tls\" subsection");
			goto error;
		}
	} else {
		/*
		 *	If the home is not a virtual server, guess the port
		 *	and look up the source ip address.
		 */
		rad_assert(home->ipaddr.af != AF_UNSPEC);

#ifdef WITH_TLS
		if (tls && (home->proto != IPPROTO_TCP)) {
			cf_log_err_cs(cs, "TLS transport is not available for UDP sockets");
			goto error;
		}
#endif

		/*
		 *	Set the default port if necessary.
		 */
		if (home->port == 0) {
			char buffer[INET6_ADDRSTRLEN + 3];

			/*
			 *	For RADSEC we use the special RADIUS over TCP/TLS port
			 *	for both accounting and authentication, but for some
			 *	bizarre reason for RADIUS over plain TCP we use separate
			 *	ports 1812 and 1813.
			 */
#ifdef WITH_TLS
			if (tls) {
				home->port = PW_RADIUS_TLS_PORT;
			} else
#endif
			switch (home->type) {
			default:
				rad_assert(0);
				/* FALL-THROUGH */

			/*
			 *	One is added to get the accounting port
			 *	for home->dual.
			 */
			case HOME_TYPE_AUTH_ACCT:
			case HOME_TYPE_AUTH:
				home->port = PW_AUTH_UDP_PORT;
				break;

			case HOME_TYPE_ACCT:
				home->port = PW_ACCT_UDP_PORT;
				break;

			case HOME_TYPE_COA:
				home->port = PW_COA_UDP_PORT;
				break;
			}

			/*
			 *	Now that we have a real port, use that.
			 */
			rad_const_free(home->log_name);

			fr_ntop(buffer, sizeof(buffer), &home->ipaddr);

			home->log_name = talloc_asprintf(home, "%s:%i", buffer, home->port);
		}

		/*
		 *	If we have a src_ipaddr_str resolve it to
		 *	the same address family as the destination
		 *	IP.
		 */
		if (home->src_ipaddr_str) {
			if (ip_hton(&home->src_ipaddr, home->ipaddr.af, home->src_ipaddr_str, false) < 0) {
				cf_log_err_cs(cs, "Failed parsing src_ipaddr");
				goto error;
			}
		/*
		 *	Source isn't specified, set it to the
		 *	correct address family, but leave it as
		 *	zeroes.
		 */
		} else {
			home->src_ipaddr.af = home->ipaddr.af;
		}

#ifdef WITH_TLS
		/*
		 *	Parse the SSL client configuration.
		 */
		if (tls) {
			home->tls = tls_client_conf_parse(tls);
			if (!home->tls) {
				goto error;
			}
		}
#endif
	} /* end of parse home server */

	realm_home_server_sanitize(home, cs);

	return home;
}

/** Fixup a client configuration section to specify a home server
 *
 * This is used to create the equivalent CoA home server entry for a client,
 * so that the server can originate CoA messages.
 *
 * The server section automatically inherits the following fields from the client:
 *  - ipaddr/ipv4addr/ipv6addr
 *  - secret
 *  - src_ipaddr
 *
 * @note new CONF_SECTION will be allocated in the context of the client, but the client
 *	CONF_SECTION will not be modified.
 *
 * @param client CONF_SECTION to inherit values from.
 * @return a new server CONF_SCTION, or a pointer to the existing CONF_SECTION in the client.
 */
CONF_SECTION *home_server_cs_afrom_client(CONF_SECTION *client)
{
	CONF_SECTION *server, *cs;
	CONF_PAIR *cp;

	/*
	 *	Alloc a plain home server for both cases
	 *
	 *	There's no way these can be referenced by a pool,
	 *	and they may conflict with home servers in proxy.conf
	 *	so it's easier to not set a name.
	 */

	/*
	 *
	 *	Duplicate the server section, so we don't mangle
	 *	the client CONF_SECTION we were passed.
	 */
	cs = cf_section_sub_find(client, "coa_server");
	if (cs) {
		server = cf_section_dup(client, cs, "home_server", NULL, true);
	} else {
		server = cf_section_alloc(client, "home_server", cf_section_name2(client));
	}

	if (!cs || (!cf_pair_find(cs, "ipaddr") && !cf_pair_find(cs, "ipv4addr") && !cf_pair_find(cs, "ipv6addr"))) {
		cp = cf_pair_find(client, "ipaddr");
		if (!cp) cp = cf_pair_find(client, "ipv4addr");
		if (!cp) cp = cf_pair_find(client, "ipv6addr");

		cf_pair_add(server, cf_pair_dup(server, cp));
	}

	if (!cs || !cf_pair_find(cs, "secret")) {
		cp = cf_pair_find(client, "secret");
		if (cp) cf_pair_add(server, cp);
	}

	if (!cs || !cf_pair_find(cs, "src_ipaddr")) {
		cp = cf_pair_find(client, "src_ipaddr");
		if (cp) cf_pair_add(server, cf_pair_dup(server, cp));
	}

	if (!cs || !(cp = cf_pair_find(cs, "type"))) {
		cp = cf_pair_alloc(server, "type", "coa", T_OP_EQ, T_BARE_WORD, T_SINGLE_QUOTED_STRING);
		if (cp) cf_pair_add(server, cf_pair_dup(server, cp));
	} else if (strcmp(cf_pair_value(cp), "coa") != 0) {
		talloc_free(server);
		cf_log_err_cs(server, "server.type must be \"coa\"");
		return NULL;
	}

	return server;
}

static home_pool_t *server_pool_alloc(char const *name, home_pool_type_t type,
				      home_type_t server_type, int num_home_servers)
{
	home_pool_t *pool;

	pool = rad_malloc(sizeof(*pool) + (sizeof(pool->servers[0]) * num_home_servers));
	if (!pool) return NULL;	/* just for pairanoia */

	memset(pool, 0, sizeof(*pool) + (sizeof(pool->servers[0]) * num_home_servers));

	pool->name = name;
	pool->type = type;
	pool->server_type = server_type;
	pool->num_home_servers = num_home_servers;

	return pool;
}

/*
 * Ensure any home_server clauses in a home_server_pool section reference
 * defined home servers, which should already have been created, regardless
 * of where they appear in the configuration.
 */
static int pool_check_home_server(UNUSED realm_config_t *rc, CONF_PAIR *cp,
				  char const *name, home_type_t server_type,
				  home_server_t **phome)
{
	home_server_t myhome, *home;

	if (!name) {
		cf_log_err_cp(cp,
			   "No value given for home_server");
		return 0;
	}

	myhome.name = name;
	myhome.type = server_type;
	home = rbtree_finddata(home_servers_byname, &myhome);
	if (home) {
		*phome = home;
		return 1;
	}

	switch (server_type) {
	case HOME_TYPE_AUTH:
	case HOME_TYPE_ACCT:
		myhome.type = HOME_TYPE_AUTH_ACCT;
		home = rbtree_finddata(home_servers_byname, &myhome);
		if (home) {
			*phome = home;
			return 1;
		}
		break;

	default:
		break;
	}

	cf_log_err_cp(cp, "Unknown home_server \"%s\".", name);
	return 0;
}


#ifndef HAVE_PTHREAD_H
void realm_pool_free(home_pool_t *pool)
{
	if (!event_loop_started) return;
	if (!realm_config->dynamic) return;

	talloc_free(pool);
}
#else  /* HAVE_PTHREAD_H */
typedef struct pool_list_t pool_list_t;

struct pool_list_t {
	pool_list_t	*next;
	home_pool_t	*pool;
	time_t		when;
};

static bool		pool_free_init = false;
static pthread_mutex_t	pool_free_mutex;
static pool_list_t	*pool_list = NULL;

void realm_pool_free(home_pool_t *pool)
{
	int i;
	time_t now;
	pool_list_t *this, **last;

	if (!event_loop_started) return;
	if (!realm_config->dynamic) return;

	if (pool) {
		/*
		 *	Double-check that the realm wasn't loaded from the
		 *	configuration files.
		 */
		for (i = 0; i < pool->num_home_servers; i++) {
			if (pool->servers[i]->cs) {
				rad_assert(0 == 1);
				return;
			}
		}
	}

	if (!pool_free_init) {
		pthread_mutex_init(&pool_free_mutex, NULL);
		pool_free_init = true;
	}

	/*
	 *	Ensure only one caller at a time is freeing a pool.
	 */
	pthread_mutex_lock(&pool_free_mutex);

	/*
	 *	Free all of the pools.
	 */
	if (!pool) {
		while ((this = pool_list) != NULL) {
			pool_list = this->next;
			talloc_free(this->pool);
			talloc_free(this);
		}
		pthread_mutex_unlock(&pool_free_mutex);
		return;
	}

	now = time(NULL);

	/*
	 *	Free the oldest pool(s)
	 */
	while ((this = pool_list) != NULL) {
		if (this->when > now) break;

		pool_list = this->next;
		talloc_free(this->pool);
		talloc_free(this);
	}

	/*
	 *	Add this pool to the end of the list.
	 */
	for (last = &pool_list;
	     *last != NULL;
	     last = &((*last))->next) {
		/* do nothing */
	}

	*last = this = talloc(NULL, pool_list_t);
	if (!this) {
		talloc_free(pool); /* hope for the best */
		pthread_mutex_unlock(&pool_free_mutex);
		return;
	}

	this->next = NULL;
	this->when = now + 300;
	this->pool = pool;
	pthread_mutex_unlock(&pool_free_mutex);
}
#endif	/* HAVE_PTHREAD_H */

int realm_pool_add(home_pool_t *pool, UNUSED CONF_SECTION *cs)
{
	/*
	 *	The structs aren't mutex protected.  Refuse to destroy
	 *	the server.
	 */
	if (event_loop_started && !realm_config->dynamic) {
		DEBUG("Must set \"dynamic = true\" in proxy.conf");
		return 0;
	}

	if (!rbtree_insert(home_pools_byname, pool)) {
		rad_assert("Internal sanity check failed" == NULL);
		return 0;
	}

	return 1;
}

static int server_pool_add(realm_config_t *rc,
			   CONF_SECTION *cs, home_type_t server_type, bool do_print)
{
	char const *name2;
	home_pool_t *pool = NULL;
	char const *value;
	CONF_PAIR *cp;
	int num_home_servers;
	home_server_t *home;

	name2 = cf_section_name1(cs);
	if (!name2 || ((strcasecmp(name2, "server_pool") != 0) &&
		       (strcasecmp(name2, "home_server_pool") != 0))) {
		cf_log_err_cs(cs,
			   "Section is not a home_server_pool");
		return 0;
	}

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs,
			   "Server pool section is missing a name");
		return 0;
	}

	/*
	 *	Count the home servers and initalize them.
	 */
	num_home_servers = 0;
	for (cp = cf_pair_find(cs, "home_server");
	     cp != NULL;
	     cp = cf_pair_find_next(cs, cp, "home_server")) {
		num_home_servers++;

		if (!pool_check_home_server(rc, cp, cf_pair_value(cp),
					    server_type, &home)) {
			return 0;
		}
	}

	if (num_home_servers == 0) {
		cf_log_err_cs(cs,
			   "No home servers defined in pool %s",
			   name2);
		goto error;
	}

	pool = server_pool_alloc(name2, HOME_POOL_FAIL_OVER, server_type,
				 num_home_servers);
	if (!pool) {
		cf_log_err_cs(cs, "Failed allocating memory for pool");
		goto error;
	}
	pool->cs = cs;


	/*
	 *	Fallback servers must be defined, and must be
	 *	virtual servers.
	 */
	cp = cf_pair_find(cs, "fallback");
	if (cp) {
#ifdef WITH_COA
		if (server_type == HOME_TYPE_COA) {
			cf_log_err_cs(cs, "Home server pools of type \"coa\" cannot have a fallback virtual server");
			goto error;
		}
#endif

		if (!pool_check_home_server(rc, cp, cf_pair_value(cp), server_type, &pool->fallback)) {
			goto error;
		}

		if (!pool->fallback->server) {
			cf_log_err_cs(cs, "Fallback home_server %s does NOT contain a virtual_server directive",
				      pool->fallback->log_name);
			goto error;
		}
	}

	if (do_print) cf_log_info(cs, " home_server_pool %s {", name2);

	cp = cf_pair_find(cs, "type");
	if (cp) {
		static FR_NAME_NUMBER pool_types[] = {
			{ "load-balance", HOME_POOL_LOAD_BALANCE },

			{ "fail-over", HOME_POOL_FAIL_OVER },
			{ "fail_over", HOME_POOL_FAIL_OVER },

			{ "round-robin", HOME_POOL_LOAD_BALANCE },
			{ "round_robin", HOME_POOL_LOAD_BALANCE },

			{ "client-balance", HOME_POOL_CLIENT_BALANCE },
			{ "client-port-balance", HOME_POOL_CLIENT_PORT_BALANCE },
			{ "keyed-balance", HOME_POOL_KEYED_BALANCE },
			{ NULL, 0 }
		};

		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err_cp(cp,
				   "No value given for type");
			goto error;
		}

		pool->type = fr_str2int(pool_types, value, 0);
		if (!pool->type) {
			cf_log_err_cp(cp,
				   "Unknown type \"%s\".",
				   value);
			goto error;
		}

		if (do_print) cf_log_info(cs, "\ttype = %s", value);
	}

	cp = cf_pair_find(cs, "virtual_server");
	if (cp) {
		pool->virtual_server = cf_pair_value(cp);
		if (!pool->virtual_server) {
			cf_log_err_cp(cp, "No value given for virtual_server");
			goto error;
		}

		if (do_print) {
			cf_log_info(cs, "\tvirtual_server = %s", pool->virtual_server);
		}

		if (!cf_section_sub_find_name2(rc->cs, "server", pool->virtual_server)) {
			cf_log_err_cp(cp, "No such server %s", pool->virtual_server);
			goto error;
		}

	}

	num_home_servers = 0;
	for (cp = cf_pair_find(cs, "home_server");
	     cp != NULL;
	     cp = cf_pair_find_next(cs, cp, "home_server")) {
		home_server_t myhome;

		value = cf_pair_value(cp);

		memset(&myhome, 0, sizeof(myhome));
		myhome.name = value;
		myhome.type = server_type;

		home = rbtree_finddata(home_servers_byname, &myhome);
		if (!home) {
			switch (server_type) {
			case HOME_TYPE_AUTH:
			case HOME_TYPE_ACCT:
				myhome.type = HOME_TYPE_AUTH_ACCT;
				home = rbtree_finddata(home_servers_byname, &myhome);
				break;

			default:
				break;
			}
		}

		if (!home) {
			ERROR("Failed to find home server %s", value);
			goto error;
		}

		if (do_print) cf_log_info(cs, "\thome_server = %s", home->name);
		pool->servers[num_home_servers++] = home;
	} /* loop over home_server's */

	if (pool->fallback && do_print) {
		cf_log_info(cs, "\tfallback = %s", pool->fallback->name);
	}

	if (!realm_pool_add(pool, cs)) goto error;

	if (do_print) cf_log_info(cs, " }");

	cf_data_add(cs, "home_server_pool", pool, free);

	rad_assert(pool->server_type != 0);

	return 1;

 error:
	if (do_print) cf_log_info(cs, " }");
	free(pool);
	return 0;
}
#endif

static int old_server_add(realm_config_t *rc, CONF_SECTION *cs,
			  char const *realm,
			  char const *name, char const *secret,
			  home_pool_type_t ldflag, home_pool_t **pool_p,
			  home_type_t type, char const *server)
{
#ifdef WITH_PROXY
	int i, insert_point, num_home_servers;
	home_server_t myhome, *home;
	home_pool_t mypool, *pool;
	CONF_SECTION *subcs;
#else
	(void) rc;		/* -Wunused */
	(void) realm;
	(void) secret;
	(void) ldflag;
	(void) type;
	(void) server;
#endif

	/*
	 *	LOCAL realms get sanity checked, and nothing else happens.
	 */
	if (strcmp(name, "LOCAL") == 0) {
		if (*pool_p) {
			cf_log_err_cs(cs, "Realm \"%s\" cannot be both LOCAL and remote", name);
			return 0;
		}
		return 1;
	}

#ifndef WITH_PROXY
	return 0;		/* Not proxying.  Can't do non-LOCAL realms */

#else
	mypool.name = realm;
	mypool.server_type = type;
	pool = rbtree_finddata(home_pools_byname, &mypool);
	if (pool) {
		if (pool->type != ldflag) {
			cf_log_err_cs(cs, "Inconsistent ldflag for server pool \"%s\"", name);
			return 0;
		}

		if (pool->server_type != type) {
			cf_log_err_cs(cs, "Inconsistent home server type for server pool \"%s\"", name);
			return 0;
		}
	}

	myhome.name = name;
	myhome.type = type;
	home = rbtree_finddata(home_servers_byname, &myhome);
	if (home) {
		WARN("Please use pools instead of authhost and accthost");

		if (secret && (strcmp(home->secret, secret) != 0)) {
			cf_log_err_cs(cs, "Inconsistent shared secret for home server \"%s\"", name);
			return 0;
		}

		if (home->type != type) {
			cf_log_err_cs(cs, "Inconsistent type for home server \"%s\"", name);
			return 0;
		}

		/*
		 *	See if the home server is already listed
		 *	in the pool.  If so, do nothing else.
		 */
		if (pool) for (i = 0; i < pool->num_home_servers; i++) {
			if (pool->servers[i] == home) {
				return 1;
			}
		}
	}

	/*
	 *	If we do have a pool, check that there is room to
	 *	insert the home server we've found, or the one that we
	 *	create here.
	 *
	 *	Note that we insert it into the LAST available
	 *	position, in order to maintain the same order as in
	 *	the configuration files.
	 */
	insert_point = -1;
	if (pool) {
		for (i = pool->num_home_servers - 1; i >= 0; i--) {
			if (pool->servers[i]) break;

			if (!pool->servers[i]) {
				insert_point = i;
			}
		}

		if (insert_point < 0) {
			cf_log_err_cs(cs, "No room in pool to add home server \"%s\".  Please update the realm configuration to use the new-style home servers and server pools.", name);
			return 0;
		}
	}

	/*
	 *	No home server, allocate one.
	 */
	if (!home) {
		char const *p;
		char *q;

		home = talloc_zero(rc, home_server_t);
		home->name = name;
		home->type = type;
		home->secret = secret;
		home->cs = cs;
		home->proto = IPPROTO_UDP;

		p = strchr(name, ':');
		if (!p) {
			if (type == HOME_TYPE_AUTH) {
				home->port = PW_AUTH_UDP_PORT;
			} else {
				home->port = PW_ACCT_UDP_PORT;
			}

			p = name;
			q = NULL;

		} else if (p == name) {
			cf_log_err_cs(cs, "Invalid hostname %s", name);
			talloc_free(home);
			return 0;
		} else {
			unsigned long port = strtoul(p + 1, NULL, 0);
			if ((port == 0) || (port > 65535)) {
				cf_log_err_cs(cs, "Invalid port %s", p + 1);
				talloc_free(home);
				return 0;
			}

			home->port = (uint16_t)port;
			q = talloc_array(home, char, (p - name) + 1);
			memcpy(q, name, (p - name));
			q[p - name] = '\0';
			p = q;
		}

		if (!server) {
			if (ip_hton(&home->ipaddr, AF_UNSPEC, p, false) < 0) {
				cf_log_err_cs(cs,
					   "Failed looking up hostname %s.",
					   p);
				talloc_free(home);
				talloc_free(q);
				return 0;
			}
			home->src_ipaddr.af = home->ipaddr.af;
		} else {
			home->ipaddr.af = AF_UNSPEC;
			home->server = server;
		}
		talloc_free(q);

		/*
		 *	Use the old-style configuration.
		 */
		home->max_outstanding = 65535*16;
		home->zombie_period = rc->retry_delay * rc->retry_count;
		if (home->zombie_period < 2) home->zombie_period = 30;
		home->response_window.tv_sec = home->zombie_period - 1;
		home->response_window.tv_usec = 0;

		home->ping_check = HOME_PING_CHECK_NONE;

		home->revive_interval = rc->dead_time;

		if (rbtree_finddata(home_servers_byaddr, home)) {
			cf_log_err_cs(cs, "Home server %s has the same IP address and/or port as another home server.", name);
			talloc_free(home);
			return 0;
		}

		if (!rbtree_insert(home_servers_byname, home)) {
			cf_log_err_cs(cs, "Internal error %d adding home server %s.", __LINE__, name);
			talloc_free(home);
			return 0;
		}

		if (!rbtree_insert(home_servers_byaddr, home)) {
			rbtree_deletebydata(home_servers_byname, home);
			cf_log_err_cs(cs, "Internal error %d adding home server %s.", __LINE__, name);
			talloc_free(home);
			return 0;
		}

#ifdef WITH_STATS
		home->number = home_server_max_number++;
		if (!rbtree_insert(home_servers_bynumber, home)) {
			rbtree_deletebydata(home_servers_byname, home);
			if (home->ipaddr.af != AF_UNSPEC) {
				rbtree_deletebydata(home_servers_byname, home);
			}
			cf_log_err_cs(cs,
				   "Internal error %d adding home server %s.",
				   __LINE__, name);
			talloc_free(home);
			return 0;
		}
#endif
	}

	/*
	 *	We now have a home server, see if we can insert it
	 *	into pre-existing pool.
	 */
	if (insert_point >= 0) {
		rad_assert(pool != NULL);
		pool->servers[insert_point] = home;
		return 1;
	}

	rad_assert(pool == NULL);
	rad_assert(home != NULL);

	/*
	 *	Count the old-style realms of this name.
	 */
	num_home_servers = 0;
	for (subcs = cf_section_find_next(cs, NULL, "realm");
	     subcs != NULL;
	     subcs = cf_section_find_next(cs, subcs, "realm")) {
		char const *this = cf_section_name2(subcs);

		if (!this || (strcmp(this, realm) != 0)) continue;
		num_home_servers++;
	}

	if (num_home_servers == 0) {
		cf_log_err_cs(cs, "Internal error counting pools for home server %s.", name);
		talloc_free(home);
		return 0;
	}

	pool = server_pool_alloc(realm, ldflag, type, num_home_servers);
	if (!pool) {
		cf_log_err_cs(cs, "Out of memory");
		return 0;
	}

	pool->cs = cs;

	pool->servers[0] = home;

	if (!rbtree_insert(home_pools_byname, pool)) {
		rad_assert("Internal sanity check failed" == NULL);
		return 0;
	}

	*pool_p = pool;

	return 1;
#endif
}

static int old_realm_config(realm_config_t *rc, CONF_SECTION *cs, REALM *r)
{
	char const *host;
	char const *secret = NULL;
	home_pool_type_t ldflag;
	CONF_PAIR *cp;

	cp = cf_pair_find(cs, "ldflag");
	ldflag = HOME_POOL_FAIL_OVER;
	if (cp) {
		host = cf_pair_value(cp);
		if (!host) {
			cf_log_err_cp(cp, "No value specified for ldflag");
			return 0;
		}

		if (strcasecmp(host, "fail_over") == 0) {
			cf_log_info(cs, "\tldflag = fail_over");

		} else if (strcasecmp(host, "round_robin") == 0) {
			ldflag = HOME_POOL_LOAD_BALANCE;
			cf_log_info(cs, "\tldflag = round_robin");

		} else {
			cf_log_err_cs(cs, "Unknown value \"%s\" for ldflag", host);
			return 0;
		}
	} /* else don't print it. */

	/*
	 *	Allow old-style if it doesn't exist, or if it exists and
	 *	it's LOCAL.
	 */
	cp = cf_pair_find(cs, "authhost");
	if (cp) {
		host = cf_pair_value(cp);
		if (!host) {
			cf_log_err_cp(cp, "No value specified for authhost");
			return 0;
		}

		if (strcmp(host, "LOCAL") != 0) {
			cp = cf_pair_find(cs, "secret");
			if (!cp) {
				cf_log_err_cs(cs, "No shared secret supplied for realm: %s", r->name);
				return 0;
			}

			secret = cf_pair_value(cp);
			if (!secret) {
				cf_log_err_cp(cp, "No value specified for secret");
				return 0;
			}
		}

		cf_log_info(cs, "\tauthhost = %s",  host);

		if (!old_server_add(rc, cs, r->name, host, secret, ldflag,
				    &r->auth_pool, HOME_TYPE_AUTH, NULL)) {
			return 0;
		}
	}

	cp = cf_pair_find(cs, "accthost");
	if (cp) {
		host = cf_pair_value(cp);
		if (!host) {
			cf_log_err_cp(cp, "No value specified for accthost");
			return 0;
		}

		/*
		 *	Don't look for a secret again if it was found
		 *	above.
		 */
		if ((strcmp(host, "LOCAL") != 0) && !secret) {
			cp = cf_pair_find(cs, "secret");
			if (!cp) {
				cf_log_err_cs(cs, "No shared secret supplied for realm: %s", r->name);
				return 0;
			}

			secret = cf_pair_value(cp);
			if (!secret) {
				cf_log_err_cp(cp, "No value specified for secret");
				return 0;
			}
		}

		cf_log_info(cs, "\taccthost = %s", host);

		if (!old_server_add(rc, cs, r->name, host, secret, ldflag,
				    &r->acct_pool, HOME_TYPE_ACCT, NULL)) {
			return 0;
		}
	}

	cp = cf_pair_find(cs, "virtual_server");
	if (cp) {
		host = cf_pair_value(cp);
		if (!host) {
			cf_log_err_cp(cp, "No value specified for virtual_server");
			return 0;
		}

		cf_log_info(cs, "\tvirtual_server = %s", host);

		if (!old_server_add(rc, cs, r->name, host, "", ldflag,
				    &r->auth_pool, HOME_TYPE_AUTH, host)) {
			return 0;
		}
		if (!old_server_add(rc, cs, r->name, host, "", ldflag,
				    &r->acct_pool, HOME_TYPE_ACCT, host)) {
			return 0;
		}
	}

	if (secret) {
		if (rad_debug_lvl <= 2) {
			cf_log_info(cs, "\tsecret = <<< secret >>>");
		} else {
			cf_log_info(cs, "\tsecret = %s", secret);
		}
	}

	return 1;

}


#ifdef WITH_PROXY
static int add_pool_to_realm(realm_config_t *rc, CONF_SECTION *cs,
			     char const *name, home_pool_t **dest,
			     home_type_t server_type, bool do_print)
{
	home_pool_t mypool, *pool;

	mypool.name = name;
	mypool.server_type = server_type;

	pool = rbtree_finddata(home_pools_byname, &mypool);
	if (!pool) {
		CONF_SECTION *pool_cs;

		pool_cs = cf_section_sub_find_name2(rc->cs,
						    "home_server_pool",
						    name);
		if (!pool_cs) {
			pool_cs = cf_section_sub_find_name2(rc->cs,
							    "server_pool",
							    name);
		}
		if (!pool_cs) {
			cf_log_err_cs(cs, "Failed to find home_server_pool \"%s\"", name);
			return 0;
		}

		if (!server_pool_add(rc, pool_cs, server_type, do_print)) {
			return 0;
		}

		pool = rbtree_finddata(home_pools_byname, &mypool);
		if (!pool) {
			ERROR("Internal sanity check failed in add_pool_to_realm");
			return 0;
		}
	}

	if (pool->server_type != server_type) {
		cf_log_err_cs(cs, "Incompatible home_server_pool \"%s\" (mixed auth_pool / acct_pool)", name);
		return 0;
	}

	*dest = pool;

	return 1;
}
#endif


static int realm_add(realm_config_t *rc, CONF_SECTION *cs)
{
	char const *name2;
	REALM *r = NULL;
	CONF_PAIR *cp;
#ifdef WITH_PROXY
	home_pool_t *auth_pool, *acct_pool;
	char const *auth_pool_name, *acct_pool_name;
#ifdef WITH_COA
	char const *coa_pool_name;
	home_pool_t *coa_pool;
#endif
#endif

	name2 = cf_section_name1(cs);
	if (!name2 || (strcasecmp(name2, "realm") != 0)) {
		cf_log_err_cs(cs, "Section is not a realm");
		return 0;
	}

	name2 = cf_section_name2(cs);
	if (!name2) {
		cf_log_err_cs(cs, "Realm section is missing the realm name");
		return 0;
	}

#ifdef WITH_PROXY
	auth_pool = acct_pool = NULL;
	auth_pool_name = acct_pool_name = NULL;
#ifdef WITH_COA
	coa_pool = NULL;
	coa_pool_name = NULL;
#endif

	/*
	 *	Prefer new configuration to old one.
	 */
	cp = cf_pair_find(cs, "pool");
	if (!cp) cp = cf_pair_find(cs, "home_server_pool");
	if (cp) auth_pool_name = cf_pair_value(cp);
	if (cp && auth_pool_name) {
		acct_pool_name = auth_pool_name;
		if (!add_pool_to_realm(rc, cs,
				       auth_pool_name, &auth_pool,
				       HOME_TYPE_AUTH, 1)) {
			return 0;
		}
		if (!add_pool_to_realm(rc, cs,
				       auth_pool_name, &acct_pool,
				       HOME_TYPE_ACCT, 0)) {
			return 0;
		}
	}

	cp = cf_pair_find(cs, "auth_pool");
	if (cp) auth_pool_name = cf_pair_value(cp);
	if (cp && auth_pool_name) {
		if (auth_pool) {
			cf_log_err_cs(cs, "Cannot use \"pool\" and \"auth_pool\" at the same time");
			return 0;
		}
		if (!add_pool_to_realm(rc, cs,
				       auth_pool_name, &auth_pool,
				       HOME_TYPE_AUTH, 1)) {
			return 0;
		}
	}

	cp = cf_pair_find(cs, "acct_pool");
	if (cp) acct_pool_name = cf_pair_value(cp);
	if (cp && acct_pool_name) {
		bool do_print = true;

		if (acct_pool) {
			cf_log_err_cs(cs, "Cannot use \"pool\" and \"acct_pool\" at the same time");
			return 0;
		}

		if (!auth_pool ||
		    (auth_pool_name &&
		     (strcmp(auth_pool_name, acct_pool_name) != 0))) {
			do_print = true;
		}

		if (!add_pool_to_realm(rc, cs,
				       acct_pool_name, &acct_pool,
				       HOME_TYPE_ACCT, do_print)) {
			return 0;
		}
	}

#ifdef WITH_COA
	cp = cf_pair_find(cs, "coa_pool");
	if (cp) coa_pool_name = cf_pair_value(cp);
	if (cp && coa_pool_name) {
		bool do_print = true;

		if (!add_pool_to_realm(rc, cs,
				       coa_pool_name, &coa_pool,
				       HOME_TYPE_COA, do_print)) {
			return 0;
		}
	}
#endif
#endif

	cf_log_info(cs, " realm %s {", name2);

#ifdef WITH_PROXY
	/*
	 *	The realm MAY already exist if it's an old-style realm.
	 *	In that case, merge the old-style realm with this one.
	 */
	r = realm_find2(name2);
	if (r && (strcmp(r->name, name2) == 0)) {
		if (cf_pair_find(cs, "auth_pool") ||
		    cf_pair_find(cs, "acct_pool")) {
			cf_log_err_cs(cs, "Duplicate realm \"%s\"", name2);
			goto error;
		}

		if (!old_realm_config(rc, cs, r)) {
			goto error;
		}

		cf_log_info(cs, " } # realm %s", name2);
		return 1;
	}
#endif

	r = talloc_zero(rc, REALM);
	r->name = name2;
	r->strip_realm = true;
#ifdef WITH_PROXY
	r->auth_pool = auth_pool;
	r->acct_pool = acct_pool;
#ifdef WITH_COA
	r->coa_pool = coa_pool;
#endif

	if (auth_pool_name &&
	    (auth_pool_name == acct_pool_name)) { /* yes, ptr comparison */
		cf_log_info(cs, "\tpool = %s", auth_pool_name);
	} else {
		if (auth_pool_name) cf_log_info(cs, "\tauth_pool = %s", auth_pool_name);
		if (acct_pool_name) cf_log_info(cs, "\tacct_pool = %s", acct_pool_name);
#ifdef WITH_COA
		if (coa_pool_name) cf_log_info(cs, "\tcoa_pool = %s", coa_pool_name);
#endif
	}
#endif

	cp = cf_pair_find(cs, "nostrip");
	if (cp && (cf_pair_value(cp) == NULL)) {
		r->strip_realm = false;
		cf_log_info(cs, "\tnostrip");
	}

	/*
	 *	We're a new-style realm.  Complain if we see the old
	 *	directives.
	 */
	if (r->auth_pool || r->acct_pool) {
		if (((cp = cf_pair_find(cs, "authhost")) != NULL) ||
		    ((cp = cf_pair_find(cs, "accthost")) != NULL) ||
		    ((cp = cf_pair_find(cs, "secret")) != NULL) ||
		    ((cp = cf_pair_find(cs, "ldflag")) != NULL)) {
			WARN("Ignoring old-style configuration entry \"%s\" in realm \"%s\"", cf_pair_attr(cp), r->name);
		}


		/*
		 *	The realm MAY be an old-style realm, as there
		 *	was no auth_pool or acct_pool.  Double-check
		 *	it, just to be safe.
		 */
	} else if (!old_realm_config(rc, cs, r)) {
		goto error;
	}

	if (!realm_realm_add(r, cs)) {
		goto error;
	}

	cf_log_info(cs, " }");

	return 1;

 error:
	cf_log_info(cs, " } # realm %s", name2);
	return 0;
}

#ifdef HAVE_REGEX
int realm_realm_add(REALM *r, CONF_SECTION *cs)
#else
int realm_realm_add(REALM *r, UNUSED CONF_SECTION *cs)
#endif
{
	/*
	 *	The structs aren't mutex protected.  Refuse to destroy
	 *	the server.
	 */
	if (event_loop_started && !realm_config->dynamic) {
		DEBUG("Must set \"dynamic = true\" in proxy.conf");
		return 0;
	}

#ifdef HAVE_REGEX
	/*
	 *	It's a regex.  Sanity check it, and add it to a
	 *	separate list.
	 */
	if (r->name[0] == '~') {
		ssize_t slen;
		realm_regex_t *rr, **last;

		rr = talloc(r, realm_regex_t);

		/*
		 *	Include substring matches.
		 */
		slen = regex_compile(rr, &rr->preg, r->name + 1, strlen(r->name) - 1, true, false, false, false);
		if (slen <= 0) {
			char *spaces, *text;

			fr_canonicalize_error(r, &spaces, &text, slen, r->name + 1);

			cf_log_err_cs(cs, "Invalid regular expression:");
			cf_log_err_cs(cs, "%s", text);
			cf_log_err_cs(cs, "%s^ %s", spaces, fr_strerror());

			talloc_free(spaces);
			talloc_free(text);
			talloc_free(rr);

			return 0;
		}

		last = &realms_regex;
		while (*last) last = &((*last)->next);  /* O(N^2)... sue me. */

		rr->realm = r;
		rr->next = NULL;

		*last = rr;
		return 1;
	}
#endif

	if (!rbtree_insert(realms_byname, r)) {
		rad_assert("Internal sanity check failed" == NULL);
		return 0;
	}

	return 1;
}

#ifdef WITH_COA

static int pool_peek_type(CONF_SECTION *config, CONF_SECTION *cs)
{
	int home;
	char const *name, *type;
	CONF_PAIR *cp;
	CONF_SECTION *server_cs;

	cp = cf_pair_find(cs, "home_server");
	if (!cp) {
		cf_log_err_cs(cs, "Pool does not contain a \"home_server\" entry");
		return HOME_TYPE_INVALID;
	}

	name = cf_pair_value(cp);
	if (!name) {
		cf_log_err_cp(cp, "home_server entry does not reference a home server");
		return HOME_TYPE_INVALID;
	}

	server_cs = cf_section_sub_find_name2(config, "home_server", name);
	if (!server_cs) {
		cf_log_err_cp(cp, "home_server \"%s\" does not exist", name);
		return HOME_TYPE_INVALID;
	}

	cp = cf_pair_find(server_cs, "type");
	if (!cp) {
		cf_log_err_cs(server_cs, "home_server %s does not contain a \"type\" entry", name);
		return HOME_TYPE_INVALID;
	}

	type = cf_pair_value(cp);
	if (!type) {
		cf_log_err_cs(server_cs, "home_server %s contains an empty \"type\" entry", name);
		return HOME_TYPE_INVALID;
	}

	home = fr_str2int(home_server_types, type, HOME_TYPE_INVALID);
	if (home == HOME_TYPE_INVALID) {
		cf_log_err_cs(server_cs, "home_server %s contains an invalid \"type\" entry of value \"%s\"", name, type);
		return HOME_TYPE_INVALID;
	}

	return home;		/* 'cause we miss it so much */
}
#endif

int realms_init(CONF_SECTION *config)
{
	CONF_SECTION *cs;
	int flags = 0;
#ifdef WITH_PROXY
	CONF_SECTION *server_cs;
#endif
	realm_config_t *rc;

	if (event_loop_started) return 1;

	rc = talloc_zero(NULL, realm_config_t);
	rc->cs = config;

#ifdef WITH_PROXY
	cs = cf_subsection_find_next(config, NULL, "proxy");
	if (cs) {
		if (cf_section_parse(cs, rc, proxy_config) < 0) {
			ERROR("Failed parsing proxy section");
			goto error;
		}
	} else {
		rc->dead_time = DEAD_TIME;
		rc->retry_count = RETRY_COUNT;
		rc->retry_delay = RETRY_DELAY;
		rc->fallback = false;
		rc->dynamic = false;
		rc->wake_all_if_all_dead= 0;
	}

	if (rc->dynamic) {
		flags = RBTREE_FLAG_LOCK;
	}

	home_servers_byaddr = rbtree_create(NULL, home_server_addr_cmp, home_server_free, flags);
	if (!home_servers_byaddr) goto error;

	home_servers_byname = rbtree_create(NULL, home_server_name_cmp, NULL, flags);
	if (!home_servers_byname) goto error;

#ifdef WITH_STATS
	home_servers_bynumber = rbtree_create(NULL, home_server_number_cmp, NULL, flags);
	if (!home_servers_bynumber) goto error;
#endif

	home_pools_byname = rbtree_create(NULL, home_pool_name_cmp, NULL, flags);
	if (!home_pools_byname) goto error;

	for (cs = cf_subsection_find_next(config, NULL, "home_server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "home_server")) {
	     	home_server_t *home;

	     	home = home_server_afrom_cs(rc, rc, cs);
	     	if (!home) goto error;
		if (!realm_home_server_add(home)) goto error;
	}

	/*
	 *	Loop over virtual servers to find home servers which
	 *	are defined in them.
	 */
	for (server_cs = cf_subsection_find_next(config, NULL, "server");
	     server_cs != NULL;
	     server_cs = cf_subsection_find_next(config, server_cs, "server")) {
		for (cs = cf_subsection_find_next(server_cs, NULL, "home_server");
		     cs != NULL;
		     cs = cf_subsection_find_next(server_cs, cs, "home_server")) {
			home_server_t *home;

			home = home_server_afrom_cs(rc, rc, cs);
			if (!home) goto error;
			if (!realm_home_server_add(home)) goto error;
		}
	}
#endif

	/*
	 *	Now create the realms, which point to the home servers
	 *	and home server pools.
	 */
	realms_byname = rbtree_create(NULL, realm_name_cmp, NULL, flags);
	if (!realms_byname) goto error;

	for (cs = cf_subsection_find_next(config, NULL, "realm");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "realm")) {
		if (!realm_add(rc, cs)) {
		error:
			realms_free();
			/*
			 *	Must be called after realms_free as home_servers
			 *	parented by rc are in trees freed by realms_free()
			 */
			talloc_free(rc);
			return 0;
		}
	}

#ifdef WITH_COA
	/*
	 *	CoA pools aren't necessarily tied to realms.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "home_server_pool");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "home_server_pool")) {
		int type;

		/*
		 *	Pool was already loaded.
		 */
		if (cf_data_find(cs, "home_server_pool")) continue;

		type = pool_peek_type(config, cs);
		if (type == HOME_TYPE_INVALID) goto error;
		if (!server_pool_add(rc, cs, type, true)) goto error;
	}
#endif

#ifdef WITH_PROXY
	xlat_register("home_server", xlat_home_server, NULL, NULL);
	xlat_register("home_server_pool", xlat_server_pool, NULL, NULL);
#endif

	realm_config = rc;
	return 1;
}

/*
 *	Find a realm where "name" might be the regex.
 */
REALM *realm_find2(char const *name)
{
	REALM myrealm;
	REALM *realm;

	if (!name) name = "NULL";

	myrealm.name = name;
	realm = rbtree_finddata(realms_byname, &myrealm);
	if (realm) return realm;

#ifdef HAVE_REGEX
	if (realms_regex) {
		realm_regex_t *this;

		for (this = realms_regex; this != NULL; this = this->next) {
			if (strcmp(this->realm->name, name) == 0) {
				return this->realm;
			}
		}
	}
#endif

	/*
	 *	Couldn't find a realm.  Look for DEFAULT.
	 */
	myrealm.name = "DEFAULT";
	return rbtree_finddata(realms_byname, &myrealm);
}


/*
 *	Find a realm in the REALM list.
 */
REALM *realm_find(char const *name)
{
	REALM myrealm;
	REALM *realm;

	if (!name) name = "NULL";

	myrealm.name = name;
	realm = rbtree_finddata(realms_byname, &myrealm);
	if (realm) return realm;

#ifdef HAVE_REGEX
	if (realms_regex) {
		realm_regex_t *this;

		for (this = realms_regex;
		     this != NULL;
		     this = this->next) {
			int compare;

			compare = regex_exec(this->preg, name, strlen(name), NULL, NULL);
			if (compare < 0) {
				ERROR("Failed performing realm comparison: %s", fr_strerror());
				return NULL;
			}
			if (compare == 1) return this->realm;
		}
	}
#endif

	/*
	 *	Couldn't find a realm.  Look for DEFAULT.
	 */
	myrealm.name = "DEFAULT";
	return rbtree_finddata(realms_byname, &myrealm);
}


#ifdef WITH_PROXY

/*
 *	Allocate the proxy list if it doesn't already exist, and copy request
 *	VPs into it. Setup src/dst IP addresses based on home server, and
 *	calculate and add the message-authenticator.
 *
 *	This is a distinct function from home_server_ldb, as not all home_server_t
 *	lookups result in the *CURRENT* request being proxied,
 *	as in rlm_replicate, and this may trigger asserts elsewhere in the
 *	server.
 */
void home_server_update_request(home_server_t *home, REQUEST *request)
{

	/*
	 *	Allocate the proxy packet, only if it wasn't
	 *	already allocated by a module.  This check is
	 *	mainly to support the proxying of EAP-TTLS and
	 *	EAP-PEAP tunneled requests.
	 *
	 *	In those cases, the EAP module creates a
	 *	"fake" request, and recursively passes it
	 *	through the authentication stage of the
	 *	server.  The module then checks if the request
	 *	was supposed to be proxied, and if so, creates
	 *	a proxy packet from the TUNNELED request, and
	 *	not from the EAP request outside of the
	 *	tunnel.
	 *
	 *	The proxy then works like normal, except that
	 *	the response packet is "eaten" by the EAP
	 *	module, and encapsulated into an EAP packet.
	 */
	if (!request->proxy) {
		request->proxy = rad_alloc(request, true);
		if (!request->proxy) {
			ERROR("no memory");
			fr_exit(1);
		}

		/*
		 *	Copy the request, then look up name
		 *	and plain-text password in the copy.
		 *
		 *	Note that the User-Name attribute is
		 *	the *original* as sent over by the
		 *	client.  The Stripped-User-Name
		 *	attribute is the one hacked through
		 *	the 'hints' file.
		 */
		request->proxy->vps = fr_pair_list_copy(request->proxy,
					       request->packet->vps);
	}

	/*
	 *	Update the various fields as appropriate.
	 */
	request->proxy->src_ipaddr = home->src_ipaddr;
	request->proxy->src_port = 0;
	request->proxy->dst_ipaddr = home->ipaddr;
	request->proxy->dst_port = home->port;
#ifdef WITH_TCP
	request->proxy->proto = home->proto;
#endif
	request->home_server = home;

	/*
	 *	Access-Requests have a Message-Authenticator added,
	 *	unless one already exists.
	 */
	if ((request->packet->code == PW_CODE_ACCESS_REQUEST) &&
	    !fr_pair_find_by_num(request->proxy->vps, PW_MESSAGE_AUTHENTICATOR, 0, TAG_ANY)) {
		fr_pair_make(request->proxy, &request->proxy->vps,
			 "Message-Authenticator", "0x00",
			 T_OP_SET);
	}
}

home_server_t *home_server_ldb(char const *realmname,
			     home_pool_t *pool, REQUEST *request)
{
	int		start;
	int		count;
	home_server_t	*found = NULL;
	home_server_t	*zombie = NULL;
	VALUE_PAIR	*vp;
	uint32_t	hash;

	/*
	 *	Determine how to pick choose the home server.
	 */
	switch (pool->type) {


		/*
		 *	For load-balancing by client IP address, we
		 *	pick a home server by hashing the client IP.
		 *
		 *	This isn't as even a load distribution as
		 *	tracking the State attribute, but it's better
		 *	than nothing.
		 */
	case HOME_POOL_CLIENT_BALANCE:
		switch (request->packet->src_ipaddr.af) {
		case AF_INET:
			hash = fr_hash(&request->packet->src_ipaddr.ipaddr.ip4addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip4addr));
			break;

		case AF_INET6:
			hash = fr_hash(&request->packet->src_ipaddr.ipaddr.ip6addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip6addr));
			break;

		default:
			hash = 0;
			break;
		}
		start = hash % pool->num_home_servers;
		break;

	case HOME_POOL_CLIENT_PORT_BALANCE:
		switch (request->packet->src_ipaddr.af) {
		case AF_INET:
			hash = fr_hash(&request->packet->src_ipaddr.ipaddr.ip4addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip4addr));
			break;

		case AF_INET6:
			hash = fr_hash(&request->packet->src_ipaddr.ipaddr.ip6addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip6addr));
			break;

		default:
			hash = 0;
			break;
		}
		hash = fr_hash_update(&request->packet->src_port,
				      sizeof(request->packet->src_port), hash);
		start = hash % pool->num_home_servers;
		break;

	case HOME_POOL_KEYED_BALANCE:
		if ((vp = fr_pair_find_by_num(request->config, PW_LOAD_BALANCE_KEY, 0, TAG_ANY)) != NULL) {
			hash = fr_hash(vp->vp_strvalue, vp->vp_length);
			start = hash % pool->num_home_servers;
			break;
		}
		/* FALL-THROUGH */

	case HOME_POOL_LOAD_BALANCE:
	case HOME_POOL_FAIL_OVER:
		start = 0;
		break;

	default:		/* this shouldn't happen... */
		start = 0;
		break;

	}

	/*
	 *	Starting with the home server we chose, loop through
	 *	all home servers.  If the current one is dead, skip
	 *	it.  If it is too busy, skip it.
	 *
	 *	Otherwise, use it.
	 */
	for (count = 0; count < pool->num_home_servers; count++) {
		home_server_t *home = pool->servers[(start + count) % pool->num_home_servers];

		if (!home) continue;

		/*
		 *	Skip dead home servers.
		 *
		 *	Home servers that are unknown, alive, or zombie
		 *	are used for proxying.
		 */
		if (home->state == HOME_STATE_IS_DEAD) {
			continue;
		}

		/*
		 *	This home server is too busy.  Choose another one.
		 */
		if (home->currently_outstanding >= home->max_outstanding) {
			continue;
		}

#ifdef WITH_DETAIL
		/*
		 *	We read the packet from a detail file, AND it
		 *	came from this server.  Don't re-proxy it
		 *	there.
		 */
		if ((request->listener->type == RAD_LISTEN_DETAIL) &&
		    (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) &&
		    (fr_ipaddr_cmp(&home->ipaddr, &request->packet->src_ipaddr) == 0)) {
			continue;
		}
#endif

		/*
		 *	Default virtual: ignore homes tied to a
		 *	virtual.
		 */
		if (!request->server && home->parent_server) {
			continue;
		}

		/*
		 *	A virtual AND home is tied to virtual,
		 *	ignore ones which don't match.
		 */
		if (request->server && home->parent_server &&
		    strcmp(request->server, home->parent_server) != 0) {
			continue;
		}

		/*
		 *	Allow request->server && !home->parent_server
		 *
		 *	i.e. virtuals can proxy to globally defined
		 *	homes.
		 */

		/*
		 *	It's zombie, so we remember the first zombie
		 *	we find, but we don't mark it as a "live"
		 *	server.
		 */
		if (home->state == HOME_STATE_ZOMBIE) {
			if (!zombie) zombie = home;
			continue;
		}

		/*
		 *	We've found the first "live" one.  Use that.
		 */
		if (pool->type != HOME_POOL_LOAD_BALANCE) {
			found = home;
			break;
		}

		/*
		 *	Otherwise we're doing some kind of load balancing.
		 *	If we haven't found one yet, pick this one.
		 */
		if (!found) {
			found = home;
			continue;
		}

		RDEBUG3("PROXY %s %d\t%s %d",
		       found->log_name, found->currently_outstanding,
		       home->log_name, home->currently_outstanding);

		/*
		 *	Prefer this server if it's less busy than the
		 *	one we had previously found.
		 */
		if (home->currently_outstanding < found->currently_outstanding) {
			RDEBUG3("PROXY Choosing %s: It's less busy than %s",
			       home->log_name, found->log_name);
			found = home;
			continue;
		}

		/*
		 *	Ignore servers which are busier than the one
		 *	we found.
		 */
		if (home->currently_outstanding > found->currently_outstanding) {
			RDEBUG3("PROXY Skipping %s: It's busier than %s",
			       home->log_name, found->log_name);
			continue;
		}

		/*
		 *	From the list of servers which have the same
		 *	load, choose one at random.
		 */
		if (((count + 1) * (fr_rand() & 0xffff)) < (uint32_t) 0x10000) {
			found = home;
		}
	} /* loop over the home servers */

	/*
	 *	We have no live servers, BUT we have a zombie.  Use
	 *	the zombie as a last resort.
	 */
	if (!found && zombie) {
		found = zombie;
		zombie = NULL;
	}

	/*
	 *	There's a fallback if they're all dead.
	 */
	if (!found && pool->fallback) {
		found = pool->fallback;

		WARN("Home server pool %s failing over to fallback %s",
		      pool->name, found->server);
		if (pool->in_fallback) goto update_and_return;

		pool->in_fallback = true;

		/*
		 *      Run the trigger once an hour saying that
		 *      they're all dead.
		 */
		if ((pool->time_all_dead + 3600) < request->timestamp) {
			pool->time_all_dead = request->timestamp;
			exec_trigger(request, pool->cs, "home_server_pool.fallback", false);
		}
	}

	if (found) {
	update_and_return:
		if ((found != pool->fallback) && pool->in_fallback) {
			pool->in_fallback = false;
			exec_trigger(request, pool->cs, "home_server_pool.normal", false);
		}

		return found;
	}

	/*
	 *	No live match found, and no fallback to the "DEFAULT"
	 *	realm.  We fix this by blindly marking all servers as
	 *	"live".  But only do it for ones that don't support
	 *	"pings", as they will be marked live when they
	 *	actually are live.
	 */
	if (!realm_config->fallback &&
	    realm_config->wake_all_if_all_dead) {
		for (count = 0; count < pool->num_home_servers; count++) {
			home_server_t *home = pool->servers[count];

			if (!home) continue;

			if ((home->state == HOME_STATE_IS_DEAD) &&
			    (home->ping_check == HOME_PING_CHECK_NONE)) {
				home->state = HOME_STATE_ALIVE;
				home->response_timeouts = 0;
				if (!found) found = home;
			}
		}

		if (found) goto update_and_return;
	}

	/*
	 *	Still nothing.  Look up the DEFAULT realm, but only
	 *	if we weren't looking up the NULL or DEFAULT realms.
	 */
	if (realm_config->fallback &&
	    realmname &&
	    (strcmp(realmname, "NULL") != 0) &&
	    (strcmp(realmname, "DEFAULT") != 0)) {
		REALM *rd = realm_find("DEFAULT");

		if (!rd) return NULL;

		pool = NULL;
		if (request->packet->code == PW_CODE_ACCESS_REQUEST) {
			pool = rd->auth_pool;

		} else if (request->packet->code == PW_CODE_ACCOUNTING_REQUEST) {
			pool = rd->acct_pool;
		}
		if (!pool) return NULL;

		RDEBUG2("PROXY - realm %s has no live home servers.  Falling back to the DEFAULT realm.", realmname);
		return home_server_ldb(rd->name, pool, request);
	}

	/*
	 *	Still haven't found anything.  Oh well.
	 */
	return NULL;
}


home_server_t *home_server_find(fr_ipaddr_t *ipaddr, uint16_t port,
#ifndef WITH_TCP
				UNUSED
#endif
				int proto)
{
	home_server_t myhome;

	memset(&myhome, 0, sizeof(myhome));
	myhome.ipaddr = *ipaddr;
	myhome.src_ipaddr.af = ipaddr->af;
	myhome.port = port;
#ifdef WITH_TCP
	myhome.proto = proto;
#else
	myhome.proto = IPPROTO_UDP;
#endif
	myhome.server = NULL;	/* we're not called for internal proxying */

	return rbtree_finddata(home_servers_byaddr, &myhome);
}

#ifdef WITH_COA
home_server_t *home_server_byname(char const *name, int type)
{
	home_server_t myhome;

	memset(&myhome, 0, sizeof(myhome));
	myhome.type = type;
	myhome.name = name;

	return rbtree_finddata(home_servers_byname, &myhome);
}
#endif

#ifdef WITH_STATS
home_server_t *home_server_bynumber(int number)
{
	home_server_t myhome;

	memset(&myhome, 0, sizeof(myhome));
	myhome.number = number;
	myhome.server = NULL;	/* we're not called for internal proxying */

	return rbtree_finddata(home_servers_bynumber, &myhome);
}
#endif

home_pool_t *home_pool_byname(char const *name, int type)
{
	home_pool_t mypool;

	memset(&mypool, 0, sizeof(mypool));
	mypool.name = name;
	mypool.server_type = type;
	return rbtree_finddata(home_pools_byname, &mypool);
}

#endif
