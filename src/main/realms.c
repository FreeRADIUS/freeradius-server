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

static rbtree_t *realms_byname = NULL;

static rbtree_t	*home_servers_byaddr = NULL;
static rbtree_t	*home_servers_byname = NULL;

static rbtree_t	*home_pools_byname = NULL;

static int realm_name_cmp(const void *one, const void *two)
{
	const REALM *a = one;
	const REALM *b = two;

	return strcasecmp(a->name, b->name);
}


static int home_server_name_cmp(const void *one, const void *two)
{
	const home_server *a = one;
	const home_server *b = two;

	return strcasecmp(a->name, b->name);
}

static int home_server_addr_cmp(const void *one, const void *two)
{
	const home_server *a = one;
	const home_server *b = two;

	if (a->port < b->port) return -1;
	if (a->port > b->port) return +1;

	return lrad_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}


static int home_pool_name_cmp(const void *one, const void *two)
{
	const home_pool_t *a = one;
	const home_pool_t *b = two;

	return strcasecmp(a->name, b->name);
}


void realms_free(void)
{
	rbtree_free(home_servers_byname);
	home_servers_byname = NULL;

	rbtree_free(home_servers_byaddr);
	home_servers_byaddr = NULL;

	rbtree_free(home_pools_byname);
	home_pools_byname = NULL;

	rbtree_free(realms_byname);
	realms_byname = NULL;
}


int realms_init(const char *filename)
{
	CONF_SECTION *cs;

	if (realms_byname) return 1;

	realms_byname = rbtree_create(realm_name_cmp, free, 0);
	if (!realms_byname) {
		realms_free();
		return 0;
	}

	home_servers_byaddr = rbtree_create(home_server_addr_cmp, free, 0);
	if (!home_servers_byaddr) {
		realms_free();
		return 0;
	}

	home_servers_byname = rbtree_create(home_server_name_cmp, NULL, 0);
	if (!home_servers_byname) {
		realms_free();
		return 0;
	}

	home_pools_byname = rbtree_create(home_pool_name_cmp, free, 0);
	if (!home_pools_byname) {
		realms_free();
		return 0;
	}

	for (cs = cf_subsection_find_next(mainconfig.config, NULL, "realm");
	     cs != NULL;
	     cs = cf_subsection_find_next(mainconfig.config, cs, "realm")) {
		if (!realm_add(filename, cs)) {
			realms_free();
			return 0;
		}
	}

	return 1;
}

static struct in_addr hs_ip4addr;
static struct in6_addr hs_ip6addr;
static char *hs_type = NULL;
static char *hs_check = NULL;

static CONF_PARSER home_server_config[] = {
	{ "ipaddr",  PW_TYPE_IPADDR,
	  0, &hs_ip4addr,  NULL },
	{ "ipv6addr",  PW_TYPE_IPV6ADDR,
	  0, &hs_ip6addr, NULL },

	{ "hostname",  PW_TYPE_STRING_PTR,
	  offsetof(home_server,hostname), NULL,  NULL},
	{ "port", PW_TYPE_INTEGER,
	  offsetof(home_server,port), NULL,   "0" },

	{ "type",  PW_TYPE_STRING_PTR,
	  0, &hs_type, NULL },

	{ "secret",  PW_TYPE_STRING_PTR,
	  offsetof(home_server,secret), NULL,  NULL},

	{ "response_window", PW_TYPE_INTEGER,
	  offsetof(home_server,response_window), NULL,   "30" },
	{ "max_outstanding", PW_TYPE_INTEGER,
	  offsetof(home_server,max_outstanding), NULL,   "65536" },

	{ "zombie_period", PW_TYPE_INTEGER,
	  offsetof(home_server,zombie_period), NULL,   "40" },
	{ "status_check", PW_TYPE_STRING_PTR,
	  0, &hs_check,   "none" },
	{ "ping_check", PW_TYPE_STRING_PTR,
	  0, &hs_check,   "none" },

	{ "ping_interval", PW_TYPE_INTEGER,
	  offsetof(home_server,ping_interval), NULL,   "30" },
	{ "check_interval", PW_TYPE_INTEGER,
	  offsetof(home_server,ping_interval), NULL,   "30" },
	{ "num_answers_to_alive", PW_TYPE_INTEGER,
	  offsetof(home_server,num_pings_to_alive), NULL,   "3" },
	{ "num_pings_to_alive", PW_TYPE_INTEGER,
	  offsetof(home_server,num_pings_to_alive), NULL,   "3" },
	{ "revive_interval", PW_TYPE_INTEGER,
	  offsetof(home_server,revive_interval), NULL,   "300" },
	{ "status_check_timeout", PW_TYPE_INTEGER,
	  offsetof(home_server,ping_timeout), NULL,   "4" },

	{ "username",  PW_TYPE_STRING_PTR,
	  offsetof(home_server,ping_user_name), NULL,  NULL},
	{ "password",  PW_TYPE_STRING_PTR,
	  offsetof(home_server,ping_user_password), NULL,  NULL},
	
	{ NULL, -1, 0, NULL, NULL }		/* end the list */

};


static int home_server_add(const char *filename, CONF_SECTION *cs)
{
	const char *name2;
	home_server *home;

	name2 = cf_section_name1(cs);
	if (!name2 || (strcasecmp(name2, "home_server") != 0)) {
		radlog(L_ERR, "%s[%d]: Section is not a home_server.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	name2 = cf_section_name2(cs);
	if (!name2) {
		radlog(L_ERR, "%s[%d]: Home server section is missing a name.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	home = rad_malloc(sizeof(*home));
	memset(home, 0, sizeof(*home));

	home->name = name2;
	
	memset(&hs_ip4addr, 0, sizeof(hs_ip4addr));
	memset(&hs_ip6addr, 0, sizeof(hs_ip6addr));
	cf_section_parse(cs, home, home_server_config);

	if (!home->hostname && (htonl(hs_ip4addr.s_addr) == INADDR_NONE) &&
	    IN6_IS_ADDR_UNSPECIFIED(&hs_ip6addr)) {
		radlog(L_ERR, "%s[%d]: No hostname, IPv4 address, or IPv6 address defined for home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		free(hs_type);
		hs_type = NULL;
		free(hs_check);
		hs_check = NULL;
		return 0;
	}

	/*
	 *	FIXME: Parse home->hostname!
	 *
	 *	Right now, only ipaddr && ip6addr are used.
	 *	The old-style parsing still allows hostnames.
	 */
	if (htonl(hs_ip4addr.s_addr) != INADDR_NONE) {
		home->ipaddr.af = AF_INET;
		home->ipaddr.ipaddr.ip4addr = hs_ip4addr;

	} else if (!IN6_IS_ADDR_UNSPECIFIED(&hs_ip6addr)) {
		home->ipaddr.af = AF_INET6;
		home->ipaddr.ipaddr.ip6addr = hs_ip6addr;

	} else {
		radlog(L_ERR, "%s[%d]: FIXME: parse hostname for home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		free(hs_type);
		hs_type = NULL;
		free(hs_check);
		hs_check = NULL;
		return 0;
	}

	if (!home->port || (home->port > 65535)) {
		radlog(L_ERR, "%s[%d]: No port, or invalid port defined for home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		free(hs_type);
		hs_type = NULL;
		free(hs_check);
		hs_check = NULL;
		return 0;
	}

	if (0) {
		radlog(L_ERR, "%s[%d]: Fatal error!  Home server %s is ourselves!",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		free(hs_type);
		hs_type = NULL;
		free(hs_check);
		hs_check = NULL;
		return 0;
	}

	if (strcasecmp(hs_type, "auth") == 0) {
		home->type = HOME_TYPE_AUTH;

	} else if (strcasecmp(hs_type, "acct") == 0) {
		home->type = HOME_TYPE_ACCT;

	} else {
		radlog(L_ERR, "%s[%d]: Invalid type \"%s\" for home server %s.",
		       filename, cf_section_lineno(cs), hs_type, name2);
		free(home);
		free(hs_type);
		hs_type = NULL;
		free(hs_check);
		hs_check = NULL;
		return 0;
	}
	free(hs_type);
	hs_type = NULL;

	if (!home->secret) {
		radlog(L_ERR, "%s[%d]: No shared secret defined for home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		return 0;
	}

	if (strcasecmp(hs_check, "none") == 0) {
		home->ping_check = HOME_PING_CHECK_NONE;

	} else if (strcasecmp(hs_check, "status-server") == 0) {
		home->ping_check = HOME_PING_CHECK_STATUS_SERVER;

	} else if (strcasecmp(hs_check, "request") == 0) {
		home->ping_check = HOME_PING_CHECK_REQUEST;

	} else {
		radlog(L_ERR, "%s[%d]: Invalid ping_check \"%s\" for home server %s.",
		       filename, cf_section_lineno(cs), hs_check, name2);
		free(home);
		free(hs_check);
		hs_check = NULL;
		return 0;
	}
	free(hs_check);
	hs_check = NULL;

	if ((home->ping_check != HOME_PING_CHECK_NONE) &&
	    (home->ping_check != HOME_PING_CHECK_STATUS_SERVER)) {
		if (!home->ping_user_name) {
			radlog(L_INFO, "%s[%d]: You must supply a user name to enable ping checks",
			       filename, cf_section_lineno(cs));
			free(home);
			return 0;
		}

		if ((home->type == HOME_TYPE_AUTH) && 
		    !home->ping_user_password) {	
			radlog(L_INFO, "%s[%d]: You must supply a password to enable ping checks",
			       filename, cf_section_lineno(cs));
			free(home);
			return 0;
		}
	}

	if (rbtree_finddata(home_servers_byaddr, home)) {
		radlog(L_INFO, "%s[%d]: Ignoring duplicate home server %s.",
		       filename, cf_section_lineno(cs), name2);
		return 1;
	}

	if (!rbtree_insert(home_servers_byname, home)) {
		radlog(L_ERR, "%s[%d]: Internal error adding home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		return 0;
	}

	if (!rbtree_insert(home_servers_byaddr, home)) {
		rbtree_deletebydata(home_servers_byname, home);
		radlog(L_ERR, "%s[%d]: Internal error adding home server %s.",
		       filename, cf_section_lineno(cs), name2);
		free(home);
		return 0;
	}

	if (home->response_window < 5) home->response_window = 5;
	if (home->response_window > 60) home->response_window = 60;

	if (home->max_outstanding < 8) home->max_outstanding = 8;
	if (home->max_outstanding > 65536*16) home->max_outstanding = 65536*16;

	if (home->ping_interval < 6) home->ping_interval = 6;
	if (home->ping_interval > 120) home->ping_interval = 120;

	if (home->zombie_period < 20) home->zombie_period = 20;
	if (home->zombie_period > 120) home->zombie_period = 120;

	if (home->zombie_period < home->response_window) {
		home->zombie_period = home->response_window;
	}

	if (home->num_pings_to_alive < 3) home->num_pings_to_alive = 3;
	if (home->num_pings_to_alive > 10) home->num_pings_to_alive = 10;

	if (home->ping_timeout < 3) home->ping_timeout = 3;
	if (home->ping_timeout > 10) home->ping_timeout = 10;

	if (home->revive_interval < 60) home->revive_interval = 60;
	if (home->revive_interval > 3600) home->revive_interval = 3600;

	return 1;
}


static int server_pool_add(const char *filename, CONF_SECTION *cs)
{
	const char *name2;
	home_pool_t *pool;
	const char *value;
	CONF_PAIR *cp;
	int num_home_servers;

	name2 = cf_section_name1(cs);
	if (!name2 || (strcasecmp(name2, "server_pool") != 0)) {
		radlog(L_ERR, "%s[%d]: Section is not a server_pool.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	name2 = cf_section_name2(cs);
	if (!name2) {
		radlog(L_ERR, "%s[%d]: Server pool section is missing a name.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	num_home_servers = 0;
	for (cp = cf_pair_find(cs, "home_server");
	     cp != NULL;
	     cp = cf_pair_find_next(cs, cp, "home_server")) {
		num_home_servers++;
	}

	if (num_home_servers == 0) {
		radlog(L_ERR, "%s[%d]: No home servers defined in pool %s",
		       filename, cf_section_lineno(cs), name2);
		return 0;
	}

	pool = rad_malloc(sizeof(*pool) + num_home_servers * sizeof(pool->servers[0]));
	memset(pool, 0, sizeof(*pool) + num_home_servers * sizeof(pool->servers[0]));

	pool->type = HOME_POOL_FAIL_OVER;
	pool->name = name2;

	cp = cf_pair_find(cs, "type");
	if (cp) {
		static LRAD_NAME_NUMBER pool_types[] = {
			{ "load-balance", HOME_POOL_LOAD_BALANCE },
			{ "fail-over", HOME_POOL_FAIL_OVER },
			{ "round_robin", HOME_POOL_LOAD_BALANCE },
			{ "fail_over", HOME_POOL_FAIL_OVER },
			{ "client-balance", HOME_POOL_CLIENT_BALANCE },
			{ NULL, 0 }
		};

		value = cf_pair_value(cp);
		if (!value) {
			radlog(L_ERR, "%s[%d]: No value given for type.",
			       filename, cf_pair_lineno(cp));
			free(pool);
			return 0;
		}

		pool->type = lrad_str2int(pool_types, value, 0);
		if (!pool->type) {
			radlog(L_ERR, "%s[%d]: Unknown type \"%s\".",
			       filename, cf_pair_lineno(cp), value);
			free(pool);
			return 0;
		}

		DEBUG2(" server_pool %s: type = %s", name2, value);
	}

	for (cp = cf_pair_find(cs, "home_server");
	     cp != NULL;
	     cp = cf_pair_find_next(cs, cp, "home_server")) {
		home_server myhome, *home;

		value = cf_pair_value(cp);
		if (!value) {
			radlog(L_ERR, "%s[%d]: No value given for home_server.",
			       filename, cf_pair_lineno(cp));
			free(pool);
			return 0;
		}

		myhome.name = value;

		home = rbtree_finddata(home_servers_byname, &myhome);
		if (!home) {
			CONF_SECTION *server_cs;

			server_cs = cf_section_sub_find_name2(NULL,
							      "home_server",
							      value);
			if (!server_cs) {
				radlog(L_ERR, "%s[%d]: Unknown home_server \"%s\".",
				       filename, cf_pair_lineno(cp), value);
				free(pool);
				return 0;
			}
			
			if (!home_server_add(filename, server_cs)) {
				free(pool);
				return 0;
			}

			home = rbtree_finddata(home_servers_byname, &myhome);
			if (!home) {
				rad_assert("Internal sanity check failed");
				return 0;
			}
		}

		if (!pool->server_type) {
			rad_assert(home->type != 0);
			pool->server_type = home->type;

		} else if (pool->server_type != home->type) {
			radlog(L_ERR, "%s[%d]: Home server \"%s\" is not of the same type as previous servers in server pool %s",
			       filename, cf_pair_lineno(cp), value, pool->name);
			free(pool);
			return 0;
		}

		if (0) {
			DEBUG2("Warning: Duplicate home server %s in server pool %s", home->name, pool->name);
			continue;
		}

		DEBUG2(" server_pool %s: home_server = %s", name2, home->name);
		pool->servers[pool->num_home_servers] = home;
		pool->num_home_servers++;

	} /* loop over home_server's */

	if (!rbtree_insert(home_pools_byname, pool)) {
		rad_assert("Internal sanity check failed");
		return 0;
	}

	rad_assert(pool->server_type != 0);
	
	return 1;
}


static int old_server_add(const char *filename, int lineno,
			  const char *name, const char *secret,
			  home_pool_type_t ldflag, home_pool_t **pool_p,
			  int type)
{
	int i, insert_point, num_home_servers;
	home_server myhome, *home;
	home_pool_t mypool, *pool;
	CONF_SECTION *cs;

	/*
	 *	LOCAL realms get sanity checked, and nothing else happens.
	 */
	if (strcmp(name, "LOCAL") == 0) {
		if (*pool_p) {
			radlog(L_ERR, "%s[%d]: Realm \"%s\" cannot be both LOCAL and remote", filename, lineno, name);
			return 0;
		}
		return 1;
	}

	mypool.name = name;
	pool = rbtree_finddata(home_pools_byname, &mypool);
	if (pool) {
		if (pool->type != ldflag) {
			radlog(L_ERR, "%s[%d]: Inconsistent ldflag for server pool \"%s\"", filename, lineno, name);
			return 0;
		}

		if (pool->server_type != type) {
			radlog(L_ERR, "%s[%d]: Inconsistent home server type for server pool \"%s\"", filename, lineno, name);
			return 0;
		}
	}

	myhome.name = name;
	home = rbtree_finddata(home_servers_byname, &myhome);
	if (home) {
		if (strcmp(home->secret, secret) != 0) {
			radlog(L_ERR, "%s[%d]: Inconsistent shared secret for home server \"%s\"", filename, lineno, name);
			return 0;
		}

		if (home->type != type) {
			radlog(L_ERR, "%s[%d]: Inconsistent type for home server \"%s\"", filename, lineno, name);
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
			radlog(L_ERR, "%s[%d]: No room in pool to add home server \"%s\".  Please update the realm configuration to use the new-style home servers and server pools.", filename, lineno, name);
			return 0;
		}
	}

	/*
	 *	No home server, allocate one.
	 */
	if (!home) {	     
		const char *p;
		char *q;

		home = rad_malloc(sizeof(*home));
		memset(home, 0, sizeof(*home));

		home->name = name;
		home->hostname = name;
		home->type = type;
		home->secret = secret;

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
				radlog(L_ERR, "%s[%d]: Invalid hostname %s.",
				       filename, lineno, name);
				free(home);
				return 0;

		} else {
			home->port = atoi(p + 1);
			if ((home->port == 0) || (home->port > 65535)) {
				radlog(L_ERR, "%s[%d]: Invalid port %s.",
				       filename, lineno, p + 1);
				free(home);
				return 0;
			}

			q = rad_malloc((p - name) + 1);
			memcpy(q, name, (p - name));
			q[p - name] = '\0';
			p = q;
		}

		if (ip_hton(p, AF_UNSPEC, &home->ipaddr) < 0) {
			radlog(L_ERR, "%s[%d]: Failed looking up hostname %s.",
			       filename, lineno, p);
			free(home);
			free(q);
			return 0;
		}
		free(q);

		/*
		 *	Use the old-style configuration.
		 */
		home->max_outstanding = 65535*16;
		home->zombie_period = mainconfig.proxy_retry_delay * mainconfig.proxy_retry_count;
		if (home->zombie_period == 0) home->zombie_period =30;
		home->response_window = home->zombie_period - 1;

		home->ping_check = HOME_PING_CHECK_NONE;

		home->revive_interval = mainconfig.proxy_dead_time;

		if (rbtree_finddata(home_servers_byaddr, home)) {
			radlog(L_ERR, "%s[%d]: Home server %s has the same IP address as another home server.",
			       filename, lineno, name);
			free(home);
			return 0;
		}

		if (!rbtree_insert(home_servers_byname, home)) {
			radlog(L_ERR, "%s[%d]: Internal error adding home server %s.",
			       filename, lineno, name);
			free(home);
			return 0;
		}
		
		if (!rbtree_insert(home_servers_byaddr, home)) {
			rbtree_deletebydata(home_servers_byname, home);
			radlog(L_ERR, "%s[%d]: Internal error adding home server %s.",
			       filename, lineno, name);
			free(home);
			return 0;
		}
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
	for (cs = cf_section_sub_find_name2(mainconfig.config, "realm", name);
	     cs != NULL;
	     cs = cf_section_sub_find_name2(cs, "realm", name)) {
		num_home_servers++;
	}


	pool = rad_malloc(sizeof(*pool) + num_home_servers * sizeof(pool->servers[0]));
	memset(pool, 0, sizeof(*pool) + num_home_servers * sizeof(pool->servers[0]));

	pool->name = name;
	pool->type = ldflag;
	pool->server_type = type;
	pool->num_home_servers = num_home_servers;
	pool->servers[0] = home;

	if (!rbtree_insert(home_pools_byname, pool)) {
		rad_assert("Internal sanity check failed");
		return 0;
	}

	*pool_p = pool;

	return 1;
}

static int old_realm_config(const char *filename, CONF_SECTION *cs, REALM *r)
{
	char *host;
	const char *secret;
	home_pool_type_t ldflag;

	secret = cf_section_value_find(cs, "secret");

	host = cf_section_value_find(cs, "ldflag");
	if (!host ||
	    (strcasecmp(host, "fail_over") == 0)) {
		ldflag = HOME_POOL_FAIL_OVER;
		DEBUG2("  realm %s: ldflag = fail_over", r->name);

	} else if (strcasecmp(host, "round_robin") == 0) {
		ldflag = HOME_POOL_LOAD_BALANCE;
		DEBUG2("  realm %s: ldflag = round_robin", r->name);

	} else {
		radlog(L_ERR, "%s[%d]: Unknown value \"%s\" for ldflag",
		       filename, cf_section_lineno(cs), host);
		return 0;
	}

	/*
	 *	Allow old-style if it doesn't exist, or if it exists and
	 *	it's LOCAL.
	 */
	if (((host = cf_section_value_find(cs, "authhost")) != NULL) &&
	    (strcmp(host, "LOCAL") != 0)) {
		if (!secret) {
			radlog(L_ERR, "%s[%d]: No shared secret supplied for realm: %s",
			       filename, cf_section_lineno(cs), r->name);
			return 0;
		}

		DEBUG2("  realm %s: authhost = %s",  r->name, host);

		if (!old_server_add(filename, cf_section_lineno(cs),
				    host, secret, ldflag,
				    &r->auth_pool, HOME_TYPE_AUTH)) {
			return 0;
		}
	}

	if (((host = cf_section_value_find(cs, "accthost")) != NULL) &&
	    (strcmp(host, "LOCAL") != 0)) {
		if (!secret) {
			radlog(L_ERR, "%s[%d]: No shared secret supplied for realm: %s",
			       filename, cf_section_lineno(cs), r->name);
			return 0;
		}

		DEBUG2("  realm %s: accthost = %s", r->name, host);

		if (!old_server_add(filename, cf_section_lineno(cs),
				    host, secret, ldflag,
				    &r->auth_pool, HOME_TYPE_ACCT)) {
			return 0;
		}
	}

	if (secret) DEBUG2("  realm %s: secret = %s", r->name, secret);

	return 1;
	
}


static int add_pool_to_realm(const char *filename, int lineno,
			     const char *name, home_pool_t **dest,
			     int server_type)
{
	home_pool_t mypool, *pool;

	mypool.name = name;
	pool = rbtree_finddata(home_pools_byname, &mypool);
	if (!pool) {
		CONF_SECTION *pool_cs;

		pool_cs = cf_section_sub_find_name2(NULL, "server_pool",
						    name);
		if (!pool_cs) {
			radlog(L_ERR, "%s[%d]: Failed to find server_pool \"%s\"",
			       filename, lineno, name);
			return 0;
		}

		if (!server_pool_add(filename, pool_cs)) {
			return 0;
		}
		
		pool = rbtree_finddata(home_pools_byname, &mypool);
		if (!pool) {
			rad_assert("Internal sanity check failed");
			return 0;
		}
	}

	if (pool->server_type != server_type) {
		radlog(L_ERR, "%s[%d]: Incompatible server_pool \"%s\" (mixed auth_pool / acct_pool)",
		       filename, lineno, name);
		return 0;
	}

	*dest = pool;

	return 1;
}

int realm_add(const char *filename, CONF_SECTION *cs)
{
	const char *name2;
	char *pool = NULL;
	REALM *r;
	CONF_PAIR *cp;

	name2 = cf_section_name1(cs);
	if (!name2 || (strcasecmp(name2, "realm") != 0)) {
		radlog(L_ERR, "%s[%d]: Section is not a realm.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	name2 = cf_section_name2(cs);
	if (!name2) {
		radlog(L_ERR, "%s[%d]: Realm section is missing the realm name.",
		       filename, cf_section_lineno(cs));
		return 0;
	}

	/*
	 *	The realm MAY already exist if it's an old-style realm.
	 *	In that case, merge the old-style realm with this one.
	 */
	r = realm_find(name2);
	if (r) {
		if (cf_pair_find(cs, "auth_pool") ||
		    cf_pair_find(cs, "acct_pool")) {
			radlog(L_ERR, "%s[%d]: Duplicate realm \"%s\"",
			       filename, cf_section_lineno(cs), name2);
			return 0;
		}

		if (!old_realm_config(filename, cs, r)) {
			return 0;
		}

		return 1;
	}

	r = rad_malloc(sizeof(*r));
	memset(r, 0, sizeof(*r));

	r->name = name2;

	/*
	 *	Prefer new configuration to old one.
	 */
	cp = cf_pair_find(cs, "auth_pool");
	if (cp) pool = cf_pair_value(cp);
	if (cp && pool) {
		if (!add_pool_to_realm(filename, cf_pair_lineno(cp),
				       pool, &r->auth_pool, HOME_TYPE_AUTH)) {
			free(r);
			return 0;
		}
		DEBUG2(" realm %s: auth_pool = %s", name2, pool);
	}

	cp = cf_pair_find(cs, "acct_pool");
	if (cp) pool = cf_pair_value(cp);
	if (cp && pool) {
		if (!add_pool_to_realm(filename, cf_pair_lineno(cp),
				       pool, &r->acct_pool, HOME_TYPE_ACCT)) {
			free(r);
			return 0;
		}
		DEBUG2(" realm %s: acct_pool = %s", name2, pool);
	}

	r->striprealm = 1;
	
	if ((cf_section_value_find(cs, "nostrip")) != NULL) {
		r->striprealm = 0;
		DEBUG2(" realm %s: nostrip", name2);
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
			DEBUG2("WARNING: Ignoring old-style configuration entry \"%s\" in realm \"%s\"", cf_pair_attr(cp), r->name);
		}


		/*
		 *	The realm MAY be an old-style realm, as there
		 *	was no auth_pool or acct_pool.  Double-check
		 *	it, just to be safe.
		 */
	} else if (!old_realm_config(filename, cs, r)) {
		free(r);
		return 0;
	}

	if (!rbtree_insert(realms_byname, r)) {
		rad_assert("Internal sanity check failed");
		free(r);
		return 0;
	}

	return 1;
}


/*
 *	Find a realm in the REALM list.
 */
REALM *realm_find(const char *name)
{
	REALM myrealm;

	if (!name) name = "NULL";

	myrealm.name = name;
	return rbtree_finddata(realms_byname, &myrealm);
}


home_server *home_server_ldb(const char *realmname,
			     home_pool_t *pool, REQUEST *request)
{
	int		start;
	int		count;

	start = 0;

	/*
	 *	Determine how to pick choose the home server.
	 */
	switch (pool->type) {
		uint32_t hash;

		/*
		 *	Load balancing.  Pick one at random.
		 */
	case HOME_POOL_LOAD_BALANCE:
		hash = lrad_rand();
		start = hash % pool->num_home_servers;
		break;

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
			hash = lrad_hash(&request->packet->src_ipaddr.ipaddr.ip4addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip4addr));
			break;
		case AF_INET6:
			hash = lrad_hash(&request->packet->src_ipaddr.ipaddr.ip6addr,
					 sizeof(request->packet->src_ipaddr.ipaddr.ip6addr));
			break;
		default:
			hash = 0;
			break;
		}
		start = hash % pool->num_home_servers;
		break;

	default:
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
		home_server *home = pool->servers[(start + count) % pool->num_home_servers];

		if (home->state == HOME_STATE_IS_DEAD) {
			continue;
		}

		/*
		 *	This home server is too busy.  Choose another one.
		 */
		if (home->currently_outstanding >= home->max_outstanding) {
			continue;
		}

		return home;
	} /* loop over the home servers */

	/*
	 *	No live match found, and no fallback to the "DEFAULT"
	 *	realm.  We fix this by blindly marking all servers as
	 *	"live".  But only do it for ones that don't support
	 *	"pings", as they will be marked live when they
	 *	actually are live.
	 */
	if (!mainconfig.proxy_fallback &&
	    mainconfig.wake_all_if_all_dead) {
		home_server *lb = NULL;

		for (count = 0; count < pool->num_home_servers; count++) {
			home_server *home = pool->servers[count];

			if ((home->state == HOME_STATE_IS_DEAD) &&
			    (home->ping_check == HOME_PING_CHECK_NONE)) {
				home->state = HOME_STATE_ALIVE;
				if (!lb) lb = home;
			}
		}

		if (lb) return lb;
	}

	/*
	 *	Still nothing.  Look up the DEFAULT realm, but only
	 *	if we weren't looking up the NULL or DEFAULT realms.
	 */
	if (mainconfig.proxy_fallback &&
	    realmname &&
	    (strcmp(realmname, "NULL") != 0) &&
	    (strcmp(realmname, "DEFAULT") != 0)) {
		REALM *rd = realm_find("DEFAULT");

		if (!rd) return NULL;

		pool = NULL;
		if (request->packet->code == PW_AUTHENTICATION_REQUEST) {
			pool = rd->auth_pool;
			
		} else if (request->packet->code == PW_ACCOUNTING_REQUEST) {
			pool = rd->acct_pool;
		}
		if (!pool) return NULL;

		DEBUG2("  Realm %s has no live home servers.  Falling back to the DEFAULT realm.", realmname);
		return home_server_ldb(rd->name, pool, request);
	}

	/*
	 *	Still haven't found anything.  Oh well.
	 */
	return NULL;
}


home_server *home_server_find(lrad_ipaddr_t *ipaddr, int port)
{
	home_server myhome;

	myhome.ipaddr = *ipaddr;
	myhome.port = port;

	return rbtree_finddata(home_servers_byaddr, &myhome);
}
