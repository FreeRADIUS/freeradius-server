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
 * @file rlm_redis_ippool.c
 * @brief IP Allocation module with a redis backend.
 *
 * @author Arran Cudbard-Bell
 *
 * Performs lease management using a Redis backed.
 *
 *
 * Creates three types of objects:
 * - @verbatim {<pool name>:<pool type>}:pool @endverbatim (zset) contains IP addresses
 *	with priority set by expiry time.
 * - @verbatim {<pool name>:<pool type>}:ip:<address> @endverbatim (hash) contains four keys
 *     * range   - Range identifier, used to lookup attributes associated with a range within a pool.
 *     * device  - Lease owner identifier for the device which last bound this address.
 *     * gateway - Gateway of device which last bound this address.
 *     * counter - How many times this IP address has been bound.
 * - @verbatim {<pool name>:<pool type>}:device:<client id> @endverbatim (string) contains last
 *	IP address bound by this client.
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/modpriv.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/hex.h>

#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>
#include "redis_ippool.h"

#include <freeradius-devel/dhcpv4/dhcpv4.h>

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.

	tmpl_t			*pool_name;	//!< Name of the pool we're allocating IP addresses from.

	tmpl_t			*offer_time;	//!< How long we should reserve a lease for during
						//!< the pre-allocation stage (typically responding
						//!< to DHCP discover).
	tmpl_t			*lease_time;	//!< How long an IP address should be allocated for.

	uint32_t		wait_num;	//!< How many slaves we want to acknowledge allocations
						//!< or updates.

	fr_time_delta_t		wait_timeout;	//!< How long we wait for slaves to acknowledge writing.

	tmpl_t			*owner;	//!< Unique Lease owner identifier.  Could be mac-address
						//!< or a combination of User-Name and something
						//!< unique to the device.

	tmpl_t			*gateway_id;	//!< Gateway identifier, usually
						//!< NAS-Identifier or the actual Option 82 gateway.
						//!< Used for bulk lease cleanups.

	tmpl_t			*requested_address;		//!< Attribute to read the IP for renewal from.

	tmpl_t			*allocated_address_attr;	//!< IP attribute and destination.

	tmpl_t			*range_attr;	//!< Attribute to write the range ID to.

	tmpl_t			*expiry_attr;	//!< Time at which the lease will expire.

	bool			ipv4_integer;	//!< Whether IPv4 addresses should be cast to integers,
						//!< for renew operations.

	bool			copy_on_update; //!< Copy the address provided by ip_address to the
						//!< allocated_address_attr if updates are successful.

	fr_redis_cluster_t	*cluster;	//!< Redis cluster.
} rlm_redis_ippool_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("pool_name", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, pool_name) },

	{ FR_CONF_OFFSET("owner", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, owner) },
	{ FR_CONF_OFFSET("gateway", FR_TYPE_TMPL, rlm_redis_ippool_t, gateway_id) },\

	{ FR_CONF_OFFSET("offer_time", FR_TYPE_TMPL, rlm_redis_ippool_t, offer_time) },
	{ FR_CONF_OFFSET("lease_time", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lease_time) },

	{ FR_CONF_OFFSET("wait_num", FR_TYPE_UINT32, rlm_redis_ippool_t, wait_num) },
	{ FR_CONF_OFFSET("wait_timeout", FR_TYPE_TIME_DELTA, rlm_redis_ippool_t, wait_timeout) },

	{ FR_CONF_OFFSET("requested_address", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, requested_address), .dflt = "%{%{DHCP-Requested-IP-Address}:-%{DHCP-Client-IP-Address}}", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_DEPRECATED("ip_address", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, NULL) },

	{ FR_CONF_OFFSET("allocated_address_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, allocated_address_attr), .dflt = "&reply.DHCP-Your-IP-Address", .quote = T_BARE_WORD },
	{ FR_CONF_DEPRECATED("reply_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, NULL) },

	{ FR_CONF_OFFSET("range_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, range_attr), .dflt = "&reply.Pool-Range", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("expiry_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_redis_ippool_t, expiry_attr) },

	{ FR_CONF_OFFSET("ipv4_integer", FR_TYPE_BOOL, rlm_redis_ippool_t, ipv4_integer) },
	{ FR_CONF_OFFSET("copy_on_update", FR_TYPE_BOOL, rlm_redis_ippool_t, copy_on_update), .dflt = "yes", .quote = T_BARE_WORD },

	/*
	 *	Split out to allow conversion to universal ippool module with
	 *	minimum of config changes.
	 */
	{ FR_CONF_POINTER("redis", FR_TYPE_SUBSECTION, NULL), .subcs = redis_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;
static fr_dict_t const *dict_dhcpv4;

extern fr_dict_autoload_t rlm_redis_ippool_dict[];
fr_dict_autoload_t rlm_redis_ippool_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ NULL }
};

static fr_dict_attr_t const *attr_pool_action;
static fr_dict_attr_t const *attr_acct_status_type;
static fr_dict_attr_t const *attr_message_type;

extern fr_dict_attr_autoload_t rlm_redis_ippool_dict_attr[];
fr_dict_attr_autoload_t rlm_redis_ippool_dict_attr[] = {
	{ .out = &attr_pool_action, .name = "Pool-Action", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ .out = &attr_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ NULL }
};

#define EOL "\n"

/** Lua script for allocating new leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] Wall time (seconds since epoch).
 * - ARGV[2] Expires in (seconds).
 * - ARGV[3] Lease owner identifier (administratively configured).
 * - ARGV[4] (optional) Gateway identifier.
 *
 * Returns @verbatim { <rcode>[, <ip>][, <range>][, <lease time>][, <counter>] } @endverbatim
 * - IPPOOL_RCODE_SUCCESS lease updated..
 * - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
 */
static char lua_alloc_cmd[] =
	"local ip" EOL											/* 1 */
	"local exists" EOL										/* 2 */

	"local pool_key" EOL										/* 3 */
	"local address_key" EOL										/* 4 */
	"local owner_key" EOL										/* 5 */

	"pool_key = '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"'" EOL					/* 6 */
	"owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[3]" EOL			/* 7 */

	/*
	 *	Check to see if the client already has a lease,
	 *	and if it does return that.
	 *
	 *	The additional sanity checks are to allow for the record
	 *	of device/ip binding to persist for longer than the lease.
	 */
	"exists = redis.call('GET', owner_key);" EOL							/* 8 */
	"if exists then" EOL										/* 9 */
	"  local expires_in = tonumber(redis.call('ZSCORE', pool_key, exists) - ARGV[1])" EOL		/* 10 */
	"  if expires_in > 0 then" EOL									/* 11 */
	"    ip = redis.call('HMGET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. exists, 'device', 'range', 'counter')" EOL	/* 12 */
	"    if ip and (ip[1] == ARGV[3]) then" EOL							/* 13 */
//	"      if expires_in < ARGV[2] then" EOL							/* 14 */
//	"        redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2], ip[1])" EOL			/* 15 */
//	"        expires_in = ARGV[2]" EOL								/* 16 */
//	"      end" EOL											/* 17 */
	"      return {" STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", exists, ip[2], expires_in, ip[3] }" EOL	/* 18 */
	"    end" EOL											/* 19 */
	"  end" EOL											/* 20 */
	"end" EOL											/* 21 */

	/*
	 *	Else, get the IP address which expired the longest time ago.
	 */
	"ip = redis.call('ZREVRANGE', pool_key, -1, -1, 'WITHSCORES')" EOL				/* 22 */
	"if not ip or not ip[1] then" EOL								/* 23 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 24 */
	"end" EOL											/* 25 */
	"if ip[2] >= ARGV[1] then" EOL									/* 26 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 27 */
	"end" EOL											/* 28 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2], ip[1])" EOL				/* 29 */

	/*
	 *	Set the device/gateway keys
	 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ip[1]" EOL			/* 30 */
	"redis.call('HMSET', address_key, 'device', ARGV[3], 'gateway', ARGV[4])" EOL			/* 31 */
	"redis.call('SET', owner_key, ip[1])" EOL							/* 32 */
	"redis.call('EXPIRE', owner_key, ARGV[2])" EOL							/* 33 */
	"return { " EOL											/* 34 */
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL							/* 35 */
	"  ip[1], " EOL											/* 36 */
	"  redis.call('HGET', address_key, 'range'), " EOL						/* 37 */
	"  tonumber(ARGV[2]), " EOL									/* 38 */
	"  redis.call('HINCRBY', address_key, 'counter', 1)" EOL					/* 39 */
	"}" EOL;											/* 40 */
static char lua_alloc_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for updating leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] Wall time (seconds since epoch).
 * - ARGV[2] Expires in (seconds).
 * - ARGV[3] IP address to update.
 * - ARGV[4] Lease owner identifier.
 * - ARGV[5] (optional) Gateway identifier.
 *
 * Returns @verbatim array { <rcode>[, <range>] } @endverbatim
 * - IPPOOL_RCODE_SUCCESS lease updated..
 * - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
 * - IPPOOL_RCODE_EXPIRED lease has already expired.
 * - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client.
 */
static char lua_update_cmd[] =
	"local ret" EOL									/* 1 */
	"local found" EOL								/* 2 */

	"local pool_key" EOL								/* 3 */
	"local address_key" EOL								/* 4 */
	"local owner_key" EOL								/* 5 */

	/*
	 *	We either need to know that the IP was last allocated to the
	 *	same device, or that the lease on the IP has NOT expired.
	 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ARGV[3]" EOL	/* 6 */
	"found = redis.call('HMGET', address_key, 'range', 'device', 'gateway', 'counter' )" EOL	/* 7 */
	/*
	 *	Range may be nil (if not used), so we use the device key
	 */
	"if not found[2] then" EOL							/* 8 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_NOT_FOUND) "}" EOL				/* 9 */
	"end" EOL									/* 10 */
	"if found[2] ~= ARGV[4] then" EOL						/* 11 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_DEVICE_MISMATCH) ", found[2]}" EOL		/* 12 */
	"end" EOL									/* 13 */

	/*
	 *	Update the expiry time
	 */
	"pool_key = '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"'" EOL			/* 14 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2], ARGV[3])" EOL		/* 15 */

	/*
	 *	The device key should usually exist, but
	 *	theoretically, if we were right on the cusp
	 *	of a lease being expired, it may have been
	 *	removed.
	 */
	"owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[4]" EOL	/* 16 */
	"if redis.call('EXPIRE', owner_key, ARGV[2]) == 0 then" EOL			/* 17 */
	"  redis.call('SET', owner_key, ARGV[3])" EOL					/* 18 */
	"  redis.call('EXPIRE', owner_key, ARGV[2])" EOL				/* 19 */
	"end" EOL									/* 20 */

	/*
	 *	Update the gateway address
	 */
	"if ARGV[5] ~= found[3] then" EOL						/* 21 */
	"  redis.call('HSET', address_key, 'gateway', ARGV[5])" EOL			/* 22 */
	"end" EOL									/* 23 */
	"return { " STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", found[1], found[4] }"EOL;	/* 24 */
static char lua_update_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for releasing leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] Wall time (seconds since epoch).
 * - ARGV[2] IP address to release.
 * - ARGV[3] Client identifier.
 *
 * Sets the expiry time to be NOW() - 1 to maximise time between
 * IP address allocations.
 *
 * Returns @verbatim array { <rcode>[, <counter>] } @endverbatim
 * - IPPOOL_RCODE_SUCCESS lease updated..
 * - IPPOOL_RCODE_NOT_FOUND lease not found in pool.
 * - IPPOOL_RCODE_DEVICE_MISMATCH lease was allocated to a different client..
 */
static char lua_release_cmd[] =
	"local ret" EOL									/* 1 */
	"local found" EOL								/* 2 */

	"local pool_key" EOL								/* 3 */
	"local address_key" EOL								/* 4 */
	"local owner_key" EOL								/* 5 */

	/*
	 *	Check that the device releasing was the one
	 *	the IP address is allocated to.
	 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ARGV[2]" EOL	/* 6 */
	"found = redis.call('HGET', address_key, 'device')" EOL				/* 7 */
	"if not found then" EOL								/* 8 */
	"  return { " STRINGIFY(_IPPOOL_RCODE_NOT_FOUND) "}" EOL			/* 9 */
	"end" EOL									/* 11 */
	"if found and found ~= ARGV[3] then" EOL					/* 12 */
	"  return { " STRINGIFY(_IPPOOL_RCODE_DEVICE_MISMATCH) ", found[2] }" EOL	/* 13 */
	"end" EOL									/* 14 */

	/*
	 *	Set expiry time to now() - 1
	 */
	"pool_key = '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"'" EOL			/* 15 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] - 1, ARGV[2])" EOL			/* 16 */

	/*
	 *	Remove the association between the device and a lease
	 */
	"owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[3]" EOL	/* 17 */
	"redis.call('DEL', owner_key)" EOL						/* 18 */
	"return { " EOL
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL					/* 19 */
	"  redis.call('HINCRBY', address_key, 'counter', 1) - 1" EOL			/* 20 */
	"}";										/* 21 */
static char lua_release_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Check the requisite number of slaves replicated the lease info
 *
 * @param request The current request.
 * @param wait_num Number of slaves required.
 * @param reply we got from the server.
 * @return
 *	- 0 if enough slaves replicated the data.
 *	- -1 if too few slaves replicated the data, or another error.
 */
static inline int ippool_wait_check(request_t *request, uint32_t wait_num, redisReply *reply)
{
	if (!wait_num) return 0;

	if (reply->type != REDIS_REPLY_INTEGER) {
		REDEBUG("WAIT result is wrong type, expected integer got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		return -1;
	}
	if (reply->integer < wait_num) {
		REDEBUG("Too few slaves acknowledged allocation, needed %i, got %lli",
			wait_num, reply->integer);
		return -1;
	}
	return 0;
}

static void ippool_action_print(request_t *request, ippool_action_t action,
				fr_log_lvl_t lvl,
				uint8_t const *key_prefix, size_t key_prefix_len,
				char const *ip_str,
				uint8_t const *owner, size_t owner_len,
				uint8_t const *gateway_id, size_t gateway_id_len,
				uint32_t expires)
{
	char *key_prefix_str, *device_str = NULL, *gateway_str = NULL;

	key_prefix_str = fr_asprint(request, (char const *)key_prefix, key_prefix_len, '"');
	if (gateway_id) gateway_str = fr_asprint(request, (char const *)gateway_id, gateway_id_len, '"');
	if (owner) device_str = fr_asprint(request, (char const *)owner, owner_len, '"');

	switch (action) {
	case POOL_ACTION_ALLOCATE:
		RDEBUGX(lvl, "Allocating lease from pool \"%s\"%s%s%s%s%s%s, expires in %us",
			key_prefix_str,
			device_str ? ", to \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			gateway_str ? ", on \"" : "", gateway_str ? gateway_str : "",
			gateway_str ? "\"" : "",
			expires);
		break;

	case POOL_ACTION_UPDATE:
		RDEBUGX(lvl, "Updating %s in pool \"%s\"%s%s%s%s%s%s, expires in %us",
			ip_str, key_prefix_str,
			device_str ? ", device \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			gateway_str ? ", gateway \"" : "", gateway_str ? gateway_str : "",
			gateway_str ? "\"" : "",
			expires);
		break;

	case POOL_ACTION_RELEASE:
		RDEBUGX(lvl, "Releasing %s%s%s%s to pool \"%s\"",
			ip_str,
			device_str ? " leased by \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			key_prefix_str);
		break;

	default:
		break;
	}

	/*
	 *	Ordering is important, needs to be LIFO
	 *	for proper talloc pool re-use.
	 */
	talloc_free(key_prefix_str);
	talloc_free(device_str);
	talloc_free(gateway_str);
}

/** Execute a script against Redis cluster
 *
 * Handles uploading the script to the server if required.
 *
 * @note All replies will be freed on error.
 *
 * @param[out] out		Where to write Redis reply object resulting from the command.
 * @param[in] request		The current request.
 * @param[in] cluster		configuration.
 * @param[in] key		to use to determine the cluster node.
 * @param[in] key_len		length of the key.
 * @param[in] wait_num		If > 0 wait until this many slaves have replicated the data
 *				from the last command.
 * @param[in] wait_timeout	How long to wait for slaves.
 * @param[in] digest		of script.
 * @param[in] script		to upload.
 * @param[in] cmd		EVALSHA command to execute.
 * @param[in] ...		Arguments for the eval command.
 * @return status of the command.
 */
static fr_redis_rcode_t ippool_script(redisReply **out, request_t *request, fr_redis_cluster_t *cluster,
				      uint8_t const *key, size_t key_len,
				      uint32_t wait_num, fr_time_delta_t wait_timeout,
				      char const digest[], char const *script,
				      char const *cmd, ...)
{
	fr_redis_conn_t			*conn;
	redisReply			*replies[5];	/* Must be equal to the maximum number of pipelined commands */
	size_t				reply_cnt = 0, i;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		s_ret, status;
	unsigned int			pipelined = 0;

	va_list				ap;

	*out = NULL;

#ifndef NDEBUG
	memset(replies, 0, sizeof(replies));
#endif

	va_start(ap, cmd);

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, cluster, request, key, key_len, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;	/* Continue */
	     s_ret = fr_redis_cluster_state_next(&state, &conn, cluster, request, status, &replies[0])) {
	     	va_list	copy;

	     	RDEBUG3("Calling script 0x%s", digest);
	     	va_copy(copy, ap);	/* copy or segv */
		redisvAppendCommand(conn->handle, cmd, copy);
		va_end(copy);
		pipelined = 1;
		if (wait_num) {
			redisAppendCommand(conn->handle, "WAIT %i %i", wait_num, fr_time_delta_to_msec(wait_timeout));
			pipelined++;
		}
		reply_cnt = fr_redis_pipeline_result(&pipelined, &status,
						     replies, NUM_ELEMENTS(replies),
						     conn);
		if (status != REDIS_RCODE_NO_SCRIPT) continue;

		/*
		 *	Clear out the existing reply
		 */
		fr_redis_pipeline_free(replies, reply_cnt);

		/*
		 *	Last command failed with NOSCRIPT, this means
		 *	we have to send the Lua script up to the node
		 *	so it can be cached.
		 */
	     	RDEBUG3("Loading script 0x%s", digest);
		redisAppendCommand(conn->handle, "MULTI");
		redisAppendCommand(conn->handle, "SCRIPT LOAD %s", script);
	     	va_copy(copy, ap);	/* copy or segv */
		redisvAppendCommand(conn->handle, cmd, copy);
		va_end(copy);
		redisAppendCommand(conn->handle, "EXEC");
		pipelined = 4;
		if (wait_num) {
			redisAppendCommand(conn->handle, "WAIT %i %i", wait_num, wait_timeout);
			pipelined++;
		}

		reply_cnt = fr_redis_pipeline_result(&pipelined, &status,
						     replies, NUM_ELEMENTS(replies),
						     conn);
		if (status == REDIS_RCODE_SUCCESS) {
			if (RDEBUG_ENABLED3) for (i = 0; i < reply_cnt; i++) {
				fr_redis_reply_print(L_DBG_LVL_3, replies[i], request, i);
			}

			if (replies[3]->type != REDIS_REPLY_ARRAY) {
				REDEBUG("Bad response to EXEC, expected array got %s",
					fr_table_str_by_value(redis_reply_types, replies[3]->type, "<UNKNOWN>"));
			error:
				fr_redis_pipeline_free(replies, reply_cnt);
				status = REDIS_RCODE_ERROR;
				goto finish;
			}
			if (replies[3]->elements != 2) {
				REDEBUG("Bad response to EXEC, expected 2 result elements, got %zu",
					replies[3]->elements);
				goto error;
			}
			if (replies[3]->element[0]->type != REDIS_REPLY_STRING) {
				REDEBUG("Bad response to SCRIPT LOAD, expected string got %s",
					fr_table_str_by_value(redis_reply_types, replies[3]->element[0]->type, "<UNKNOWN>"));
				goto error;
			}
			if (strcmp(replies[3]->element[0]->str, digest) != 0) {
				RWDEBUG("Incorrect SHA1 from SCRIPT LOAD, expected %s, got %s",
					digest, replies[3]->element[0]->str);
				goto error;
			}
		}
	}
	if (s_ret != REDIS_RCODE_SUCCESS) goto error;

	switch (reply_cnt) {
	case 2:	/* EVALSHA with wait */
		if (ippool_wait_check(request, wait_num, replies[1]) < 0) goto error;
		fr_redis_reply_free(&replies[1]);	/* Free the wait response */
		break;

	case 1:	/* EVALSHA */
		*out = replies[0];
		break;

	case 5: /* LOADSCRIPT + EVALSHA + WAIT */
		if (ippool_wait_check(request, wait_num, replies[4]) < 0) goto error;
		fr_redis_reply_free(&replies[4]);	/* Free the wait response */
		FALL_THROUGH;

	case 4: /* LOADSCRIPT + EVALSHA */
		fr_redis_reply_free(&replies[2]);	/* Free the queued cmd response*/
		fr_redis_reply_free(&replies[1]);	/* Free the queued script load response */
		fr_redis_reply_free(&replies[0]);	/* Free the queued multi response */
		*out = replies[3]->element[1];
		replies[3]->element[1] = NULL;		/* Prevent double free */
		fr_redis_reply_free(&replies[3]);	/* This works because hiredis checks for NULL elements */
		break;

	case 0:
		break;
	}

finish:
	va_end(ap);
	return s_ret;
}

/** Allocate a new IP address from a pool
 *
 */
static ippool_rcode_t redis_ippool_allocate(rlm_redis_ippool_t const *inst, request_t *request,
					    uint8_t const *key_prefix, size_t key_prefix_len,
					    uint8_t const *owner, size_t owner_len,
					    uint8_t const *gateway_id, size_t gateway_id_len,
					    uint32_t expires)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	fr_assert(key_prefix);
	fr_assert(owner);

	now = fr_time_to_timeval(fr_time());

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!gateway_id) gateway_id = (uint8_t const *)"";

	status = ippool_script(&reply, request, inst->cluster,
			       key_prefix, key_prefix_len,
			       inst->wait_num, inst->wait_timeout,
			       lua_alloc_digest, lua_alloc_cmd,
	 		       "EVALSHA %s 1 %b %u %u %b %b",
	 		       lua_alloc_digest,
			       key_prefix, key_prefix_len,
			       (unsigned int)now.tv_sec, expires,
			       owner, owner_len,
			       gateway_id, gateway_id_len);
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	fr_assert(reply);
	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}
	ret = reply->element[0]->integer;
	if (ret < 0) goto finish;

	/*
	 *	Process IP address
	 */
	if (reply->elements > 1) {
		tmpl_t ip_rhs;
		map_t ip_map = {
			.lhs = inst->allocated_address_attr,
			.op = T_OP_SET,
			.rhs = &ip_rhs
		};

		tmpl_init_shallow(&ip_rhs, TMPL_TYPE_DATA, T_BARE_WORD, "", 0);
		switch (reply->element[1]->type) {
		/*
		 *	Destination attribute may not be IPv4, in which case
		 *	we want to pre-convert the integer value to an IPv4
		 *	address before casting it once more to the type of
		 *	the destination attribute.
		 */
		case REDIS_REPLY_INTEGER:
		{
			if (tmpl_da(ip_map.lhs)->type != FR_TYPE_IPV4_ADDR) {
				fr_value_box_t tmp;

				fr_value_box_shallow(&tmp,
						     (uint32_t)ntohl((uint32_t)reply->element[1]->integer), true);
				if (fr_value_box_cast(NULL, tmpl_value(ip_map.rhs), FR_TYPE_IPV4_ADDR,
						      NULL, &tmp)) {
					RPEDEBUG("Failed converting integer to IPv4 address");
					ret = IPPOOL_RCODE_FAIL;
					goto finish;
				}
			} else {
				fr_value_box_shallow(&ip_map.rhs->data.literal,
						     (uint32_t)ntohl((uint32_t)reply->element[1]->integer), true);
			}
		}
			goto do_ip_map;

		case REDIS_REPLY_STRING:
			fr_value_box_bstrndup_shallow(&ip_map.rhs->data.literal,
						      NULL, reply->element[1]->str, reply->element[1]->len, false);
		do_ip_map:
			if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) {
				ret = IPPOOL_RCODE_FAIL;
				goto finish;
			}
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for IP element (result[1])",
				fr_table_str_by_value(redis_reply_types, reply->element[1]->type, "<UNKNOWN>"));
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
	}

	/*
	 *	Process Range identifier
	 */
	if (reply->elements > 2) {
		switch (reply->element[2]->type) {
		/*
		 *	Add range ID to request
		 */
		case REDIS_REPLY_STRING:
		{
			tmpl_t range_rhs;
			map_t range_map = {
				.lhs = inst->range_attr,
				.op = T_OP_SET,
				.rhs = &range_rhs
			};

			tmpl_init_shallow(&range_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0);
			fr_value_box_bstrndup_shallow(&range_map.rhs->data.literal,
						      NULL, reply->element[2]->str, reply->element[2]->len, true);
			if (map_to_request(request, &range_map, map_to_vp, NULL) < 0) {
				ret = IPPOOL_RCODE_FAIL;
				goto finish;
			}
		}
			break;

		case REDIS_REPLY_NIL:
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for range element (result[2])",
				fr_table_str_by_value(redis_reply_types, reply->element[2]->type, "<UNKNOWN>"));
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
	}

	/*
	 *	Process Expiry time
	 */
	if (inst->expiry_attr && (reply->elements > 3)) {
		tmpl_t expiry_rhs;
		map_t expiry_map = {
			.lhs = inst->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};

		tmpl_init_shallow(&expiry_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0);
		if (reply->element[3]->type != REDIS_REPLY_INTEGER) {
			REDEBUG("Server returned unexpected type \"%s\" for expiry element (result[3])",
				fr_table_str_by_value(redis_reply_types, reply->element[3]->type, "<UNKNOWN>"));
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}

		fr_value_box_shallow(&expiry_map.rhs->data.literal, (uint32_t)reply->element[3]->integer, true);
		if (map_to_request(request, &expiry_map, map_to_vp, NULL) < 0) {
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
	}
finish:
	fr_redis_reply_free(&reply);
	return ret;
}

/** Update an existing IP address in a pool
 *
 */
static ippool_rcode_t redis_ippool_update(rlm_redis_ippool_t const *inst, request_t *request,
					  uint8_t const *key_prefix, size_t key_prefix_len,
					  fr_ipaddr_t *ip,
					  uint8_t const *owner, size_t owner_len,
					  uint8_t const *gateway_id, size_t gateway_id_len,
					  uint32_t expires)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	tmpl_t		range_rhs;
	map_t		range_map = { .lhs = inst->range_attr, .op = T_OP_SET, .rhs = &range_rhs };

	tmpl_init_shallow(&range_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0);

	now = fr_time_to_timeval(fr_time());

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!owner) owner = (uint8_t const *)"";
	if (!gateway_id) gateway_id = (uint8_t const *)"";

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %u %u %u %b %b",
				       lua_update_digest,
				       key_prefix, key_prefix_len,
				       (unsigned int)now.tv_sec, expires,
				       htonl(ip->addr.v4.s_addr),
				       owner, owner_len,
				       gateway_id, gateway_id_len);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %u %u %s %b %b",
				       lua_update_digest,
				       key_prefix, key_prefix_len,
				       (unsigned int)now.tv_sec, expires,
				       ip_buff,
				       owner, owner_len,
				       gateway_id, gateway_id_len);
	}
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}
	ret = reply->element[0]->integer;
	if (ret < 0) goto finish;

	/*
	 *	Process Range identifier
	 */
	if (reply->elements > 1) {
		switch (reply->element[1]->type) {
		/*
		 *	Add range ID to request
		 */
		case REDIS_REPLY_STRING:
			fr_value_box_bstrndup_shallow(&range_map.rhs->data.literal, NULL,
						      reply->element[1]->str, reply->element[1]->len, true);
			if (map_to_request(request, &range_map, map_to_vp, NULL) < 0) {
				ret = IPPOOL_RCODE_FAIL;
				goto finish;
			}
			break;

		case REDIS_REPLY_NIL:
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for range element (result[1])",
				fr_table_str_by_value(redis_reply_types, reply->element[0]->type, "<UNKNOWN>"));
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
	}

	/*
	 *	Copy expiry time to expires attribute (if set)
	 */
	if (inst->expiry_attr) {
		tmpl_t expiry_rhs;
		map_t expiry_map = {
			.lhs = inst->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};


		tmpl_init_shallow(&expiry_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0);

		fr_value_box_shallow(&expiry_map.rhs->data.literal, expires, false);
		if (map_to_request(request, &expiry_map, map_to_vp, NULL) < 0) {
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
	}

finish:
	fr_redis_reply_free(&reply);

	return ret;
}

/** Release an existing IP address in a pool
 *
 */
static ippool_rcode_t redis_ippool_release(rlm_redis_ippool_t const *inst, request_t *request,
					   uint8_t const *key_prefix, size_t key_prefix_len,
					   fr_ipaddr_t *ip,
					   uint8_t const *owner, size_t owner_len)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	now = fr_time_to_timeval(fr_time());

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!owner) owner = (uint8_t const *)"";

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %u %u %b",
				       lua_release_digest,
				       key_prefix, key_prefix_len,
				       (unsigned int)now.tv_sec,
				       htonl(ip->addr.v4.s_addr),
				       owner, owner_len);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %u %s %b",
				       lua_release_digest,
				       key_prefix, key_prefix_len,
				       (unsigned int)now.tv_sec,
				       ip_buff,
				       owner, owner_len);
	}
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}
	ret = reply->element[0]->integer;
	if (ret < 0) goto finish;

finish:
	fr_redis_reply_free(&reply);

	return ret;
}

/** Find the pool name we'll be allocating from
 *
 * @param[out] out	Where to write the pool name.
 * @param[out] buff	Where to write the pool name (in the case of an expansion).
 * @param[in] bufflen	Size of the output buffer.
 * @param[in] inst	This instance of the rlm_redis_ippool module.
 * @param[in] request	The current request.
 * @return
 *	- < 0 on error.
 *	- 0 if no pool attribute exists, or the pool name is a zero length string.
 *	- > 0 on success (length of data written to out).
 */
static inline ssize_t ippool_pool_name(uint8_t const **out, uint8_t buff[], size_t bufflen,
				       rlm_redis_ippool_t const *inst, request_t *request)
{
	ssize_t slen;

	slen = tmpl_expand(out, (char *)buff, bufflen, request, inst->pool_name, NULL, NULL);
	if (slen < 0) {
		if (tmpl_is_attr(inst->pool_name)) {
			RDEBUG2("Pool attribute not present in request.  Doing nothing");
			return 0;
		}
		REDEBUG("Failed expanding pool name");
		return -1;
	}
	if (slen == 0) {
		RDEBUG2("Empty pool name.  Doing nothing");
		return 0;
	}

	if ((*out == buff) && is_truncated((size_t)slen, bufflen)) {
		REDEBUG("Pool name too long.  Expected %zu bytes, got %zu bytes", bufflen, (size_t)slen);
		return -1;
	}

	return slen;
}

static unlang_action_t mod_action(rlm_rcode_t *p_result, rlm_redis_ippool_t const *inst, request_t *request, ippool_action_t action)
{
	uint8_t		key_prefix_buff[IPPOOL_MAX_KEY_PREFIX_SIZE], owner_buff[256], gateway_id_buff[256];
	uint8_t const	*key_prefix, *owner = NULL, *gateway_id = NULL;
	size_t		key_prefix_len, owner_len = 0, gateway_id_len = 0;
	ssize_t		slen;
	fr_ipaddr_t	ip;
	char		expires_buff[20];
	char const	*expires_str;
	unsigned long	expires = 0;
	char		*q;

	slen = ippool_pool_name(&key_prefix, (uint8_t *)&key_prefix_buff, sizeof(key_prefix_len), inst, request);
	if (slen < 0) RETURN_MODULE_FAIL;
	if (slen == 0) RETURN_MODULE_NOOP;

	key_prefix_len = (size_t)slen;

	if (inst->owner) {
		slen = tmpl_expand((char const **)&owner,
				   (char *)&owner_buff, sizeof(owner_buff),
				   request, inst->owner, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Failed expanding device (%s)", inst->owner->name);
			RETURN_MODULE_FAIL;
		}
		owner_len = (size_t)slen;
	}

	if (inst->gateway_id) {
		slen = tmpl_expand((char const **)&gateway_id,
				   (char *)&gateway_id_buff, sizeof(gateway_id_buff),
				   request, inst->gateway_id, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Failed expanding gateway (%s)", inst->gateway_id->name);
			RETURN_MODULE_FAIL;
		}
		gateway_id_len = (size_t)slen;
	}

	switch (action) {
	case POOL_ACTION_ALLOCATE:
		if (tmpl_expand(&expires_str, expires_buff, sizeof(expires_buff),
				request, inst->offer_time, NULL, NULL) < 0) {
			REDEBUG("Failed expanding offer_time (%s)", inst->offer_time->name);
			RETURN_MODULE_FAIL;
		}

		expires = strtoul(expires_str, &q, 10);
		if (q != (expires_str + strlen(expires_str))) {
			REDEBUG("Invalid offer_time.  Must be an integer value");
			RETURN_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len, NULL,
				    owner, owner_len, gateway_id, gateway_id_len, expires);
		switch (redis_ippool_allocate(inst, request, key_prefix, key_prefix_len,
					      owner, owner_len,
					      gateway_id, gateway_id_len, (uint32_t)expires)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("IP address lease allocated");
			RETURN_MODULE_UPDATED;

		case IPPOOL_RCODE_POOL_EMPTY:
			RWDEBUG("Pool contains no free addresses");
			RETURN_MODULE_NOTFOUND;

		default:
			RETURN_MODULE_FAIL;
		}

	case POOL_ACTION_UPDATE:
	{
		char		ip_buff[INET6_ADDRSTRLEN + 4];
		char const	*ip_str;

		if (tmpl_expand(&expires_str, expires_buff, sizeof(expires_buff),
				request, inst->lease_time, NULL, NULL) < 0) {
			REDEBUG("Failed expanding lease_time (%s)", inst->lease_time->name);
			RETURN_MODULE_FAIL;
		}

		expires = strtoul(expires_str, &q, 10);
		if (q != (expires_str + strlen(expires_str))) {
			REDEBUG("Invalid expires.  Must be an integer value");
			RETURN_MODULE_FAIL;
		}

		if (tmpl_expand(&ip_str, ip_buff, sizeof(ip_buff), request, inst->requested_address, NULL, NULL) < 0) {
			REDEBUG("Failed expanding requested_address (%s)", inst->requested_address->name);
			RETURN_MODULE_FAIL;
		}

		if (fr_inet_pton(&ip, ip_str, -1, AF_UNSPEC, false, true) < 0) {
			RPEDEBUG("Failed parsing address");
			RETURN_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip_str, owner, owner_len, gateway_id, gateway_id_len, expires);
		switch (redis_ippool_update(inst, request, key_prefix, key_prefix_len,
					    &ip, owner, owner_len,
					    gateway_id, gateway_id_len, (uint32_t)expires)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("Requested IP address' \"%s\" lease updated", ip_str);

			/*
			 *	Copy over the input IP address to the reply attribute
			 */
			if (inst->copy_on_update) {
				tmpl_t ip_rhs = {
					.name = "",
					.type = TMPL_TYPE_DATA,
					.quote = T_BARE_WORD,
				};
				map_t ip_map = {
					.lhs = inst->allocated_address_attr,
					.op = T_OP_SET,
					.rhs = &ip_rhs
				};

				fr_value_box_strdup_shallow(&ip_rhs.data.literal, NULL, ip_str, false);

				if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) RETURN_MODULE_FAIL;
			}
			RETURN_MODULE_UPDATED;

		/*
		 *	It's useful to be able to identify the 'not found' case
		 *	as we can relay to a server where the IP address might
		 *	be found.  This extremely useful for migrations.
		 */
		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("Requested IP address \"%s\" is not a member of the specified pool", ip_str);
			RETURN_MODULE_NOTFOUND;

		case IPPOOL_RCODE_EXPIRED:
			REDEBUG("Requested IP address' \"%s\" lease already expired at time of renewal", ip_str);
			RETURN_MODULE_INVALID;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("Requested IP address' \"%s\" lease allocated to another device", ip_str);
			RETURN_MODULE_INVALID;

		default:
			RETURN_MODULE_FAIL;
		}
	}

	case POOL_ACTION_RELEASE:
	{
		char		ip_buff[INET6_ADDRSTRLEN + 4];
		char const	*ip_str;

		if (tmpl_expand(&ip_str, ip_buff, sizeof(ip_buff), request, inst->requested_address, NULL, NULL) < 0) {
			REDEBUG("Failed expanding requested_address (%s)", inst->requested_address->name);
			RETURN_MODULE_FAIL;
		}

		if (fr_inet_pton(&ip, ip_str, -1, AF_UNSPEC, false, true) < 0) {
			RPEDEBUG("Failed parsing address");
			RETURN_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip_str, owner, owner_len, gateway_id, gateway_id_len, 0);
		switch (redis_ippool_release(inst, request, key_prefix, key_prefix_len,
					     &ip, owner, owner_len)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("IP address \"%s\" released", ip_str);
			RETURN_MODULE_UPDATED;

		/*
		 *	It's useful to be able to identify the 'not found' case
		 *	as we can relay to a server where the IP address might
		 *	be found.  This extremely useful for migrations.
		 */
		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("Requested IP address \"%s\" is not a member of the specified pool", ip_str);
			RETURN_MODULE_NOTFOUND;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("Requested IP address' \"%s\" lease allocated to another device", ip_str);
			RETURN_MODULE_INVALID;

		default:
			RETURN_MODULE_FAIL;
		}
	}

	case POOL_ACTION_BULK_RELEASE:
		RDEBUG2("Bulk release not yet implemented");
		RETURN_MODULE_NOOP;

	default:
		fr_assert(0);
		RETURN_MODULE_FAIL;
	}
}

static unlang_action_t CC_HINT(nonnull) mod_accounting(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	fr_pair_t			*vp;

	/*
	 *	Pool-Action override
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_pool_action);
	if (vp) return mod_action(p_result, inst, request, vp->vp_uint32);

	/*
	 *	Otherwise, guess the action by Acct-Status-Type
	 */
	vp = fr_pair_find_by_da(&request->request_pairs, attr_acct_status_type);
	if (!vp) {
		RDEBUG2("Couldn't find &request.Acct-Status-Type or &control.Pool-Action, doing nothing...");
		RETURN_MODULE_NOOP;
	}

	switch (vp->vp_uint32) {
	case FR_STATUS_START:
	case FR_STATUS_ALIVE:
		return mod_action(p_result, inst, request, POOL_ACTION_UPDATE);

	case FR_STATUS_STOP:
		return mod_action(p_result, inst, request, POOL_ACTION_RELEASE);

	case FR_STATUS_ACCOUNTING_OFF:
	case FR_STATUS_ACCOUNTING_ON:
		return mod_action(p_result, inst, request, POOL_ACTION_BULK_RELEASE);

	default:
		RETURN_MODULE_NOOP;
	}
}

static unlang_action_t CC_HINT(nonnull) mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	fr_pair_t			*vp;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_pool_action);
	return mod_action(p_result, inst, request, vp ? vp->vp_uint32 : POOL_ACTION_ALLOCATE);
}

static unlang_action_t CC_HINT(nonnull) mod_post_auth(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	fr_pair_t			*vp;
	ippool_action_t			action = POOL_ACTION_ALLOCATE;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, attr_pool_action);
	if (vp) {
		if ((vp->vp_uint32 > 0) && (vp->vp_uint32 <= POOL_ACTION_BULK_RELEASE)) {
			action = vp->vp_uint32;

		} else {
			RWDEBUG("Ignoring invalid action %d", vp->vp_uint32);
			RETURN_MODULE_NOOP;
		}

	} else if (request->dict == dict_dhcpv4) {
		vp = fr_pair_find_by_da(&request->control_pairs, attr_message_type);
		if (!vp) goto run;

		if (vp->vp_uint8 == FR_DHCP_REQUEST) action = POOL_ACTION_UPDATE;
	}

run:
	return mod_action(p_result, inst, request, action);
}

static unlang_action_t CC_HINT(nonnull) mod_request(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	fr_pair_t			*vp;

	/*
	 *	Unless it's overridden the default action is to update
	 *	when called by DHCP request
	 */

	vp = fr_pair_find_by_da(&request->control_pairs, attr_pool_action);
	return mod_action(p_result, inst, request, vp ? vp->vp_uint32 : POOL_ACTION_UPDATE);
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	static bool			done_hash = false;
	CONF_SECTION			*subcs = cf_section_find(conf, "redis", NULL);

	rlm_redis_ippool_t		*inst = instance;

	fr_assert(tmpl_is_attr(inst->allocated_address_attr));
	fr_assert(subcs);

	inst->cluster = fr_redis_cluster_alloc(inst, subcs, &inst->conf, true, NULL, NULL, NULL);
	if (!inst->cluster) return -1;

	if (!fr_redis_cluster_min_version(inst->cluster, "3.0.2")) {
		PERROR("Cluster error");
		return -1;
	}

	/*
	 *	Pre-Compute the SHA1 hashes of the Lua scripts
	 */
	if (!done_hash) {
		fr_sha1_ctx	sha1_ctx;
		uint8_t		digest[SHA1_DIGEST_LENGTH];

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_alloc_cmd, sizeof(lua_alloc_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(&FR_SBUFF_OUT(lua_alloc_digest, sizeof(lua_alloc_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)), SIZE_MAX);

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_update_cmd, sizeof(lua_update_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(&FR_SBUFF_OUT(lua_update_digest, sizeof(lua_update_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)), SIZE_MAX);

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_release_cmd, sizeof(lua_release_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(&FR_SBUFF_OUT(lua_release_digest, sizeof(lua_release_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)), SIZE_MAX);
	}

	/*
	 *	If we don't have a separate time specifically for offers
	 *	just use the lease time.
	 */
	if (!inst->offer_time) inst->offer_time = inst->lease_time;

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return 0;
}

extern module_t rlm_redis_ippool;
module_t rlm_redis_ippool = {
	.magic		= RLM_MODULE_INIT,
	.name		= "redis",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_redis_ippool_t),
	.config		= module_config,
	.onload		= mod_load,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth,
	},
	.method_names = (module_method_names_t[]) {
		{ "recv",	"DHCP-Request",	mod_request },
		MODULE_NAME_TERMINATOR
	}
};
