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
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/modpriv.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/token.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>

#include <freeradius-devel/unlang/call_env.h>

#include "redis_ippool.h"

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.

	uint32_t		wait_num;	//!< How many slaves we want to acknowledge allocations
						//!< or updates.

	fr_time_delta_t		wait_timeout;	//!< How long we wait for slaves to acknowledge writing.

	bool			ipv4_integer;	//!< Whether IPv4 addresses should be cast to integers,
						//!< for renew operations.

	bool			copy_on_update; //!< Copy the address provided by ip_address to the
						//!< allocated_address_attr if updates are successful.

	fr_redis_cluster_t	*cluster;	//!< Redis cluster.
} rlm_redis_ippool_t;

static conf_parser_t redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("wait_num", rlm_redis_ippool_t, wait_num) },
	{ FR_CONF_OFFSET("wait_timeout", rlm_redis_ippool_t, wait_timeout) },

	{ FR_CONF_DEPRECATED("ip_address", rlm_redis_ippool_t, NULL) },

	{ FR_CONF_DEPRECATED("reply_attr", rlm_redis_ippool_t, NULL) },

	{ FR_CONF_OFFSET("ipv4_integer", rlm_redis_ippool_t, ipv4_integer) },
	{ FR_CONF_OFFSET("copy_on_update", rlm_redis_ippool_t, copy_on_update), .dflt = "yes", .quote = T_BARE_WORD },

	/*
	 *	Split out to allow conversion to universal ippool module with
	 *	minimum of config changes.
	 */
	{ FR_CONF_POINTER("redis", 0, CONF_FLAG_SUBSECTION, NULL), .subcs = redis_config },
	CONF_PARSER_TERMINATOR
};

/** Call environment used when calling redis_ippool allocate method.
 *
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of the pool we're allocating IP addresses from.

	fr_value_box_t	offer_time;			//!< How long we should reserve a lease for during
							///< the pre-allocation stage (typically responding
							///< to DHCP discover).

	fr_value_box_t	lease_time;			//!< How long an IP address should be allocated for.

	fr_value_box_t	owner;				//!< Unique lease owner identifier.  Could be mac-address
							///< or a combination of User-Name and something
							///< unique to the device.

	fr_value_box_t	gateway_id;			//!< Gateway identifier, usually NAS-Identifier or
							///< Option 82 gateway.  Used for bulk lease cleanups.

	fr_value_box_t	requested_address;		//!< Attribute to read the IP for renewal from.

	tmpl_t		*allocated_address_attr;	//!< Attribute to populate with allocated IP.

	tmpl_t		*range_attr;			//!< Attribute to write the range ID to.

	tmpl_t		*expiry_attr;			//!< Time at which the lease will expire.
} redis_ippool_alloc_call_env_t;

/** Call environment used when calling redis_ippool update method.
 *
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of the pool we're allocating IP addresses from.

	fr_value_box_t	lease_time;			//!< How long an IP address should be allocated for.

	fr_value_box_t	owner;				//!< Unique lease owner identifier.  Could be mac-address
							///< or a combination of User-Name and something
							///< unique to the device.

	fr_value_box_t	gateway_id;			//!< Gateway identifier, usually NAS-Identifier or
							///< Option 82 gateway.  Used for bulk lease cleanups.

	fr_value_box_t	requested_address;		//!< Attribute to read the IP for renewal from.

	tmpl_t		*allocated_address_attr;	//!< Attribute to populate with allocated IP.

	tmpl_t		*range_attr;			//!< Attribute to write the range ID to.

	tmpl_t		*expiry_attr;			//!< Time at which the lease will expire.
} redis_ippool_update_call_env_t;

/** Call environment used when calling redis_ippool release method.
 *
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of the pool we're allocating IP addresses from.

	fr_value_box_t	owner;				//!< Unique lease owner identifier.  Could be mac-address
							///< or a combination of User-Name and something
							///< unique to the device.

	fr_value_box_t	gateway_id;			//!< Gateway identifier, usually NAS-Identifier or
							///< Option 82 gateway.  Used for bulk lease cleanups.

	fr_value_box_t	requested_address;		//!< Attribute to read the IP for renewal from.

} redis_ippool_release_call_env_t;

/** Call environment used when calling redis_ippool bulk release method.
 *
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of the pool we're allocating IP addresses from.

	fr_value_box_t	gateway_id;			//!< Gateway identifier, usually NAS-Identifier or
							///< Option 82 gateway.  Used for bulk lease cleanups.
} redis_ippool_bulk_release_call_env_t;

static const call_env_method_t redis_ippool_alloc_method_env = {
	FR_CALL_ENV_METHOD_OUT(redis_ippool_alloc_call_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE,
				     redis_ippool_alloc_call_env_t, pool_name) },
		{ FR_CALL_ENV_OFFSET("owner", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE,
				     redis_ippool_alloc_call_env_t, owner) },
		{ FR_CALL_ENV_OFFSET("gateway", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE,
				      redis_ippool_alloc_call_env_t, gateway_id ), .pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		{ FR_CALL_ENV_OFFSET("offer_time", FR_TYPE_UINT32, CALL_ENV_FLAG_NONE, redis_ippool_alloc_call_env_t, offer_time ) },
		{ FR_CALL_ENV_OFFSET("lease_time", FR_TYPE_UINT32, CALL_ENV_FLAG_REQUIRED, redis_ippool_alloc_call_env_t, lease_time) },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_COMBO_IP_ADDR, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_alloc_call_env_t, requested_address ),
				     .pair.dflt = "%{%{Requested-IP-Address} || %{Net.Src.IP}}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("allocated_address_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_alloc_call_env_t, allocated_address_attr) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("range_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_alloc_call_env_t, range_attr),
					       .pair.dflt = "&reply.IP-Pool.Range", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("expiry_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE, redis_ippool_alloc_call_env_t, expiry_attr) },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t redis_ippool_update_method_env = {
	FR_CALL_ENV_METHOD_OUT(redis_ippool_update_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_update_call_env_t, pool_name) },
		{ FR_CALL_ENV_OFFSET("owner", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_update_call_env_t, owner) },
		{ FR_CALL_ENV_OFFSET("gateway", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_update_call_env_t, gateway_id),
				     .pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		{ FR_CALL_ENV_OFFSET("lease_time", FR_TYPE_UINT32, CALL_ENV_FLAG_REQUIRED,  redis_ippool_update_call_env_t, lease_time) },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_COMBO_IP_ADDR, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_update_call_env_t, requested_address),
				     .pair.dflt = "%{%{Requested-IP-Address} || %{Net.Src.IP}}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("allocated_address_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_update_call_env_t, allocated_address_attr) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("range_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_update_call_env_t, range_attr),
					       .pair.dflt = "&reply.IP-Pool.Range", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("expiry_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE, redis_ippool_update_call_env_t, expiry_attr) },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t redis_ippool_release_method_env = {
	FR_CALL_ENV_METHOD_OUT(redis_ippool_release_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_release_call_env_t, pool_name) },
		{ FR_CALL_ENV_OFFSET("owner", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_release_call_env_t, owner) },
		{ FR_CALL_ENV_OFFSET("gateway", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_release_call_env_t, gateway_id),
				     .pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_COMBO_IP_ADDR, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_release_call_env_t, requested_address),
				     .pair.dflt = "%{%{Requested-IP-Address} || %{Net.Src.IP}}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		CALL_ENV_TERMINATOR
	}
};

static const call_env_method_t redis_ippool_bulk_release_method_env = {
	FR_CALL_ENV_METHOD_OUT(redis_ippool_bulk_release_call_env_t),
	.env = (call_env_parser_t[]) {
		{ FR_CALL_ENV_OFFSET("pool_name", FR_TYPE_STRING, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_bulk_release_call_env_t, pool_name) },
		{ FR_CALL_ENV_OFFSET("gateway", FR_TYPE_STRING, CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_CONCAT | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_bulk_release_call_env_t, gateway_id),
				     .pair.dflt = "", .pair.dflt_quote = T_SINGLE_QUOTED_STRING },
		CALL_ENV_TERMINATOR
	}
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
	"owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[3]" EOL				/* 7 */

	/*
	 *	Check to see if the client already has a lease,
	 *	and if it does return that.
	 *
	 *	The additional sanity checks are to allow for the record
	 *	of device/ip binding to persist for longer than the lease.
	 */
	"exists = redis.call('GET', owner_key);" EOL							/* 8 */
	"if exists then" EOL										/* 9 */
	"  local expires = tonumber(redis.call('ZSCORE', pool_key, exists))" EOL			/* 10 */
	"  local static = expires >= " STRINGIFY(IPPOOL_STATIC_BIT) EOL					/* 11 */
	"  local expires_in = expires - (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0) - ARGV[1]" EOL	/* 12 */
	"  if expires_in > 0 or static then" EOL							/* 13 */
	"    ip = redis.call('HMGET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. exists, 'device', 'range', 'counter', 'gateway')" EOL	/* 14 */
	"    if ip and (ip[1] == ARGV[3]) then" EOL							/* 15 */
	"      if expires_in < tonumber(ARGV[2]) then" EOL						/* 16 */
	"        redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2] + (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0), exists)" EOL	/* 17 */
	"        expires_in = tonumber(ARGV[2])" EOL							/* 18 */
	"        if not static then" EOL								/* 19 */
	"          redis.call('EXPIRE', owner_key, ARGV[2])" EOL					/* 20 */
	"        end" EOL										/* 21 */
	"      end" EOL											/* 22 */

	/*
	 *	Ensure gateway is set correctly
	 */
	"      if ARGV[4] ~= ip[4] then" EOL								/* 23 */
	"        redis.call('HSET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":', 'gateway', ARGV[4])" EOL	/* 24 */
	"      end" EOL											/* 25 */
	"      return {" STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", exists, ip[2], expires_in, ip[3] }" EOL	/* 26 */
	"    end" EOL											/* 27 */
	"  end" EOL											/* 28 */
	"end" EOL											/* 29 */

	/*
	 *	Else, get the IP address which expired the longest time ago.
	 */
	"ip = redis.call('ZREVRANGE', pool_key, -1, -1, 'WITHSCORES')" EOL				/* 30 */
	"if not ip or not ip[1] then" EOL								/* 31 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 32 */
	"end" EOL											/* 33 */
	"if ip[2] >= ARGV[1] then" EOL									/* 34 */
	"  return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 35 */
	"end" EOL											/* 36 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2], ip[1])" EOL				/* 37 */

	/*
	 *	Set the device/gateway keys
	 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ip[1]" EOL			/* 38 */
	"redis.call('HMSET', address_key, 'device', ARGV[3], 'gateway', ARGV[4])" EOL			/* 39 */
	"redis.call('SET', owner_key, ip[1])" EOL							/* 40 */
	"redis.call('EXPIRE', owner_key, ARGV[2])" EOL							/* 41 */
	"return { " EOL											/* 42 */
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL							/* 43 */
	"  ip[1], " EOL											/* 44 */
	"  redis.call('HGET', address_key, 'range'), " EOL						/* 45 */
	"  tonumber(ARGV[2]), " EOL									/* 46 */
	"  redis.call('HINCRBY', address_key, 'counter', 1)" EOL					/* 47 */
	"}" EOL;											/* 48 */
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
	"local expires = tonumber(redis.call('ZSCORE', pool_key, ARGV[3]))" EOL		/* 15 */
	"local static = expires > " STRINGIFY(IPPOOL_STATIC_BIT) EOL			/* 16 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2] + (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0), ARGV[3])" EOL	/* 17 */

	/*
	 *	The device key should usually exist, but
	 *	theoretically, if we were right on the cusp
	 *	of a lease being expired, it may have been
	 *	removed.
	 */
	"owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[4]" EOL		/* 18 */
	"if not static and (redis.call('EXPIRE', owner_key, ARGV[2]) == 0) then" EOL	/* 19 */
	"  redis.call('SET', owner_key, ARGV[3])" EOL					/* 20 */
	"  redis.call('EXPIRE', owner_key, ARGV[2])" EOL				/* 21 */
	"end" EOL									/* 22 */

	/*
	 *	Update the gateway address
	 */
	"if ARGV[5] ~= found[3] then" EOL						/* 23 */
	"  redis.call('HSET', address_key, 'gateway', ARGV[5])" EOL			/* 24 */
	"end" EOL									/* 25 */
	"return { " STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", found[1], found[4] }"EOL;	/* 26 */
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
	"end" EOL									/* 10 */
	"if found and found ~= ARGV[3] then" EOL					/* 11 */
	"  return { " STRINGIFY(_IPPOOL_RCODE_DEVICE_MISMATCH) ", found }" EOL		/* 12 */
	"end" EOL									/* 13 */

	/*
	 *	Set expiry time to now() - 1
	 */
	"pool_key = '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"'" EOL			/* 14 */
	"found = tonumber(redis.call('ZSCORE', pool_key, ARGV[2]))" EOL			/* 15 */
	"local static = found > " STRINGIFY(IPPOOL_STATIC_BIT) EOL			/* 16 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] - 1 + (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0), ARGV[2])" EOL		/* 17 */

	/*
	 *	Remove the association between the device and a lease
	 */
	"if not static then" EOL							/* 18 */
	"  owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[3]" EOL	/* 19 */
	"  redis.call('DEL', owner_key)" EOL						/* 20 */
	"end" EOL									/* 21 */
	"return { " EOL									/* 22 */
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL					/* 23 */
	"  redis.call('HINCRBY', address_key, 'counter', 1) - 1" EOL			/* 24 */
	"}";										/* 25 */
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
				fr_value_box_t const *key_prefix,
				fr_value_box_t const *ip,
				fr_value_box_t const *owner,
				fr_value_box_t  const *gateway_id,
				uint32_t expires)
{
	char *device_str = NULL, *gateway_str = NULL;

	if (gateway_id && gateway_id->vb_length > 0) gateway_str = fr_asprint(request, gateway_id->vb_strvalue,
									      gateway_id->vb_length, '"');
	if (owner && owner->vb_length > 0) device_str = fr_asprint(request, owner->vb_strvalue, owner->vb_length, '"');

	switch (action) {
	case POOL_ACTION_ALLOCATE:
		RDEBUGX(lvl, "Allocating lease from pool \"%pV\"%s%s%s%s%s%s, expires in %us",
			key_prefix,
			device_str ? ", to \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			gateway_str ? ", on \"" : "", gateway_str ? gateway_str : "",
			gateway_str ? "\"" : "",
			expires);
		break;

	case POOL_ACTION_UPDATE:
		RDEBUGX(lvl, "Updating %pV in pool \"%pV\"%s%s%s%s%s%s, expires in %us",
			ip, key_prefix,
			device_str ? ", device \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			gateway_str ? ", gateway \"" : "", gateway_str ? gateway_str : "",
			gateway_str ? "\"" : "",
			expires);
		break;

	case POOL_ACTION_RELEASE:
		RDEBUGX(lvl, "Releasing %pV%s%s%s to pool \"%pV\"",
			ip,
			device_str ? " leased by \"" : "", device_str ? device_str : "",
			device_str ? "\"" : "",
			key_prefix);
		break;

	default:
		break;
	}

	/*
	 *	Ordering is important, needs to be LIFO
	 *	for proper talloc pool reuse.
	 */
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
 * @param[in] wait_timeout	How long to wait for slaves to replicate the data.
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
			redisAppendCommand(conn->handle, "WAIT %i %i", wait_num, fr_time_delta_to_msec(wait_timeout));
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
				RERROR("Bad response to EXEC, expected array got %s",
				       fr_table_str_by_value(redis_reply_types, replies[3]->type, "<UNKNOWN>"));
			error:
				fr_redis_pipeline_free(replies, reply_cnt);
				status = REDIS_RCODE_ERROR;
				goto finish;
			}
			if (replies[3]->elements != 2) {
				RERROR("Bad response to EXEC, expected 2 result elements, got %zu",
				       replies[3]->elements);
				goto error;
			}
			if (replies[3]->element[0]->type != REDIS_REPLY_STRING) {
				RERROR("Bad response to SCRIPT LOAD, expected string got %s",
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
		FALL_THROUGH;

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
					    redis_ippool_alloc_call_env_t *env, uint32_t lease_time)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	fr_assert(env->pool_name.vb_length > 0);
	fr_assert(env->owner.vb_length > 0);

	now = fr_time_to_timeval(fr_time());

	status = ippool_script(&reply, request, inst->cluster,
			       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
			       inst->wait_num, inst->wait_timeout,
			       lua_alloc_digest, lua_alloc_cmd,
	 		       "EVALSHA %s 1 %b %u %u %b %b",
	 		       lua_alloc_digest,
			       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
			       (unsigned int)now.tv_sec, lease_time,
			       (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length,
			       (uint8_t const *)env->gateway_id.vb_strvalue, env->gateway_id.vb_length);
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
			.lhs = env->allocated_address_attr,
			.op = T_OP_SET,
			.rhs = &ip_rhs
		};

		tmpl_init_shallow(&ip_rhs, TMPL_TYPE_DATA, T_BARE_WORD, "", 0, NULL);
		switch (reply->element[1]->type) {
		/*
		 *	Destination attribute may not be IPv4, in which case
		 *	we want to pre-convert the integer value to an IPv4
		 *	address before casting it once more to the type of
		 *	the destination attribute.
		 */
		case REDIS_REPLY_INTEGER:
		{
			if (tmpl_attr_tail_da(ip_map.lhs)->type != FR_TYPE_IPV4_ADDR) {
				fr_value_box_t tmp;

				fr_value_box(&tmp, (uint32_t)ntohl((uint32_t)reply->element[1]->integer), true);
				if (fr_value_box_cast(NULL, tmpl_value(ip_map.rhs), FR_TYPE_IPV4_ADDR,
						      NULL, &tmp)) {
					RPEDEBUG("Failed converting integer to IPv4 address");
					ret = IPPOOL_RCODE_FAIL;
					goto finish;
				}
			} else {
				fr_value_box(&ip_map.rhs->data.literal,
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
				.lhs = env->range_attr,
				.op = T_OP_SET,
				.rhs = &range_rhs
			};

			tmpl_init_shallow(&range_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
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
	if (env->expiry_attr && (reply->elements > 3)) {
		tmpl_t expiry_rhs;
		map_t expiry_map = {
			.lhs = env->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};

		tmpl_init_shallow(&expiry_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
		if (reply->element[3]->type != REDIS_REPLY_INTEGER) {
			REDEBUG("Server returned unexpected type \"%s\" for expiry element (result[3])",
				fr_table_str_by_value(redis_reply_types, reply->element[3]->type, "<UNKNOWN>"));
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}

		fr_value_box(&expiry_map.rhs->data.literal, (uint32_t)reply->element[3]->integer, true);
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
					  redis_ippool_update_call_env_t *env,
					  fr_ipaddr_t *ip,
					  fr_value_box_t const *owner,
					  fr_value_box_t const *gateway_id,
					  uint32_t expires)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	now = fr_time_to_timeval(fr_time());

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = ippool_script(&reply, request, inst->cluster,
				       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				       inst->wait_num, inst->wait_timeout,
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %u %u %u %b %b",
				       lua_update_digest,
				       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				       (unsigned int)now.tv_sec, expires,
				       htonl(ip->addr.v4.s_addr),
				       (uint8_t const *)owner->vb_strvalue, owner->vb_length,
				       (uint8_t const *)gateway_id->vb_strvalue, gateway_id->vb_length);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = ippool_script(&reply, request, inst->cluster,
				       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				       inst->wait_num, inst->wait_timeout,
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %u %u %s %b %b",
				       lua_update_digest,
				       (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				       (unsigned int)now.tv_sec, expires,
				       ip_buff,
				       (uint8_t const *)owner->vb_strvalue, owner->vb_length,
				       (uint8_t const *)gateway_id->vb_strvalue, gateway_id->vb_length);
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
		{
			tmpl_t	range_rhs;
			map_t	range_map = { .lhs = env->range_attr, .op = T_OP_SET, .rhs = &range_rhs };

			tmpl_init_shallow(&range_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);
			fr_value_box_bstrndup_shallow(&range_map.rhs->data.literal, NULL,
						      reply->element[1]->str, reply->element[1]->len, true);
			if (map_to_request(request, &range_map, map_to_vp, NULL) < 0) {
				ret = IPPOOL_RCODE_FAIL;
				goto finish;
			}
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
	if (env->expiry_attr) {
		tmpl_t expiry_rhs;
		map_t expiry_map = {
			.lhs = env->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};


		tmpl_init_shallow(&expiry_rhs, TMPL_TYPE_DATA, T_DOUBLE_QUOTED_STRING, "", 0, NULL);

		fr_value_box(&expiry_map.rhs->data.literal, expires, false);
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
					   fr_value_box_t const *key_prefix,
					   fr_ipaddr_t *ip,
					   fr_value_box_t const *owner)
{
	struct			timeval now;
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	now = fr_time_to_timeval(fr_time());

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = ippool_script(&reply, request, inst->cluster,
				       (uint8_t const *)key_prefix->vb_strvalue, key_prefix->vb_length,
				       inst->wait_num, inst->wait_timeout,
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %u %u %b",
				       lua_release_digest,
				       (uint8_t const *)key_prefix->vb_strvalue, key_prefix->vb_length,
				       (unsigned int)now.tv_sec,
				       htonl(ip->addr.v4.s_addr),
				       (uint8_t const *)owner->vb_strvalue, owner->vb_length);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = ippool_script(&reply, request, inst->cluster,
				       (uint8_t const *)key_prefix->vb_strvalue, key_prefix->vb_length,
				       inst->wait_num, inst->wait_timeout,
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %u %s %b",
				       lua_release_digest,
				       (uint8_t const *)key_prefix->vb_strvalue, key_prefix->vb_length,
				       (unsigned int)now.tv_sec,
				       ip_buff,
				       (uint8_t const *)owner->vb_strvalue, owner->vb_length);
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

#define CHECK_POOL_NAME \
	if (env->pool_name.vb_length > IPPOOL_MAX_KEY_PREFIX_SIZE) { \
		REDEBUG("Pool name too long.  Expected %u bytes, got %ld bytes", \
			IPPOOL_MAX_KEY_PREFIX_SIZE, env->pool_name.vb_length); \
		RETURN_MODULE_FAIL; \
	} \
	if (env->pool_name.vb_length == 0) { \
		RDEBUG2("Empty pool name.  Doing nothing"); \
		RETURN_MODULE_NOOP; \
	}

static unlang_action_t CC_HINT(nonnull) mod_alloc(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	redis_ippool_alloc_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_alloc_call_env_t);
	uint32_t			lease_time;

	CHECK_POOL_NAME

	/*
	 *	If offer_time is defined, it will be FR_TYPE_UINT32.
	 *	Fall back to lease_time otherwise.
	 */
	lease_time = (env->offer_time.type == FR_TYPE_UINT32) ?
			env->offer_time.vb_uint32 : env->lease_time.vb_uint32;
	ippool_action_print(request, POOL_ACTION_ALLOCATE, L_DBG_LVL_2, &env->pool_name, NULL,
			    &env->owner, &env->gateway_id, lease_time);
	switch (redis_ippool_allocate(inst, request, env, lease_time)) {
	case IPPOOL_RCODE_SUCCESS:
		RDEBUG2("IP address lease allocated");
		RETURN_MODULE_UPDATED;

	case IPPOOL_RCODE_POOL_EMPTY:
		RWDEBUG("Pool contains no free addresses");
		RETURN_MODULE_NOTFOUND;

	default:
		RETURN_MODULE_FAIL;
	}
}

static unlang_action_t CC_HINT(nonnull) mod_update(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	redis_ippool_update_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_update_call_env_t);

	CHECK_POOL_NAME

	ippool_action_print(request, POOL_ACTION_UPDATE, L_DBG_LVL_2, &env->pool_name,
			    &env->requested_address, &env->owner, &env->gateway_id, env->lease_time.vb_uint32);
	switch (redis_ippool_update(inst, request, env,
				    &env->requested_address.datum.ip, &env->owner,
				    &env->gateway_id,
				    env->lease_time.vb_uint32)) {
	case IPPOOL_RCODE_SUCCESS:
		RDEBUG2("Requested IP address' \"%pV\" lease updated", &env->requested_address);

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
				.lhs = env->allocated_address_attr,
				.op = T_OP_SET,
				.rhs = &ip_rhs
			};

			fr_value_box_copy(NULL, &ip_rhs.data.literal, &env->requested_address);

			if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) RETURN_MODULE_FAIL;
		}
		RETURN_MODULE_UPDATED;

	/*
	 *	It's useful to be able to identify the 'not found' case
	 *	as we can relay to a server where the IP address might
	 *	be found.  This extremely useful for migrations.
	 */
	case IPPOOL_RCODE_NOT_FOUND:
		REDEBUG("Requested IP address \"%pV\" is not a member of the specified pool",
			&env->requested_address);
		RETURN_MODULE_NOTFOUND;

	case IPPOOL_RCODE_EXPIRED:
		REDEBUG("Requested IP address' \"%pV\" lease already expired at time of renewal",
			&env->requested_address);
		RETURN_MODULE_INVALID;

	case IPPOOL_RCODE_DEVICE_MISMATCH:
		REDEBUG("Requested IP address' \"%pV\" lease allocated to another device",
			&env->requested_address);
		RETURN_MODULE_INVALID;

	default:
		RETURN_MODULE_FAIL;
	}
}

static unlang_action_t CC_HINT(nonnull) mod_release(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	redis_ippool_release_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_release_call_env_t);

	CHECK_POOL_NAME

	ippool_action_print(request, POOL_ACTION_RELEASE, L_DBG_LVL_2, &env->pool_name,
			    &env->requested_address, &env->owner, &env->gateway_id, 0);
	switch (redis_ippool_release(inst, request, &env->pool_name, &env->requested_address.datum.ip, &env->owner)) {
	case IPPOOL_RCODE_SUCCESS:
		RDEBUG2("IP address \"%pV\" released", &env->requested_address);
		RETURN_MODULE_UPDATED;

	/*
	 *	It's useful to be able to identify the 'not found' case
	 *	as we can relay to a server where the IP address might
	 *	be found.  This extremely useful for migrations.
	 */
	case IPPOOL_RCODE_NOT_FOUND:
		REDEBUG("Requested IP address \"%pV\" is not a member of the specified pool",
			&env->requested_address);
		RETURN_MODULE_NOTFOUND;

	case IPPOOL_RCODE_DEVICE_MISMATCH:
		REDEBUG("Requested IP address' \"%pV\" lease allocated to another device",
			&env->requested_address);
		RETURN_MODULE_INVALID;

	default:
		RETURN_MODULE_FAIL;
	}
}

static unlang_action_t CC_HINT(nonnull) mod_bulk_release(rlm_rcode_t *p_result, UNUSED module_ctx_t const *mctx,
							 request_t *request)
{
	RDEBUG2("Bulk release not yet implemented");
	RETURN_MODULE_NOOP;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	static bool			done_hash = false;
	CONF_SECTION			*subcs = cf_section_find(mctx->mi->conf, "redis", NULL);

	rlm_redis_ippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_ippool_t);

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
		fr_base16_encode(&FR_SBUFF_OUT(lua_alloc_digest, sizeof(lua_alloc_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)));

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_update_cmd, sizeof(lua_update_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_base16_encode(&FR_SBUFF_OUT(lua_update_digest, sizeof(lua_update_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)));

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_release_cmd, sizeof(lua_release_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_base16_encode(&FR_SBUFF_OUT(lua_release_digest, sizeof(lua_release_digest)), &FR_DBUFF_TMP(digest, sizeof(digest)));
	}

	return 0;
}

static int mod_load(void)
{
	fr_redis_version_print();

	return 0;
}

extern module_rlm_t rlm_redis_ippool;
module_rlm_t rlm_redis_ippool = {
	.common = {
		.magic		= MODULE_MAGIC_INIT,
		.name		= "redis",
		.inst_size	= sizeof(rlm_redis_ippool_t),
		.config		= module_config,
		.onload		= mod_load,
		.instantiate	= mod_instantiate
	},
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME("recv", "Access-Request"), .method = mod_alloc, .method_env = &redis_ippool_alloc_method_env },			/* radius */
			{ .section = SECTION_NAME("accounting", "Start"), .method = mod_update, .method_env = &redis_ippool_update_method_env },			/* radius */
			{ .section = SECTION_NAME("accounting", "Interim-Update"), .method = mod_update, .method_env = &redis_ippool_update_method_env },		/* radius */
			{ .section = SECTION_NAME("accounting", "Stop"), .method = mod_release, .method_env = &redis_ippool_release_method_env },			/* radius */
			{ .section = SECTION_NAME("accounting", "Accounting-On"), .method = mod_bulk_release, .method_env = &redis_ippool_bulk_release_method_env },	/* radius */
			{ .section = SECTION_NAME("accounting", "Accounting-Off"), .method = mod_bulk_release, .method_env = &redis_ippool_bulk_release_method_env },	/* radius */

			{ .section = SECTION_NAME("recv", "Discover"), .method = mod_alloc, .method_env = &redis_ippool_alloc_method_env },				/* dhcpv4 */
			{ .section = SECTION_NAME("recv", "Release"), .method = mod_release, .method_env = &redis_ippool_release_method_env }, 				/* dhcpv4 */
			{ .section = SECTION_NAME("send", "Ack"), .method = mod_update, .method_env = &redis_ippool_update_method_env },				/* dhcpv4 */

			{ .section = SECTION_NAME("recv", "Solicit"), .method = mod_alloc, .method_env = &redis_ippool_alloc_method_env },				/* dhcpv6 */

			{ .section = SECTION_NAME("recv", CF_IDENT_ANY), .method = mod_update, .method_env = &redis_ippool_update_method_env },				/* generic */
			{ .section = SECTION_NAME("send", CF_IDENT_ANY), .method = mod_alloc, .method_env = &redis_ippool_alloc_method_env },				/* generic */

			{ .section = SECTION_NAME("allocate", NULL), .method = mod_alloc, .method_env = &redis_ippool_alloc_method_env },				/* verb */
			{ .section = SECTION_NAME("update", NULL), .method = mod_update, .method_env = &redis_ippool_update_method_env },				/* verb */
			{ .section = SECTION_NAME("renew", NULL), .method = mod_update, .method_env = &redis_ippool_update_method_env },				/* verb */
			{ .section = SECTION_NAME("release", NULL), .method = mod_release, .method_env = &redis_ippool_release_method_env },				/* verb */
			{ .section = SECTION_NAME("bulk-release", NULL), .method = mod_bulk_release, .method_env = &redis_ippool_bulk_release_method_env },		/* verb */
			MODULE_BINDING_TERMINATOR
		}
	}
};
