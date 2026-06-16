/*
 *   This program is free software; you can redistribute it and/or modify
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

#include <freeradius-devel/unlang/xlat_func.h>

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/base16.h>
#include <freeradius-devel/util/token.h>

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster_async.h>

#include "redis_ippool.h"

static fr_dict_t const *dict_redis;

extern fr_dict_autoload_t rlm_redis_ippool_dict[];
fr_dict_autoload_t rlm_redis_ippool_dict[] = {
	{ .out = &dict_redis, .proto = "redis" },
	DICT_AUTOLOAD_TERMINATOR
};

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	CONF_SECTION 		*tls_conf;	//!< TLS CONF_SECTION

	char const		*name;		//!< Instance name.

	uint32_t		wait_num;	//!< How many slaves we want to acknowledge allocations
						//!< or updates.

	fr_time_delta_t		wait_timeout;	//!< How long we wait for slaves to acknowledge writing.

	char			*wait_cmd;	//!< Preformatted redis "WAIT" command.
	int			wait_cmd_len;	//!< Length of wait_cmd

	bool			ipv4_integer;	//!< Whether IPv4 addresses should be cast to integers,
						//!< for renew operations.

	bool			copy_on_update; //!< Copy the address provided by ip_address to the
						//!< allocated_address_attr if updates are successful.

	fr_coord_reg_t		*coord_reg;		//!< Coordinator registration.
	fr_coord_pair_reg_t	*coord_pair_reg;	//!< Coord pair registration.
} rlm_redis_ippool_t;

typedef struct {
	rlm_redis_ippool_t		*inst;		//!< Module instance.
	fr_redis_cluster_thread_t	*rtcluster;	//!< Per thread Redis cluster.
	fr_coord_worker_t		*cw;		//!< Coord-worker for fetching cluster map.
} rlm_redis_ippool_thread_t;

typedef enum {
	REDIS_COORD_PAIR_CALLBACK_ID = 0,
} rlm_redis_coord_t;

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

	fr_value_box_t	association_time;		//!< How log should a device be associated with an IP address.
							///< This allows for "sticky" addressing, where the device -> IP
							///< association lasts longer than the lease time.

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

/** Resume context for validating WAIT replies.
 *
 */
typedef struct {
	int				wait_num;
	bool				fail;
} redis_wait_rctx_t;

/** Resume context for async calls to alloc script
 *
 */
typedef struct {
	redis_ippool_alloc_call_env_t	*env;		//!< Callenv for the current allocation
	char				*cmd_str;	//!< Formatted redis command
	fr_redis_command_set_t		*cmds;		//!< Command set to be run.
	fr_redis_async_cmd_t		*cmd;		//!< Redis async command.
	ippool_rcode_t			ret;		//!< Return code for the allocation result.
	redis_wait_rctx_t		wait_rctx;	//!< WAIT resume context.
} redis_ippool_alloc_rctx_t;

/** Call environment used when calling redis_ippool update method.
 *
 */
typedef struct {
	fr_value_box_t	pool_name;			//!< Name of the pool we're allocating IP addresses from.

	fr_value_box_t	lease_time;			//!< How long an IP address should be allocated for.

	fr_value_box_t	association_time;		//!< How long should a device be associated with an IP address.

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

/** Resume context for async calls to update script
 *
 */
typedef struct {
	redis_ippool_update_call_env_t	*env;		//!< Callenv for the current allocation
	char				*cmd_str;	//!< Formatted redis command
	fr_redis_command_set_t		*cmds;		//!< Command set to be run.
	fr_redis_async_cmd_t		*cmd;		//!< Redis async command.
	ippool_rcode_t			ret;		//!< Return code for the allocation result.
	redis_wait_rctx_t		wait_rctx;	//!< WAIT resume context.
} redis_ippool_update_rctx_t;

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

	fr_value_box_t	association_time;		//!< How long should a device be associated with an IP address.

} redis_ippool_release_call_env_t;

/** Resume context for async calls to update script
 *
 */
typedef struct {
	redis_ippool_release_call_env_t	*env;		//!< Callenv for the current allocation
	char				*cmd_str;	//!< Formatted redis command
	fr_redis_command_set_t		*cmds;		//!< Command set to be run.
	fr_redis_async_cmd_t		*cmd;		//!< Redis async command.
	ippool_rcode_t			ret;		//!< Return code for the allocation result.
	redis_wait_rctx_t		wait_rctx;	//!< WAIT resume context.
} redis_ippool_release_rctx_t;

/** Resume context for IP pool updating xlats
 *
 */
typedef struct {
	char 				**cmd_str;	//!< Formatted redis commands for this xlat
	fr_redis_command_set_t		*cmds;		//!< Redis command set to run
	fr_redis_async_cmd_t		*cmd;		//!< Redis async command.
	uint32_t			changes;	//!< Number of changes reported by redis.
} redis_ippool_tool_rctx_t;

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
		{ FR_CALL_ENV_OFFSET("association_time", FR_TYPE_UINT32, CALL_ENV_FLAG_NULLABLE, redis_ippool_alloc_call_env_t, association_time) },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_COMBO_IP_ADDR, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_alloc_call_env_t, requested_address ),
				     .pair.dflt = "%{%{Requested-IP-Address} || %{Net.Src.IP}}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("allocated_address_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_alloc_call_env_t, allocated_address_attr) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("range_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_alloc_call_env_t, range_attr),
					       .pair.dflt = "reply.IP-Pool.Range", .pair.dflt_quote = T_BARE_WORD },
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
		{ FR_CALL_ENV_OFFSET("association_time", FR_TYPE_UINT32, CALL_ENV_FLAG_NULLABLE,  redis_ippool_update_call_env_t, association_time) },
		{ FR_CALL_ENV_OFFSET("requested_address", FR_TYPE_COMBO_IP_ADDR, CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_NULLABLE | CALL_ENV_FLAG_BARE_WORD_ATTRIBUTE, redis_ippool_update_call_env_t, requested_address),
				     .pair.dflt = "%{Requested-IP-Address || Net.Src.IP}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("allocated_address_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_update_call_env_t, allocated_address_attr) },
		{ FR_CALL_ENV_PARSE_ONLY_OFFSET("range_attr", FR_TYPE_VOID, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED, redis_ippool_update_call_env_t, range_attr),
					       .pair.dflt = "reply.IP-Pool.Range", .pair.dflt_quote = T_BARE_WORD },
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
				     .pair.dflt = "%{Requested-IP-Address || Net.Src.IP}", .pair.dflt_quote = T_DOUBLE_QUOTED_STRING },
		{ FR_CALL_ENV_OFFSET("association_time", FR_TYPE_UINT32, CALL_ENV_FLAG_NULLABLE, redis_ippool_release_call_env_t, association_time) },
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
 * - ARGV[4] Device -> IP association time (seconds).
 * - ARGV[5] (optional) Gateway identifier.
 * - ARGV[6] (optional) Requested address.
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

	"local wall_time = tonumber(ARGV[1])" EOL							/* 8* */

	/*
	 *	Check to see if the client already has a lease,
	 *	and if it does return that.
	 *
	 *	The additional sanity checks are to allow for the record
	 *	of device/ip binding to persist for longer than the lease.
	 */
	"exists = redis.call('GET', owner_key);" EOL							/* 9 */
	"if exists then" EOL										/* 10 */
	"  local expires = tonumber(redis.call('ZSCORE', pool_key, exists))" EOL			/* 11 */
	"  local static = expires >= " STRINGIFY(IPPOOL_STATIC_BIT) EOL					/* 12 */
	"  local expires_in = expires - (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0) - ARGV[1]" EOL	/* 13 */
	"  ip = redis.call('HMGET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. exists, 'device', 'range', 'counter', 'gateway')" EOL	/* 14 */
	"  if ip and (ip[1] == ARGV[3]) then" EOL							/* 15 */
	"    if expires_in < tonumber(ARGV[2]) then" EOL						/* 16 */
	"      redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2] + (static and " STRINGIFY(IPPOOL_STATIC_BIT) " or 0), exists)" EOL		/* 17 */
	"      expires_in = tonumber(ARGV[2])" EOL							/* 18 */
	"      if not static then" EOL									/* 19 */
	"        redis.call('EXPIRE', owner_key, ARGV[4])" EOL						/* 20 */
	"      end" EOL											/* 21 */
	"    end" EOL											/* 22 */

	/*
	 *	Ensure gateway is set correctly
	 */
	"    if ARGV[5] ~= ip[5] then" EOL								/* 23 */
	"      redis.call('HSET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":', 'gateway', ARGV[5])" EOL	/* 24 */
	"    end" EOL											/* 25 */
	"    return {" STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", exists, ip[2], expires_in, ip[3] }" EOL	/* 26 */
	"  end" EOL											/* 27 */
	"end" EOL											/* 28 */

	/*
	 *	If there's a requested address, check if that is available i.e. not statically
	 *	assigned, nor already allocated.
	 */
	"if ARGV[6] and ARGV[6] ~= '' then" EOL								/* 29 */
	"  local expires = tonumber(redis.call('ZSCORE', pool_key, ARGV[6]))" EOL			/* 30 */
	"  if expires and tonumber(expires) < wall_time then" EOL					/* 31 */
	"    ip = { ARGV[6] }" EOL									/* 32 */
	"  end" EOL											/* 33 */
	"end" EOL											/* 34 */

	/*
	 *	Else, get the IP address which expired the longest time ago.
	 */
	"if not ip then" EOL										/* 35 */
	"  ip = redis.call('ZREVRANGE', pool_key, -1, -1, 'WITHSCORES')" EOL				/* 36 */
	"  if not ip or not ip[1] then" EOL								/* 37 */
	"    return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 38 */
	"  end" EOL											/* 39 */
	"  if tonumber(ip[2]) >= wall_time then" EOL							/* 40 */
	"    return {" STRINGIFY(_IPPOOL_RCODE_POOL_EMPTY) "}" EOL					/* 41 */
	"  end" EOL											/* 42 */
	"end" EOL											/* 43 */
	"redis.call('ZADD', pool_key, 'XX', ARGV[1] + ARGV[2], ip[1])" EOL				/* 44 */

	/*
	 *	Set the device/gateway keys
	 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ip[1]" EOL			/* 45 */
	"redis.call('HMSET', address_key, 'device', ARGV[3], 'gateway', ARGV[5])" EOL			/* 46 */
	"redis.call('SET', owner_key, ip[1])" EOL							/* 47 */
	"redis.call('EXPIRE', owner_key, ARGV[4])" EOL							/* 48 */
	"return { " EOL											/* 49 */
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL							/* 50 */
	"  ip[1], " EOL											/* 51 */
	"  redis.call('HGET', address_key, 'range'), " EOL						/* 52 */
	"  tonumber(ARGV[2]), " EOL									/* 53 */
	"  redis.call('HINCRBY', address_key, 'counter', 1)" EOL					/* 54 */
	"}" EOL;											/* 55 */
static char lua_alloc_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for updating leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] Wall time (seconds since epoch).
 * - ARGV[2] Expires in (seconds).
 * - ARGV[3] IP address to update.
 * - ARGV[4] Lease owner identifier.
 * - ARGV[5] Device -> IP association time (seconds).
 * - ARGV[6] (optional) Gateway identifier.
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
	"  redis.call('EXPIRE', owner_key, ARGV[5])" EOL				/* 21 */
	"end" EOL									/* 22 */

	/*
	 *	Update the gateway address
	 */
	"if ARGV[6] ~= found[3] then" EOL						/* 23 */
	"  redis.call('HSET', address_key, 'gateway', ARGV[6])" EOL			/* 24 */
	"end" EOL									/* 25 */
	"return { " STRINGIFY(_IPPOOL_RCODE_SUCCESS) ", found[1], found[4] }"EOL;	/* 26 */
static char lua_update_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for releasing leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] Wall time (seconds since epoch).
 * - ARGV[2] IP address to release.
 * - ARGV[3] Client identifier.
 * - ARGV[4] Device -> IP association time (seconds).
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
	 *	unless "sticky" addressing is in place where association_time
	 *	is set, in which case use that to set the expiry of the association.
	 */
	"if not static then" EOL							/* 18 */
	"  owner_key = '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. ARGV[3]" EOL	/* 19 */
	"  if tonumber(ARGV[4]) > 0 then" EOL						/* 20 */
	"    redis.call('EXPIRE', owner_key, ARGV[4])" EOL				/* 21 */
	"  else" EOL									/* 22 */
	"    redis.call('DEL', owner_key)" EOL						/* 24 */
	"  end" EOL									/* 25 */
	"end" EOL									/* 26 */
	"return { " EOL									/* 27 */
	"  " STRINGIFY(_IPPOOL_RCODE_SUCCESS) "," EOL					/* 28 */
	"  redis.call('HINCRBY', address_key, 'counter', 1) - 1" EOL			/* 29 */
	"}";										/* 30 */
static char lua_release_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for removing a lease
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] IP address to remove.
 *
 * Removes the IP entry in the ZSET, then removes the address hash, and the device key
 * if one exists.
 *
 * Will work with partially removed IP addresses (where the ZSET entry is absent but other
 * elements weren't cleaned up).
 *
 * Returns
 * - 0 if no ip addresses were removed.
 * - 1 if an ip address was removed.
 */
static char lua_remove_cmd[] =
	"local found" EOL								/* 1 */
	"local ret" EOL									/* 2 */
	"local address_key" EOL								/* 3 */

	"ret = redis.call('ZREM', '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"', ARGV[1])" EOL	/* 4 */
	"address_key = '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":' .. ARGV[1]" EOL	/* 5 */
	"found = redis.call('HGET', address_key, 'device')" EOL				/* 6 */
	"redis.call('DEL', address_key)" EOL						/* 7 */
	"if not found then" EOL								/* 8 */
	"  return ret"	EOL								/* 9 */
	"end" EOL									/* 10 */

	/*
	 *	Remove the association between the device and a lease
	 */
	"redis.call('DEL', '{' .. KEYS[1] .. '}:"IPPOOL_OWNER_KEY":' .. found)" EOL	/* 11 */
	"return 1" EOL;									/* 12 */

static uint32_t uint32_gen_mask(uint8_t bits)
{
	if (bits >= 32) return 0xffffffff;
	return (1U << bits) - 1;
}

/** Check the requisite number of slaves replicated the lease info
 *
 * @param request The current request.
 * @param cmd The Redis command triggering this callback
 * @param reply we got from the server.
 * @param rctx WAIT resume context.
 */
static inline void ippool_wait_check(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	redis_wait_rctx_t	*wait_rctx = rctx;
	if (!wait_rctx->wait_num) return;

	if (reply->type != REDIS_REPLY_INTEGER) {
		REDEBUG("WAIT result is wrong type, expected integer got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		wait_rctx->fail = true;
		return;
	}
	if (reply->integer < wait_rctx->wait_num) {
		REDEBUG("Too few slaves acknowledged allocation, needed %i, got %lli",
			wait_rctx->wait_num, reply->integer);
		wait_rctx->fail = true;
		return;
	}
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

/** Enqueue a script to run against a redis cluster
 *
 * @param[in] ctx		To allocate redis command set.
 * @param[out] out_cmds		Where to write a pointer to the command set.
 * @param[out] out_cmd		Where to write a pointer to the async command
 * @param[in] request		The current request.
 * @param[in] thread		Redis ippool thread
 * @param[in] key		to use to determine the cluster node.
 * @param[in] key_len		length of the key.
 * @param[in] cmd		Pre-formatted redis command to call script
 * @param[in] cmd_len		length of the pre-formatted command.
 * @param[in] complete		Callback to run when `cmd` is completed
 * @param[in] resume		Resume function to run after script completed.
 * @param[in] rctx		to pass to `complete` and `resume`.
 * @return #unlang_action_t
 */
static unlang_action_t ippool_script_enqueue(TALLOC_CTX *ctx, fr_redis_command_set_t **out_cmds,
					     fr_redis_async_cmd_t **out_cmd, request_t *request,
					     rlm_redis_ippool_thread_t *thread, uint8_t const *key, size_t key_len,
					     char const *cmd, int cmd_len, fr_redis_command_complete_t complete,
					     module_method_t resume, unlang_module_signal_t cancel, void *rctx,
					     redis_wait_rctx_t *wait_rctx)
{
	fr_redis_command_set_t	*cmds;
	fr_redis_async_rcode_t	ret;

	MEM(cmds = fr_redis_command_set_alloc(ctx, request, NULL, NULL, NULL, false));

	fr_redis_command_preformatted_add(cmds, cmd, cmd_len, complete, rctx);

	if (thread->inst->wait_cmd) {
		fr_redis_command_preformatted_add(cmds, thread->inst->wait_cmd, thread->inst->wait_cmd_len,
						  ippool_wait_check, wait_rctx);
	}

	*out_cmd = fr_redis_async_cmd_start(ctx, request, &ret, thread->rtcluster, key, key_len, cmds, false, NULL);

	REDIS_ASYNC_START_RCODE_PROCESS(ret, thread->rtcluster, thread->cw, thread->inst->coord_pair_reg,
					"Failed enqueuing Redis command", UNLANG_ACTION_FAIL)

	if (out_cmds) *out_cmds = cmds;
	return unlang_module_yield(request, resume, cancel, ~FR_SIGNAL_CANCEL, rctx);
}

/** Callback to process results from allocation script
 */
static void redis_ippool_allocate_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	redis_ippool_alloc_rctx_t	*alloc_rctx = talloc_get_type_abort(rctx, redis_ippool_alloc_rctx_t);
	redis_ippool_alloc_call_env_t	*env = alloc_rctx->env;

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		alloc_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		alloc_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		alloc_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}
	alloc_rctx->ret = reply->element[0]->integer;
	if (alloc_rctx->ret < 0) return;

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
					alloc_rctx->ret = IPPOOL_RCODE_FAIL;
					return;
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
				alloc_rctx->ret = IPPOOL_RCODE_FAIL;
				return;
			}
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for IP element (result[1])",
				fr_table_str_by_value(redis_reply_types, reply->element[1]->type, "<UNKNOWN>"));
			alloc_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
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
				alloc_rctx->ret = IPPOOL_RCODE_FAIL;
				return;
			}
		}
			break;

		case REDIS_REPLY_NIL:
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for range element (result[2])",
				fr_table_str_by_value(redis_reply_types, reply->element[2]->type, "<UNKNOWN>"));
			alloc_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
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
			alloc_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
		}

		fr_value_box(&expiry_map.rhs->data.literal, (uint32_t)reply->element[3]->integer, true);
		if (map_to_request(request, &expiry_map, map_to_vp, NULL) < 0) {
			alloc_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
		}
	}
}

/** Callback to process results from allocation script
 */
static void redis_ippool_update_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	redis_ippool_update_rctx_t	*update_rctx = talloc_get_type_abort(rctx, redis_ippool_update_rctx_t);
	redis_ippool_update_call_env_t	*env = update_rctx->env;

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		update_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		update_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		update_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}
	update_rctx->ret = reply->element[0]->integer;
	if (update_rctx->ret < 0) return;

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
				update_rctx->ret = IPPOOL_RCODE_FAIL;
				return;
			}
		}
			break;

		case REDIS_REPLY_NIL:
			break;

		default:
			REDEBUG("Server returned unexpected type \"%s\" for range element (result[1])",
				fr_table_str_by_value(redis_reply_types, reply->element[0]->type, "<UNKNOWN>"));
			update_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
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

		fr_value_box(&expiry_map.rhs->data.literal, env->lease_time.vb_uint32, false);
		if (map_to_request(request, &expiry_map, map_to_vp, NULL) < 0) {
			update_rctx->ret = IPPOOL_RCODE_FAIL;
			return;
		}
	}
}

/** Callback to process results from release script
 */
static void redis_ippool_release_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply,
					 void *rctx)
{
	redis_ippool_release_rctx_t	*release_rctx = talloc_get_type_abort(rctx, redis_ippool_release_rctx_t);

	if (reply->type != REDIS_REPLY_ARRAY) {
		REDEBUG("Expected result to be array got \"%s\"",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		release_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	if (reply->elements == 0) {
		REDEBUG("Got empty result array");
		release_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}

	/*
	 *	Process return code
	 */
	if (reply->element[0]->type != REDIS_REPLY_INTEGER) {
		REDEBUG("Server returned unexpected type \"%s\" for rcode element (result[0])",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		release_rctx->ret = IPPOOL_RCODE_FAIL;
		return;
	}
	release_rctx->ret = reply->element[0]->integer;
}

#define CHECK_POOL_NAME \
	if (env->pool_name.vb_length > IPPOOL_MAX_KEY_PREFIX_SIZE) { \
		REDEBUG("Pool name too long.  Expected %u bytes, got %ld bytes", \
			IPPOOL_MAX_KEY_PREFIX_SIZE, env->pool_name.vb_length); \
		RETURN_UNLANG_FAIL; \
	} \
	if (env->pool_name.vb_length == 0) { \
		RDEBUG2("Empty pool name.  Doing nothing"); \
		RETURN_UNLANG_NOOP; \
	}

/** Check the return code from an async redis command
 *
 * Redirecting to another node in response to ASK / MOVED codes.
 */
static inline unlang_action_t redis_ippool_rcode_check(request_t *request, fr_redis_command_set_t *cmds,
						       fr_redis_async_cmd_t *cmd, module_ctx_t const *mctx,
						       module_method_t resume, unlang_module_signal_t cancel)
{
	switch (fr_redis_command_set_rcode(cmds)) {
	case REDIS_ASYNC_RCODE_NO_SCRIPT:
		/*
		 *	Script loading is done following trunk connection.
		 *	A NO-SCRIPT response means the command was enqueued before the script load.
		 *	Re-enqueue the command set and it will run after the script load.
		 */
		if (fr_redis_async_cmd_resend(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return UNLANG_ACTION_FAIL;
		return unlang_module_yield(request, resume, cancel, ~FR_SIGNAL_CANCEL, mctx->rctx);

	case REDIS_ASYNC_RCODE_MOVE:
	{
		rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
		rlm_redis_ippool_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);

		if (inst->conf.use_cluster_map) fr_redis_cluster_thread_map_get(thread->rtcluster, thread->cw,
										inst->coord_pair_reg, false);
	}
		FALL_THROUGH;

	case REDIS_ASYNC_RCODE_ASK:
		if (fr_redis_async_cmd_redirect(cmd) != REDIS_ASYNC_RCODE_SUCCESS) return UNLANG_ACTION_FAIL;
		return unlang_module_yield(request, resume, cancel, ~FR_SIGNAL_CANCEL, mctx->rctx);

	default:
		break;
	}
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static void mod_alloc_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	redis_ippool_alloc_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_alloc_rctx_t);

	RDEBUG2("Forcibly cancelling Redis alloc command");

	fr_redis_async_cmd_cancel(rctx->cmd);
}

static unlang_action_t CC_HINT(nonnull) mod_alloc_resume(unlang_result_t *p_result, module_ctx_t const *mctx,
							 request_t *request)
{
	redis_ippool_alloc_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_alloc_rctx_t);

	if (redis_ippool_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_alloc_resume,
				     mod_alloc_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	switch (rctx->ret) {
	case IPPOOL_RCODE_SUCCESS:
		if (rctx->wait_rctx.fail) RETURN_UNLANG_FAIL;

		RDEBUG2("IP address lease allocated");
		RETURN_UNLANG_UPDATED;

	case IPPOOL_RCODE_POOL_EMPTY:
		RWDEBUG("Pool contains no free addresses");
		RETURN_UNLANG_NOTFOUND;

	default:
		RPERROR("Allocating IP address failed");
		RETURN_UNLANG_FAIL;
	}
}

static int _redis_ippool_alloc_ctx_free(redis_ippool_alloc_rctx_t *rctx)
{
	if (!rctx->cmd_str) return 0;
	redisFreeCommand(rctx->cmd_str);
	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_alloc(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	redis_ippool_alloc_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_alloc_call_env_t);
	uint32_t			lease_time;
	struct				timeval now;
	uint32_t			assoc_time;
	redis_ippool_alloc_rctx_t	*rctx;
	int				cmd_len;

	fr_assert(env->pool_name.vb_length > 0);
	fr_assert(env->owner.vb_length > 0);

	CHECK_POOL_NAME

	/*
	 *	If offer_time is defined, it will be FR_TYPE_UINT32.
	 *	Fall back to lease_time otherwise.
	 */
	lease_time = (env->offer_time.type == FR_TYPE_UINT32) ?
			env->offer_time.vb_uint32 : env->lease_time.vb_uint32;
	ippool_action_print(request, POOL_ACTION_ALLOCATE, L_DBG_LVL_2, &env->pool_name, NULL,
			    &env->owner, &env->gateway_id, lease_time);

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), redis_ippool_alloc_rctx_t));
	rctx->env = env;
	rctx->ret = IPPOOL_RCODE_FAIL;
	talloc_set_destructor(rctx, _redis_ippool_alloc_ctx_free);

	now = fr_time_to_timeval(fr_time());

	assoc_time = (env->association_time.type == FR_TYPE_UINT32) &&
		     (env->association_time.vb_uint32 > lease_time) ? env->association_time.vb_uint32 : lease_time;

	if ((env->requested_address.datum.ip.af == AF_INET) && inst->ipv4_integer) {
		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %u %b %u %b %u",
					     lua_alloc_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, lease_time,
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length,
					     assoc_time,
					     (uint8_t const *)env->gateway_id.vb_strvalue, env->gateway_id.vb_length,
					     htonl(env->requested_address.datum.ip.addr.v4.s_addr));
		if (cmd_len < 0) {
		format_error:
			RERROR("Failed formatting redis command");
			return UNLANG_ACTION_FAIL;
		}
	} else {
		char	ip_buff[FR_IPADDR_PREFIX_STRLEN];
		if (env->requested_address.type == FR_TYPE_COMBO_IP_ADDR) {
			IPPOOL_SPRINT_IP(ip_buff, &env->requested_address.datum.ip, env->requested_address.datum.ip.prefix);
		} else {
			ip_buff[0] = '\0';
		}

		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %u %b %u %b %s",
	 				     lua_alloc_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, lease_time,
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length,
					     assoc_time,
					     (uint8_t const *)env->gateway_id.vb_strvalue, env->gateway_id.vb_length,
					     ip_buff);
		if (cmd_len < 0) goto format_error;
	}

	return ippool_script_enqueue(rctx, &rctx->cmds, &rctx->cmd, request, thread,
				     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				     rctx->cmd_str, cmd_len, redis_ippool_allocate_results, mod_alloc_resume,
				     mod_alloc_cancel, rctx, &rctx->wait_rctx);
}

static void mod_update_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	redis_ippool_update_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_update_rctx_t);

	RDEBUG2("Forcibly cancelling Redis update command");

	fr_redis_async_cmd_cancel(rctx->cmd);
}

static unlang_action_t CC_HINT(nonnull) mod_update_resume(unlang_result_t *p_result, module_ctx_t const *mctx,
							 request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	redis_ippool_update_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_update_rctx_t);
	redis_ippool_update_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_update_call_env_t);

	if (redis_ippool_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_update_resume,
				     mod_alloc_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	switch (rctx->ret) {
	case IPPOOL_RCODE_SUCCESS:
		if (rctx->wait_rctx.fail) RETURN_UNLANG_FAIL;

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

			if (unlikely(fr_value_box_copy(NULL, &ip_rhs.data.literal, &env->requested_address) < 0)) {
				RPEDEBUG("Failed copying IP address to reply attribute");
				RETURN_UNLANG_FAIL;
			}

			if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) RETURN_UNLANG_FAIL;
		}
		RETURN_UNLANG_UPDATED;

	/*
	 *	It's useful to be able to identify the 'not found' case
	 *	as we can relay to a server where the IP address might
	 *	be found.  This extremely useful for migrations.
	 */
	case IPPOOL_RCODE_NOT_FOUND:
		REDEBUG("Requested IP address \"%pV\" is not a member of the specified pool",
			&env->requested_address);
		RETURN_UNLANG_NOTFOUND;

	case IPPOOL_RCODE_EXPIRED:
		REDEBUG("Requested IP address' \"%pV\" lease already expired at time of renewal",
			&env->requested_address);
		RETURN_UNLANG_INVALID;

	case IPPOOL_RCODE_DEVICE_MISMATCH:
		REDEBUG("Requested IP address' \"%pV\" lease allocated to another device",
			&env->requested_address);
		RETURN_UNLANG_INVALID;

	default:
		RPERROR("Failed updating IP address");
		RETURN_UNLANG_FAIL;
	}
}

static int _redis_ippool_update_rctx_free(redis_ippool_update_rctx_t *rctx)
{
	if (!rctx->cmd_str) return 0;
	redisFreeCommand(rctx->cmd_str);
	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_update(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	redis_ippool_update_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_update_call_env_t);
    	struct				timeval now;
	uint32_t			assoc_time, expires;
	fr_ipaddr_t			*ip = &env->requested_address.datum.ip;
	int				cmd_len;
	redis_ippool_update_rctx_t	*rctx;

	CHECK_POOL_NAME

	ippool_action_print(request, POOL_ACTION_UPDATE, L_DBG_LVL_2, &env->pool_name,
			    &env->requested_address, &env->owner, &env->gateway_id, env->lease_time.vb_uint32);

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), redis_ippool_update_rctx_t));
	rctx->env = env;
	rctx->ret = IPPOOL_RCODE_FAIL;
	talloc_set_destructor(rctx, _redis_ippool_update_rctx_free);

	now = fr_time_to_timeval(fr_time());
	expires = env->lease_time.vb_uint32;
	assoc_time = (env->association_time.type == FR_TYPE_UINT32) &&
		     (env->association_time.vb_uint32 > expires) ? env->association_time.vb_uint32 : expires;

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %u %u %b %u %b", lua_update_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, expires, htonl(ip->addr.v4.s_addr),
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length, assoc_time,
					     (uint8_t const *)env->gateway_id.vb_strvalue, env->gateway_id.vb_length);
		if (cmd_len < 0) {
		format_error:
			RERROR("Failed formatting redis command");
			return UNLANG_ACTION_FAIL;
		}
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %u %s %b %u %b", lua_update_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, expires, ip_buff,
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length, assoc_time,
					     (uint8_t const *)env->gateway_id.vb_strvalue, env->gateway_id.vb_length);
		if (cmd_len < 0) goto format_error;
	}

	return ippool_script_enqueue(rctx, &rctx->cmds, &rctx->cmd, request, thread,
				     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				     rctx->cmd_str, cmd_len, redis_ippool_update_results, mod_update_resume,
				     mod_update_cancel, rctx, &rctx->wait_rctx);
}

static void mod_release_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	redis_ippool_release_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_release_rctx_t);

	RDEBUG2("Forcibly cancelling Redis release command");

	fr_redis_async_cmd_cancel(rctx->cmd);
}

static unlang_action_t CC_HINT(nonnull) mod_release_resume(unlang_result_t *p_result, module_ctx_t const *mctx,
							   request_t *request)
{
	redis_ippool_release_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, redis_ippool_release_rctx_t);
	redis_ippool_release_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_release_call_env_t);

	if (redis_ippool_rcode_check(request, rctx->cmds, rctx->cmd, mctx, mod_release_resume,
				     mod_release_cancel) == UNLANG_ACTION_YIELD) return UNLANG_ACTION_YIELD;

	switch (rctx->ret) {
	case IPPOOL_RCODE_SUCCESS:
		if (rctx->wait_rctx.fail) RETURN_UNLANG_FAIL;

		RDEBUG2("IP address \"%pV\" released", &env->requested_address);
		RETURN_UNLANG_UPDATED;

	/*
	 *	It's useful to be able to identify the 'not found' case
	 *	as we can relay to a server where the IP address might
	 *	be found.  This extremely useful for migrations.
	 */
	case IPPOOL_RCODE_NOT_FOUND:
		REDEBUG("Requested IP address \"%pV\" is not a member of the specified pool",
			&env->requested_address);
		RETURN_UNLANG_NOTFOUND;

	case IPPOOL_RCODE_DEVICE_MISMATCH:
		REDEBUG("Requested IP address' \"%pV\" lease allocated to another device",
			&env->requested_address);
		RETURN_UNLANG_INVALID;

	default:
		RPERROR("Failed releasing IP address");
		RETURN_UNLANG_FAIL;
	}
}

static int _redis_ippool_release_rctx_free(redis_ippool_release_rctx_t *rctx)
{
	if (!rctx->cmd_str) return 0;
	redisFreeCommand(rctx->cmd_str);
	return 0;
}

static unlang_action_t CC_HINT(nonnull) mod_release(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	redis_ippool_release_call_env_t	*env = talloc_get_type_abort(mctx->env_data, redis_ippool_release_call_env_t);
	struct				timeval now;
	fr_ipaddr_t			*ip = &env->requested_address.datum.ip;
	redis_ippool_release_rctx_t	*rctx;
	int				cmd_len;

	CHECK_POOL_NAME

	ippool_action_print(request, POOL_ACTION_RELEASE, L_DBG_LVL_2, &env->pool_name,
			    &env->requested_address, &env->owner, &env->gateway_id, 0);

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), redis_ippool_release_rctx_t));
	talloc_set_destructor(rctx, _redis_ippool_release_rctx_free);

	now = fr_time_to_timeval(fr_time());

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %u %b %u", lua_release_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, htonl(ip->addr.v4.s_addr),
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length,
					     env->association_time.vb_uint32);
		if (cmd_len < 0) {
		format_error:
			RERROR("Failed formatting redis command");
			return UNLANG_ACTION_FAIL;
		}
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		cmd_len = redisFormatCommand(&rctx->cmd_str, "EVALSHA %s 1 %b %u %s %b %u", lua_release_digest,
					     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
					     (unsigned int)now.tv_sec, ip_buff,
					     (uint8_t const *)env->owner.vb_strvalue, env->owner.vb_length,
					     env->association_time.vb_uint32);
		if (cmd_len < 0) goto format_error;
	}

	return ippool_script_enqueue(rctx, &rctx->cmds, &rctx->cmd, request, thread,
				     (uint8_t const *)env->pool_name.vb_strvalue, env->pool_name.vb_length,
				     rctx->cmd_str, cmd_len, redis_ippool_release_results, mod_release_resume,
				     mod_release_cancel, rctx, &rctx->wait_rctx);
}

static unlang_action_t CC_HINT(nonnull) mod_bulk_release(unlang_result_t *p_result, UNUSED module_ctx_t const *mctx,
							 request_t *request)
{
	RDEBUG2("Bulk release not yet implemented");
	RETURN_UNLANG_NOOP;
}

static int _redis_ippool_tool_rctx_free(redis_ippool_tool_rctx_t *rctx)
{
	char	*cmd_str;
	size_t	i = 0;

	/*
	 *	Free any Redis commands
	 */
	while (i < talloc_array_length(rctx->cmd_str)) {
		cmd_str = rctx->cmd_str[i];
		if (!cmd_str) break;
		redisFreeCommand(cmd_str);
		i++;
	}

	return 0;
}

/** Increment an IP address by a given number of addresses
 */
static void ipaddr_inc(fr_ipaddr_t *addr, size_t inc)
{
	switch (addr->af) {
	case AF_INET:
		addr->addr.v4.s_addr = htonl(ntohl(addr->addr.v4.s_addr) + inc);
		break;
	case AF_INET6:
	{
		uint128_t ip_curr;

		/* Don't be tempted to cast */
		memcpy(&ip_curr, addr->addr.v6.s6_addr, sizeof(ip_curr));
			ip_curr = ntohlll(ip_curr);

			/* Increment the prefix */
			ip_curr = uint128_add(ip_curr, inc);
			ip_curr = htonlll(ip_curr);
			memcpy(&addr->addr.v6.s6_addr, &ip_curr, sizeof(addr->addr.v6.s6_addr));
			break;
	}
	}
}

/** Parse argments provided to IP pool manipulation xlats which work on subnets
 *
 * @param[in] request		The current request, for debugging.
 * @param[out] start		Where to write the start address.
 * @param[out] end		Where to write the end address.
 * @param[out] prefix_out	Where to write the parsed value of prefix.
 * @param[out] step		Where to write the step size for multiple addresses.
 * @param[out] num_addr		Where to write the number of addresses
 * @param[in] subnet		to parse.
 * @param[in] prefix_in		optinal prefix argument.
 */
static int redis_ippool_subnet_arg_parse(request_t *request, fr_value_box_t *start, fr_value_box_t *end,
					 uint8_t *prefix_out, size_t *step, size_t *num_addr,
					 fr_value_box_t *subnet, fr_value_box_t *prefix_in)
{
	uint8_t	prefix, subnetlen = subnet->vb_ip.prefix;

	switch (subnet->vb_ip.af) {
	case AF_INET:
		prefix = (prefix_in && prefix_in->type == FR_TYPE_UINT8) ? prefix_in->vb_uint8 : 32;
		if ((prefix < 1) || (prefix > 32)) {
			RERROR("Prefix %d out of range (1-32)", prefix);
			return -1;
		}
		*step = 1 << (32 - prefix);
		break;

	case AF_INET6:
		prefix = (prefix_in && prefix_in->type == FR_TYPE_UINT8) ? prefix_in->vb_uint8 : 128;
		if ((prefix < 1) || (prefix > 128)) {
			RERROR("Prefix %d out of range (1-128)", prefix);
			return -1;
		}
		*step = 1 << (128 - prefix);
		break;

	default:
		fr_assert(0);
		return -1;
	}

	*prefix_out = prefix;

	if (prefix < subnetlen) {
		ERROR("Prefix len must be greater than or equal to subnet length (%u)", subnetlen);
		return -1;
	}

	switch (subnet->vb_ip.af) {
	case AF_INET:
	{
		uint32_t ip;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 32))) return -1;

		/* Set the input to /32 so cast works */
		subnet->vb_ip.prefix = 32;
		if (fr_value_box_cast(start, start, FR_TYPE_IPV4_ADDR, NULL, subnet) < 0) return -1;
		if (subnetlen == 32) {
			if (fr_value_box_copy(end, end, start) < 0) return -1;
			*num_addr = 1;
			return 0;
		}

		ip = ntohl(start->vb_ip.addr.v4.s_addr);
		ip |= uint32_gen_mask(prefix - subnetlen) << (32 - prefix);

		/*
		 *	Exclude the broadcast address if we are working with /32 addresses.
		 */
		if (prefix == 32) ip--;

		fr_value_box_init(end, FR_TYPE_IPV4_ADDR, NULL, start->tainted);
		end->vb_ipv4addr = htonl(ip);
	}
		break;

	case AF_INET6:
	{
		uint128_t ip, p_mask;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 128))) return -1;

		/* Set the input to /128 so cast works */
		subnet->vb_ip.prefix = 128;
		if (fr_value_box_cast(start, start, FR_TYPE_IPV6_ADDR, NULL, subnet) < 0) return -1;
		if (subnetlen == 128) {
			if (fr_value_box_copy(end, end, start) < 0) return -1;
			*num_addr = 1;
			return 0;
		}

		memcpy(&ip, start->vb_ipv6addr, sizeof(ip));
		ip = ntohlll(ip);
		p_mask = uint128_lshift(uint128_gen_mask(prefix - subnetlen), (128 - prefix));
		ip = htonlll(uint128_bor(p_mask, ip));

		fr_value_box_init(end, FR_TYPE_IPV6_ADDR, NULL, start->tainted);
		memcpy(&end->vb_ipv6addr, &ip, sizeof(end->vb_ipv6addr));
	}
		break;

	default:
		fr_assert(0);
	}

	if (unlikely(!fr_cond_assert((prefix - subnetlen) < 128))) return -1;
	*num_addr = (size_t)1 << (prefix - subnetlen);
	return 0;
}

/** Parse argments provided to IP pool manipulation xlats which work on start and end addresses
 *
 * @param[in] request		The current request, for debugging.
 * @param[out] prefix_out	Where to write the parsed value of prefix.
 * @param[out] step		Where to write the step size for multiple addresses.
 * @param[out] num_addr		Where to write the number of addresses
 * @param[in] start		The provided start address.
 * @param[in] end		The provided end address.
 * @param[in] prefix_in		optinal prefix argument.
 */
static int redis_ippool_addresses_arg_parse(request_t *request, uint8_t *prefix_out, size_t *step, size_t *num_addr,
					    fr_value_box_t *start, fr_value_box_t *end, fr_value_box_t *prefix_in)
{
	uint8_t	prefix;

	if (start->vb_ip.af != end->vb_ip.af) {
		RERROR("Mis-matched start and end IP address types");
		return XLAT_ACTION_FAIL;
	}

	switch (start->vb_ip.af) {
	case AF_INET:
	{
		uint32_t	start_ip, end_ip;
		start_ip = ntohl(start->vb_ipv4addr);
		end_ip = ntohl(end->vb_ipv4addr);

		prefix = (prefix_in && prefix_in->type == FR_TYPE_UINT8) ? prefix_in->vb_uint8 : 32;
		if ((prefix < 1) || (prefix > 32)) {
			RERROR("Prefix %d out of range (1-32)", prefix);
			return -1;
		}
		*step = 1 << (32 - prefix);
		*num_addr = (end_ip - start_ip + 1) / *step;
	}
		break;

	case AF_INET6:
	{
		uint128_t	start_ip, end_ip;

		memcpy(&start_ip, start->vb_ipv6addr, sizeof(start_ip));
		memcpy(&end_ip, end->vb_ipv6addr, sizeof(end_ip));

		start_ip = ntohlll(start_ip);
		end_ip = ntohlll(end_ip);

		prefix = (prefix_in && prefix_in->type == FR_TYPE_UINT8) ? prefix_in->vb_uint8 : 128;
		if ((prefix < 1) || (prefix > 128)) {
			RERROR("Prefix %d out of range (1-127)", prefix);
			return -1;
		}
		*step = 1 << (128 - prefix);
		*num_addr = uint128_sub(end_ip, start_ip) + 1 / *step;
	}

		break;

	default:
		fr_assert(0);
		return -1;
	}

	*prefix_out = prefix;
	return 0;
}

/** Common cancellation function for xlats using redi_ippool_tool_rctx_t
 *
 */
static void redis_ippool_common_cancel(xlat_ctx_t const *xctx, request_t *request, UNUSED fr_signal_t action)
{
	redis_ippool_tool_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, redis_ippool_tool_rctx_t);

	RDEBUG2("Forcibly cancelling pending IP pool command");
	if (rctx->cmd) fr_redis_async_cmd_cancel(rctx->cmd);
}

/** Common resume function for pool manipulation xlats
 *
 * Where the number of changes is to be returned
 */
static xlat_action_t redis_ippool_common_resume(TALLOC_CTX *ctx, fr_dcursor_t *out, xlat_ctx_t const *xctx,
						UNUSED request_t *request, UNUSED fr_value_box_list_t *in)
{
	redis_ippool_tool_rctx_t	*rctx = talloc_get_type_abort(xctx->rctx, redis_ippool_tool_rctx_t);
	fr_value_box_t			*vb;

	switch (fr_redis_command_set_rcode(rctx->cmds)) {
	case REDIS_ASYNC_RCODE_SUCCESS:
		break;

	case REDIS_ASYNC_RCODE_MOVE:
	{
		rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(xctx->mctx->mi->data, rlm_redis_ippool_t);
		rlm_redis_ippool_thread_t	*thread = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_ippool_thread_t);

		if (inst->conf.use_cluster_map) fr_redis_cluster_thread_map_get(thread->rtcluster, thread->cw,
									        inst->coord_pair_reg, false);
	}
		FALL_THROUGH;

	case REDIS_ASYNC_RCODE_ASK:
		if (fr_redis_async_cmd_redirect(rctx->cmd) != REDIS_ASYNC_RCODE_SUCCESS) return XLAT_ACTION_FAIL;
		return unlang_xlat_yield(request, redis_ippool_common_resume, redis_ippool_common_cancel, ~FR_SIGNAL_CANCEL, rctx);

	case REDIS_ASYNC_RCODE_ERROR:
		PERROR("Server returned error");
		return XLAT_ACTION_FAIL;

	default:
		return XLAT_ACTION_FAIL;
	}

	vb = fr_value_box_alloc(ctx, FR_TYPE_UINT32, NULL);
	vb->vb_uint32 = rctx->changes;
	fr_dcursor_append(out, vb);

	return XLAT_ACTION_DONE;
}

/** Callback to be used when Redis commands are expected to return a single integer
 *
 * With the value indicating the number of changes made.
 */
static void redis_xlat_common_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	redis_ippool_tool_rctx_t	*xlat_rctx = talloc_get_type_abort(rctx, redis_ippool_tool_rctx_t);

	if (reply->type != REDIS_REPLY_INTEGER) {
		RERROR("Unexpected reply type");
		return;
	}

	xlat_rctx->changes += reply->integer;
	return;
}

/** Callback to be used when Redis commands are expected to return an array
 *
 * Where the first element is expected to be an integer indicating the number
 * of changes made.
 * Typically this is when a MULTI ... EXEC is used and this parses the
 * reply from EXEC.
 */
static void redis_xlat_array_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	redis_ippool_tool_rctx_t	*xlat_rctx = talloc_get_type_abort(rctx, redis_ippool_tool_rctx_t);

	if (reply->type != REDIS_REPLY_ARRAY) {
	error:
		RERROR("Unexpected reply type");
		return;
	}

	if ((reply->elements > 0) && (reply->element[0]->type == REDIS_REPLY_INTEGER)) {
		xlat_rctx->changes += reply->element[0]->integer;
	} else {
		goto error;
	}
}

/** Common code for adding addresses to a pool.
 */
static xlat_action_t redis_ippool_add_common(request_t *request, rlm_redis_ippool_t *inst, rlm_redis_ippool_thread_t *t,
					     fr_value_box_t *pool, fr_value_box_t *start, fr_value_box_t *end,
					     fr_value_box_t *range, uint8_t prefix, size_t num_addr, size_t step)
{
	redis_ippool_tool_rctx_t	*rctx;
	uint8_t				key[IPPOOL_MAX_POOL_KEY_SIZE];
	int				cmd_len;
	uint8_t				*p = key;
	ippool_rcode_t			ret = IPPOOL_RCODE_SUCCESS;
	fr_redis_async_rcode_t		rcode;
	bool				use_range = false;
	size_t				cmd_no = 0;
	fr_value_box_t			curr_addr;
	char				ipaddr[INET6_ADDRSTRLEN + 1];

	if (fr_value_box_copy(request, &curr_addr, start) < 0) return XLAT_ACTION_FAIL;

	if (prefix != (curr_addr.vb_ip.af == AF_INET ? 32 : 128)) {
		if (fr_value_box_cast_in_place(request, &curr_addr, curr_addr.vb_ip.af == AF_INET ?
					       FR_TYPE_IPV4_PREFIX : FR_TYPE_IPV6_PREFIX, NULL) < 0) return XLAT_ACTION_FAIL;
		curr_addr.vb_ip.prefix = prefix;
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), redis_ippool_tool_rctx_t));
	talloc_set_destructor(rctx, _redis_ippool_tool_rctx_free);

	IPPOOL_BUILD_KEY(key, p, pool->vb_strvalue, pool->vb_length);
	if (ret == IPPOOL_RCODE_FAIL) return XLAT_ACTION_FAIL;

	use_range = range && range->type == FR_TYPE_STRING;

	MEM(rctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	MEM(rctx->cmd_str = talloc_zero_array(rctx, char *, num_addr * (use_range ? 2 : 1)));

	do {
		DEBUG3("Adding %pV to pool \"%pV\"", &curr_addr, pool);

		if (fr_value_box_print(&FR_SBUFF_OUT(ipaddr, sizeof(ipaddr)), &curr_addr, NULL) < 0) return XLAT_ACTION_FAIL;
		cmd_len = redisFormatCommand(&rctx->cmd_str[cmd_no], "ZADD %b NX %u %s", key, p - key, 0,
					     ipaddr);
		if (cmd_len < 0) return XLAT_ACTION_FAIL;

		if (use_range) {
			uint8_t	ip_key[IPPOOL_MAX_IP_KEY_SIZE];
			uint8_t	*ip_key_p = ip_key;

			fr_redis_command_literal_add(rctx->cmds, "MULTI", NULL, NULL);
			fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str[cmd_no++], cmd_len, NULL, NULL);

			IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, pool->vb_strvalue, pool->vb_length, ipaddr);
			if (ret == IPPOOL_RCODE_FAIL) return XLAT_ACTION_FAIL;
			cmd_len = redisFormatCommand(&rctx->cmd_str[cmd_no], "HSET %b range %b", ip_key, ip_key_p - ip_key,
						     range->vb_strvalue, range->vb_length);
			if (cmd_len < 0) return XLAT_ACTION_FAIL;

			fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str[cmd_no++], cmd_len, NULL, NULL);
			fr_redis_command_literal_add(rctx->cmds, "EXEC", redis_xlat_array_results, rctx);
		} else {
			fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str[cmd_no++], cmd_len,
							  redis_xlat_common_results, rctx);
		}

		ipaddr_inc(&curr_addr.vb_ip, step);
	} while (fr_ipaddr_cmp(&curr_addr.vb_ip, &end->vb_ip) != 1);

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &rcode, t->rtcluster, (uint8_t const *)pool->vb_strvalue,
					     pool->vb_length, rctx->cmds, false, NULL);

	REDIS_ASYNC_START_RCODE_PROCESS(rcode, t->rtcluster, t->cw, inst->coord_pair_reg,
					"Failed to launch Redis command", XLAT_ACTION_FAIL);

	return unlang_xlat_yield(request, redis_ippool_common_resume, redis_ippool_common_cancel,
				 ~FR_SIGNAL_CANCEL, rctx);
}

static xlat_arg_parser_t const redis_ippool_subnet_add_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },		// Pool name
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_PREFIX },	// IP subnet
	{ .single = true, .type = FR_TYPE_UINT8 },				// Prefix length
	{ .single = true, .type = FR_TYPE_STRING },				// Range
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t redis_ippool_subnet_add_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						  xlat_ctx_t const *xctx, request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_ippool_thread_t);
	fr_value_box_t			*pool, *subnet, start, end, *prefix_in, *range;
	uint8_t				prefix;
	size_t				num_addr, step;

	XLAT_ARGS(in, &pool, &subnet, &prefix_in, &range);

	if (redis_ippool_subnet_arg_parse(request, &start, &end, &prefix, &step, &num_addr,
					  subnet, prefix_in) < 0) return XLAT_ACTION_FAIL;

	return redis_ippool_add_common(request, inst, t, pool, &start, &end, range, prefix, num_addr, step);
}

static xlat_arg_parser_t const redis_ippool_addresses_add_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },		// Pool name
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_ADDR },	// Start address
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_ADDR },	// End address
	{ .single = true, .type = FR_TYPE_UINT8 },				// Prefix length
	{ .single = true, .type = FR_TYPE_STRING },				// Range
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t redis_ippool_addresses_add_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						     xlat_ctx_t const *xctx, request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_ippool_thread_t);
	fr_value_box_t			*pool, *start, *end, *prefix_in, *range;
	uint8_t				prefix;
	size_t				num_addr, step;

	XLAT_ARGS(in, &pool, &start, &end, &prefix_in, &range);

	if (redis_ippool_addresses_arg_parse(request, &prefix, &step, &num_addr,
					     start, end, prefix_in) < 0) return XLAT_ACTION_FAIL;

	return redis_ippool_add_common(request, inst, t, pool, start, end, range, prefix, num_addr, step);
}

/** Common code for removing addresses from a pool.
 */
static xlat_action_t redis_ippool_remove_common(request_t *request, rlm_redis_ippool_t *inst, rlm_redis_ippool_thread_t *t,
						fr_value_box_t *pool, fr_value_box_t *start, fr_value_box_t *end,
						uint8_t prefix, size_t num_addr, size_t step)
{
	redis_ippool_tool_rctx_t	*rctx;
	int				cmd_len;
	fr_redis_async_rcode_t		rcode;
	size_t				cmd_no = 0;
	fr_value_box_t			curr_addr;
	char				ipaddr[INET6_ADDRSTRLEN + 1];

	if (fr_value_box_copy(request, &curr_addr, start) < 0) return XLAT_ACTION_FAIL;

	if (prefix != (curr_addr.vb_ip.af == AF_INET ? 32 : 128)) {
		if (fr_value_box_cast_in_place(request, &curr_addr, curr_addr.vb_ip.af == AF_INET ?
					       FR_TYPE_IPV4_PREFIX : FR_TYPE_IPV6_PREFIX, NULL) < 0) return XLAT_ACTION_FAIL;
		curr_addr.vb_ip.prefix = prefix;
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), redis_ippool_tool_rctx_t));
	talloc_set_destructor(rctx, _redis_ippool_tool_rctx_free);

	MEM(rctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));
	MEM(rctx->cmd_str = talloc_zero_array(rctx, char *, num_addr));

	do {
		DEBUG3("Removing %pV from pool \"%pV\"", &curr_addr, pool);

		if (fr_value_box_print(&FR_SBUFF_OUT(ipaddr, sizeof(ipaddr)), &curr_addr, NULL) < 0) return XLAT_ACTION_FAIL;
		cmd_len = redisFormatCommand(&rctx->cmd_str[cmd_no], "EVAL %s 1 %b %s", lua_remove_cmd,
					     pool->vb_strvalue, pool->vb_length, ipaddr);
		if (cmd_len < 0) return XLAT_ACTION_FAIL;

		fr_redis_command_preformatted_add(rctx->cmds, rctx->cmd_str[cmd_no++], cmd_len,
						  redis_xlat_common_results, rctx);

		ipaddr_inc(&curr_addr.vb_ip, step);
	} while (fr_ipaddr_cmp(&curr_addr.vb_ip, &end->vb_ip) != 1);

	rctx->cmd = fr_redis_async_cmd_start(rctx, request, &rcode, t->rtcluster, (uint8_t const *)pool->vb_strvalue,
					     pool->vb_length, rctx->cmds, false, NULL);

	REDIS_ASYNC_START_RCODE_PROCESS(rcode, t->rtcluster, t->cw, inst->coord_pair_reg,
					"Failed to launch Redis command", XLAT_ACTION_FAIL);

	return unlang_xlat_yield(request, redis_ippool_common_resume, redis_ippool_common_cancel,
				 ~FR_SIGNAL_CANCEL, rctx);
}

static xlat_arg_parser_t const redis_ippool_subnet_remove_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },		// Pool name
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_PREFIX },	// IP subnet
	{ .single = true, .type = FR_TYPE_UINT8 },				// Prefix length
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t redis_ippool_subnet_remove_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
						     xlat_ctx_t const *xctx, request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_ippool_thread_t);
	fr_value_box_t			*pool, *subnet, start, end, *prefix_in;
	uint8_t				prefix;
	size_t				num_addr, step;

	XLAT_ARGS(in, &pool, &subnet, &prefix_in);

	if (redis_ippool_subnet_arg_parse(request, &start, &end, &prefix, &step, &num_addr,
					  subnet, prefix_in) < 0) return XLAT_ACTION_FAIL;

	return redis_ippool_remove_common(request, inst, t, pool, &start, &end, prefix, num_addr, step);
}

static xlat_arg_parser_t const redis_ippool_addresses_remove_args[] = {
	{ .required = true, .concat = true, .type = FR_TYPE_STRING },		// Pool name
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_ADDR },	// Start address
	{ .required = true, .single = true, .type = FR_TYPE_COMBO_IP_ADDR },	// End address
	{ .single = true, .type = FR_TYPE_UINT8 },				// Prefix length
	XLAT_ARG_PARSER_TERMINATOR
};

static xlat_action_t redis_ippool_addresses_remove_xlat(UNUSED TALLOC_CTX *ctx, UNUSED fr_dcursor_t *out,
							xlat_ctx_t const *xctx, request_t *request, fr_value_box_list_t *in)
{
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(xctx->mctx->mi->data, rlm_redis_ippool_t);
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(xctx->mctx->thread, rlm_redis_ippool_thread_t);
	fr_value_box_t			*pool, *start, *end, *prefix_in;
	uint8_t				prefix;
	size_t				num_addr, step;

	XLAT_ARGS(in, &pool, &start, &end, &prefix_in);

	if (redis_ippool_addresses_arg_parse(request, &prefix, &step, &num_addr,
					     start, end, prefix_in) < 0) return XLAT_ACTION_FAIL;

	return redis_ippool_remove_common(request, inst, t, pool, start, end, prefix, num_addr, step);
}

static void lua_script_load_results(UNUSED request_t *request, UNUSED fr_redis_command_t *cmd,
				    redisReply *reply, UNUSED void *rctx)
{
	if (reply->type != REDIS_REPLY_STRING) {
		ERROR("Unexpected reply type after loading function");
		return;
	}
	DEBUG2("Loaded lua function with hash \"%s\" onto node", reply->str);
}

#define REDIS_IPPOOL_SCRIPT_LOAD(_script) do { \
	char const	**argv; \
	size_t		*argv_len; \
	MEM(argv = talloc_array(cmds, char const *, 3)); \
	MEM(argv_len = talloc_array(cmds, size_t, 3)); \
	argv[0] = "SCRIPT"; \
	argv[1] = "LOAD"; \
	argv[2] = _script; \
	argv_len[0] = (sizeof("SCRIPT") - 1); \
	argv_len[1] = (sizeof("LOAD") - 1); \
	argv_len[2] = (sizeof(_script) - 1); \
	fr_redis_command_argv_add(cmds, 3, argv, argv_len, lua_script_load_results, NULL); \
} while (0)

static void lua_script_load(fr_redis_trunk_t *rtrunk, UNUSED void *uctx)
{
	fr_redis_command_set_t		*cmds;

	MEM(cmds = fr_redis_command_set_alloc(rtrunk, NULL, NULL, NULL, NULL, true));

	REDIS_IPPOOL_SCRIPT_LOAD(lua_alloc_cmd);
	REDIS_IPPOOL_SCRIPT_LOAD(lua_update_cmd);
	REDIS_IPPOOL_SCRIPT_LOAD(lua_release_cmd);

	if (redis_command_set_enqueue(rtrunk, cmds) != FR_REDIS_PIPELINE_OK) {
		ERROR("Failed to enqueue lua function loading");
		talloc_free(cmds);
	}
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_ippool_t);

	t->rtcluster = fr_redis_cluster_thread_alloc(t, inst->tls_conf, mctx->el, &inst->conf, lua_script_load, t, true);

	if (!t->rtcluster) return -1;
	t->inst = inst;

	return 0;
}

static int mod_coord_attach(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_ippool_t);

	if (!inst->conf.use_cluster_map) return 0;

	t->cw = fr_coord_attach(t, mctx->el, inst->coord_reg);

	if (!t->cw) {
		ERROR("Failed to attach to coordinator");
		return -1;
	}

	if ((inst->conf.trunk_conf.start == 0) || (fr_schedule_worker_id() != 0)) return 0;

	return fr_redis_cluster_thread_map_bootstrap(t->rtcluster, t->cw, inst->coord_pair_reg);
}

/** Callback for worker receiving Fetch-OK packet from coordinator
 */
static void cluster_map_update(UNUSED fr_coord_worker_t *cw, UNUSED fr_coord_pair_reg_t *coord_pair_reg,
			       fr_pair_list_t const *list, UNUSED fr_time_t now,
			       module_ctx_t *mctx, UNUSED void *uctx)
{
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);
	fr_redis_cluster_thread_map_update(t->rtcluster, list);
	return;
}

static fr_coord_cb_reg_t coord_callbacks[] = {
	FR_COORD_PAIR_CALLBACK(REDIS_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_cb_reg_t worker_callbacks[] = {
	FR_COORD_WORKER_PAIR_CALLBACK(REDIS_COORD_PAIR_CALLBACK_ID),
	FR_COORD_CALLBACK_TERMINATOR
};

static fr_coord_worker_pair_cb_reg_t worker_pair_callbacks[] = {
	{ .packet_type = FR_REDIS_CLUSTER_MAP_UPDATE, .callback = cluster_map_update },
	FR_COORD_CALLBACK_TERMINATOR
};

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	static bool			done_hash = false;
	CONF_SECTION			*subcs = cf_section_find(mctx->mi->conf, "redis", NULL);
	rlm_redis_ippool_t		*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_ippool_t);

	fr_assert(subcs);

	inst->conf.log_prefix = mctx->mi->name;

	if (inst->conf.use_tls) {
		inst->tls_conf = cf_section_find(subcs, "tls", CF_IDENT_ANY);

		if (!inst->tls_conf) {
			cf_log_err(mctx->mi->conf, "Missing tls section");
			return -1;
		}
	}

	if (!inst->conf.use_cluster_map) goto cmds;

	if (inst->conf.database) {
		cf_log_err(mctx->mi->conf, "Cannot set Redis database number when cluster in use");
		return -1;
	}

	inst->coord_pair_reg = fr_coord_pair_register(&(fr_coord_pair_reg_ctx_t) {
			.name = mctx->mi->name,
			.worker_cb = worker_pair_callbacks,
			.cb_id = REDIS_COORD_PAIR_CALLBACK_ID,
			.root = fr_dict_root(dict_redis),
			.cs = subcs,
		}
	);
	if (!inst->coord_pair_reg) return -1;

	FR_COORD_PAIR_CB_CTX_SET(coord_callbacks, worker_callbacks, inst->coord_pair_reg);

	inst->coord_reg = fr_coord_register(&(fr_coord_reg_ctx_t) {
			.name = mctx->mi->name,
			.coord_cb = coord_callbacks,
			.worker_cb = worker_callbacks,
			.mi = mctx->mi
		});

	if (!inst->coord_reg) return -1;

cmds:
	if (inst->wait_num) {
		inst->wait_cmd_len = redisFormatCommand(&inst->wait_cmd, "WAIT %i %i", inst->wait_num,
							fr_time_delta_to_msec(inst->wait_timeout));
		if (inst->wait_cmd_len < 0) return -1;
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
		done_hash = true;
	}

	return 0;
}

static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_redis_ippool_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_redis_ippool_thread_t);

	if (!t->cw) return 0;

	fr_coord_detach(t->cw, true);
	t->cw = NULL;
	return 0;
}

static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_redis_ippool_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_redis_ippool_t);

	fr_coord_deregister(inst->coord_reg);
	talloc_free(inst->coord_pair_reg);

	if (inst->wait_cmd) redisFreeCommand(inst->wait_cmd);

	return 0;
}

static int mod_bootstrap(module_inst_ctx_t const *mctx)
{
	xlat_t				*xlat;

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "subnet.add", redis_ippool_subnet_add_xlat,
						      FR_TYPE_UINT32)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_ippool_subnet_add_args);

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "addresses.add", redis_ippool_addresses_add_xlat,
						      FR_TYPE_UINT32)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_ippool_addresses_add_args);

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "subnet.remove", redis_ippool_subnet_remove_xlat,
						      FR_TYPE_UINT32)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_ippool_subnet_remove_args);

	if (unlikely((xlat = module_rlm_xlat_register(mctx->mi->boot, mctx, "addresses.remove", redis_ippool_addresses_remove_xlat,
						      FR_TYPE_UINT32)) == NULL)) return -1;
	xlat_func_args_set(xlat, redis_ippool_addresses_remove_args);
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
		.name		= "redis_ippool",
		.inst_size	= sizeof(rlm_redis_ippool_t),
		.config		= module_config,
		.onload		= mod_load,
		.bootstrap	= mod_bootstrap,
		.instantiate	= mod_instantiate,
		.coord_attach	= mod_coord_attach,
		.detach		= mod_detach,
		MODULE_THREAD_INST(rlm_redis_ippool_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
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
