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
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#include "redis.h"
#include "cluster.h"
#include "redis_ippool.h"

/** rlm_redis module instance
 *
 */
typedef struct rlm_redis_ippool {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
						//!< Must be first field in this struct.

	char const		*name;		//!< Instance name.

	vp_tmpl_t		*pool_name;	//!< Name of the pool we're allocating IP addresses from.

	vp_tmpl_t		*offer_time;	//!< How long we should reserve a lease for during
						//!< the pre-allocation stage (typically responding
						//!< to DHCP discover).
	vp_tmpl_t		*lease_time;	//!< How long an IP address should be allocated for.

	uint32_t		wait_num;	//!< How many slaves we want to acknowledge allocations
						//!< or updates.

	struct timeval		wait_timeout;	//!< How long we wait for slaves to acknowledge writing.

	vp_tmpl_t		*device_id;	//!< Unique device identifier.  Could be mac-address
						//!< or a combination of User-Name and something
						//!< unique to the device.

	vp_tmpl_t		*gateway_id;	//!< Gateway identifier, usually
						//!< NAS-Identifier or the actual Option 82 gateway.
						//!< Used for bulk lease cleanups.

	vp_tmpl_t		*renew_attr;	//!< IPv4 attribute and destination.
	vp_tmpl_t		*reply_attr;	//!< IPv6 attribute and destination.

	bool			ipv4_integer;	//!< Whether IPv4 addresses should be cast to integers,
						//!< for renew operations.

	fr_redis_cluster_t	*cluster;	//!< Redis cluster.
} rlm_redis_ippool_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("pool_name", PW_TYPE_TMPL | PW_TYPE_REQUIRED, rlm_redis_ippool_t, pool_name) },

	{ FR_CONF_OFFSET("device", PW_TYPE_TMPL | PW_TYPE_REQUIRED, rlm_redis_ippool_t, device_id) },
	{ FR_CONF_OFFSET("gateway", PW_TYPE_TMPL, rlm_redis_ippool_t, gateway_id) },\

	{ FR_CONF_OFFSET("offer_time", PW_TYPE_TMPL, rlm_redis_ippool_t, offer_time) },
	{ FR_CONF_OFFSET("lease_time", PW_TYPE_TMPL | PW_TYPE_REQUIRED, rlm_redis_ippool_t, lease_time) },

	{ FR_CONF_OFFSET("wait_num", PW_TYPE_INTEGER, rlm_redis_ippool_t, wait_num) },
	{ FR_CONF_OFFSET("wait_timeout", PW_TYPE_TIMEVAL, rlm_redis_ippool_t, wait_timeout) },

	{ FR_CONF_OFFSET("renew_attr", PW_TYPE_TMPL, rlm_redis_ippool_t, renew_attr), .dflt = "&DHCP-Client-IP-Address", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("reply_attr", PW_TYPE_TMPL, rlm_redis_ippool_t, reply_attr), .dflt = "&reply:DHCP-Your-IP-Address", .quote = T_BARE_WORD },

	{ FR_CONF_OFFSET("ipv4_integer", PW_TYPE_BOOLEAN, rlm_redis_ippool_t, ipv4_integer) },

	/*
	 *	Split out to allow conversion to universal ippool module with
	 *	minimum of config changes.
	 */
	{ FR_CONF_POINTER("redis", PW_TYPE_SUBSECTION, NULL), .dflt = redis_config },
	CONF_PARSER_TERMINATOR
};

#define EOL "\n"

/** Lua script for allocating new leases
 *
 * - KEYS[1] The pool key.
 * - ARGV[1] IP key prefix.
 * - ARGV[2] Wall time (seconds since epoch).
 * - ARGV[3] Expiry time (seconds since epoch).
 * - ARGV[4] (optional) Client identifier.
 * - ARGV[5] (optional) Gateway identifier.
 */
static char lua_alloc_cmd[] =
	"local ip" EOL
	"local device_id" EOL
	"local gateway_id" EOL
	/*
	 *	Redis doesn't accept Nil Bulk strings, so we have to send
	 *	empty string instead *sigh*.
	 */
	"if ARGV[4] ~= '' then" EOL
	"  device_id = ARGV[4]" EOL
	"end" EOL
	"if ARGV[5] ~= '' then" EOL
	"  gateway_id = ARGV[5]" EOL
	"end" EOL

	/*
	 *	Get the IP address the expired the longest time ago.
	 */
	"ip = redis.call('ZREVRANGE', KEYS[1], -1, -1, 'WITHSCORES')" EOL
	"if not ip or not ip[1] then" EOL
	"  return nil" EOL
	"end" EOL
	"if ip[2] >= ARGV[2] then" EOL
	"  return nil" EOL
	"end" EOL
	"if device_id or gateway_id then" EOL
	"  redis.call('HMSET', '{' .. ARGV[1] .. '}:' .. ip[1], 'device_id', device_id, 'gateway_id', gateway_id)" EOL
	"end" EOL
	"redis.call('ZADD', KEYS[1], ARGV[3], ip[1])" EOL
	"return ip[1]" EOL;
static char lua_alloc_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for updating leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] IP hash key.
 * - ARGV[2] Wall time (seconds since epoch).
 * - ARGV[3] Expiry time (seconds since epoch).
 * - ARGV[4] IP address to update.
 * - ARGV[5] (optional) Client identifier.
 * - ARGV[6] (optional) Gateway identifier.
 *
 * Returns
 * - 0 lease updated.
 * - -1 lease not found in pool.
 * - -2 lease has already expired.
 * - -3 lease was allocated to a different client.
 */
static char lua_update_cmd[] =
	"local device_id" EOL
	"local gateway_id" EOL
	"local ret" EOL
	/*
	 *	Redis doesn't accept Nil Bulk strings, so we have to send
	 *	empty string instead *sigh*.
	 */
	"if ARGV[5] ~= '' then" EOL
	"  device_id = ARGV[5]" EOL
	"end" EOL
	"if ARGV[6] ~= '' then" EOL
	"  gateway_id = ARGV[6]" EOL
	"end" EOL
	/*
	 *	We either need to know that the IP was last allocated to the
	 *	same device, or that the lease on the IP has NOT expired.
	 */
	"if device_id then" EOL
	"  local found = redis.call('HGET', ARGV[1], 'device_id')" EOL
	"  if not found then" EOL
	"    return " STRINGIFY(_IPPOOL_RCODE_NOT_FOUND) EOL
	"  end" EOL
	"  if found ~= device_id then" EOL
	"    return " STRINGIFY(_IPPOOL_RCODE_DEVICE_MISMATCH) EOL
	"  end" EOL
	"else" EOL
	"  ret = redis.call('ZSCORE', KEYS[1], ARGV[4])" EOL
	"  if not ret then" EOL
	"    return " STRINGIFY(_IPPOOL_RCODE_NOT_FOUND) EOL
	"  end" EOL
	"  if ret < ARGV[2] then" EOL
	"    return " STRINGIFY(_IPPOOL_RCODE_EXPIRED) EOL
	"  end" EOL
	"end" EOL
	/*
	 *	Update the expiry time
	 */
	"redis.call('ZADD', KEYS[1], 'XX', ARGV[3], ARGV[4])" EOL
	/*
	 *	At this point we know the IP exists
	 */
	"if gateway_id then" EOL
	"  redis.call('HSET', ARGV[1], 'gateway_id', gateway_id)" EOL
	"end" EOL
	"return " STRINGIFY(_IPPOOL_RCODE_SUCCESS) EOL;
static char lua_update_digest[(SHA1_DIGEST_LENGTH * 2) + 1];

/** Lua script for releasing leases
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] IP hash key.
 * - ARGV[2] Wall time (seconds since epoch).
 * - ARGV[3] IP address to release.
 * - ARGV[4] (optional) Client identifier.
 *
 * Sets the expiry time to be NOW() - 1 to maximise time between
 * IP address allocations.
 * - 0 lease updated.
 * - -1 lease not found in pool.
 * - -3 lease was allocated to a different client.
 */
static char lua_release_cmd[] =
	"local device_id" EOL
	"local ret" EOL
	"if ARGV[4] ~= '' then" EOL
	"  device_id = ARGV[4]" EOL
	"end" EOL
	/*
	 *	Check that the device releasing was the one
	 *	the IP address is allocated to.
	 */
	"if device_id then" EOL
	"  local found = redis.call('HGET', ARGV[1], 'device_id')" EOL
	"  if found and found ~= device_id then" EOL
	"    return " STRINGIFY(_IPPOOL_RCODE_DEVICE_MISMATCH) EOL
	"  end" EOL
	"end" EOL
	"if not redis.call('ZSCORE', KEYS[1], ARGV[3]) then" EOL
	"  return " STRINGIFY(_IPPOOL_RCODE_NOT_FOUND) EOL
	"end" EOL
	"redis.call('ZADD', KEYS[1], 'XX', ARGV[2] - 1, ARGV[3])" EOL
	"return " STRINGIFY(_IPPOOL_RCODE_SUCCESS) EOL;
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
static inline int ippool_wait_check(REQUEST *request, uint32_t wait_num, redisReply *reply)
{
	if (!wait_num) return 0;

	if (reply->type != REDIS_REPLY_INTEGER) {
		REDEBUG("WAIT result is wrong type, expected integer got %s",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		return -1;
	}
	if (reply->integer < wait_num) {
		REDEBUG("Too few slaves acknowledged allocation, needed %i, got %lli",
			wait_num, reply->integer);
		return -1;
	}
	return 0;
}

/** Find the pool name we'll be allocating from
 *
 * @param out Where to write the pool name.
 * @param outlen Size of the output buffer.
 * @param inst This instance of the rlm_redis_ippool module.
 * @param request The current request.
 * @return
 *	- <= 0 on error.
 *	- > 0 on success (length of data written to out).
 */
static inline ssize_t ippool_pool_name(uint8_t out[], size_t outlen, rlm_redis_ippool_t *inst, REQUEST *request)
{
	ssize_t slen;
	uint8_t *out_p = out;

	slen = tmpl_expand(NULL, (char *)out_p, outlen - (out_p - out), request,
			   inst->pool_name, NULL, NULL);
	if (slen < 0) {
		REDEBUG("Failed determining pool name");
		return -1;
	}
	if (is_truncated((size_t)slen, outlen)) {
		REDEBUG("Pool name too long.  Expected %zu bytes, got %zu bytes", outlen, (size_t)slen);
		return -1;
	}
	out_p += slen;

	return out_p - out;
}

static void ippool_action_print(REQUEST *request, ippool_action_t action,
				log_lvl_t lvl,
				uint8_t const *key_prefix, size_t key_prefix_len,
				VALUE_PAIR const *ip_vp,
				uint8_t const *device_id, size_t device_id_len,
				uint8_t const *gateway_id, size_t gateway_id_len,
				uint32_t expires)
{
	char *key_prefix_str, *ip_str = NULL, *device_str = NULL, *gateway_str = NULL;

	key_prefix_str = fr_asprint(request, (char const *)key_prefix, key_prefix_len, '"');
	if (gateway_id) gateway_str = fr_asprint(request, (char const *)gateway_id, gateway_id_len, '"');
	if (device_id) device_str = fr_asprint(request, (char const *)device_id, device_id_len, '"');
	if (ip_vp) ip_str = fr_pair_value_asprint(request, ip_vp, '\0');

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
	talloc_free(ip_str);
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
 * @param[out] out Where to write Redis reply object resulting from the command.
 * @param[in] request The current request.
 * @param[in] cluster configuration.
 * @param[in] key to use to determine the cluster node.
 * @param[in] key_len length of the key.
 * @param[in] wait_num If > 0 wait until this many slaves have replicated the data
 *	from the last command.
 * @param[in] wait_timeout How long to wait for slaves.
 * @param[in] digest of script.
 * @param[in] script to upload.
 * @param[in] cmd EVALSHA command to execute.
 * @param[in] ... Arguments for the eval command.
 * @return status of the command.
 */
static fr_redis_rcode_t ippool_script(redisReply **out, REQUEST *request, fr_redis_cluster_t *cluster,
				      uint8_t const *key, size_t key_len,
				      uint32_t wait_num, uint32_t wait_timeout,
				      char const digest[], char const *script,
				      char const *cmd, ...)
{
	fr_redis_conn_t			*conn;
	redisReply			*replies[5];	/* Must be equal to the maximum number of pipelined commands */
	size_t				reply_cnt = 0, i;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		s_ret, status;
	int				pipelined = 0;

	va_list				ap;

	*out = NULL;

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
			redisAppendCommand(conn->handle, "WAIT %i %i", wait_num, wait_timeout);
			pipelined++;
		}
		reply_cnt = fr_redis_pipeline_result(&status, replies, sizeof(replies) / sizeof(*replies),
						     conn, pipelined);
		if (status != REDIS_RCODE_NO_SCRIPT) continue;

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

		reply_cnt = fr_redis_pipeline_result(&status, replies, sizeof(replies) / sizeof(*replies),
						     conn, pipelined);
		if (status == REDIS_RCODE_SUCCESS) {
			if (RDEBUG_ENABLED3) for (i = 0; i < reply_cnt; i++) {
				fr_redis_reply_print(L_DBG_LVL_3, replies[i], request, i);
			}

			if (replies[3]->type != REDIS_REPLY_ARRAY) {
				REDEBUG("Bad response to EXEC, expected array got %s",
					fr_int2str(redis_reply_types, replies[3]->type, "<UNKNOWN>"));
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
					fr_int2str(redis_reply_types, replies[3]->element[0]->type, "<UNKNOWN>"));
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
		fr_redis_reply_free(replies[1]);	/* Free the wait response */
		break;

	case 1:	/* EVALSHA */
		*out = replies[0];
		break;

	case 5: /* LOADSCRIPT + EVALSHA + WAIT */
		if (ippool_wait_check(request, wait_num, replies[4]) < 0) goto error;
		fr_redis_reply_free(replies[4]);	/* Free the wait response */
		/* FALL-THROUGH */

	case 4: /* LOADSCRIPT + EVALSHA */
		fr_redis_reply_free(replies[2]);	/* Free the queued cmd response*/
		fr_redis_reply_free(replies[1]);	/* Free the queued script load response */
		fr_redis_reply_free(replies[0]);	/* Free the queued multi response */
		*out = replies[3]->element[1];
		replies[3]->element[1] = NULL;		/* Prevent double free */
		fr_redis_reply_free(replies[3]);	/* This works because hiredis checks for NULL elements */
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
static ippool_rcode_t redis_ippool_allocate(rlm_redis_ippool_t *inst, REQUEST *request,
					       uint8_t const *key_prefix, size_t key_prefix_len,
					       uint8_t const *device_id, size_t device_id_len,
					       uint8_t const *gateway_id, size_t gateway_id_len,
					       uint32_t expires)
{
	struct				timeval now;
	redisReply			*reply = NULL;

	uint8_t				key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t				*key_p = key;

	fr_redis_rcode_t		status;
	ippool_rcode_t			ret = IPPOOL_RCODE_SUCCESS;

	vp_tmpl_t			rhs = { .type = TMPL_TYPE_DATA, .tmpl_data_type = PW_TYPE_STRING };
	vp_map_t			map = { .lhs = inst->reply_attr, .op = T_OP_SET, .rhs = &rhs,};

	gettimeofday(&now, NULL);

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!device_id) device_id = (uint8_t const *)"";
	if (!gateway_id) gateway_id = (uint8_t const *)"";

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);

	status = ippool_script(&reply, request, inst->cluster,
			       key_prefix, key_prefix_len,
			       inst->wait_num, FR_TIMEVAL_TO_MS(&inst->wait_timeout),
			       lua_alloc_digest, lua_alloc_cmd,
	 		       "EVALSHA %s 1 %b %b %u %u %b %b",
			       lua_alloc_digest,
			       key, key_p - key,
			       key_prefix, key_prefix_len,
			       (unsigned int)now.tv_sec, (unsigned int)now.tv_sec + expires,
			       device_id, device_id_len,
			       gateway_id, gateway_id_len);
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	rad_assert(reply);
	switch (reply->type) {
	/*
	 *	Can't have 128bit numbers (yet) so these are always IPv4
	 */
	case REDIS_REPLY_INTEGER:
	{
		/*
		 *	Destination attribute may not be IPv4, in which case
		 *	we want to pre-convert the integer value to an IPv4
		 *	address before casting it once more to the type of
		 *	the destination attribute.
		 */
		if (map.lhs->tmpl_da->type != PW_TYPE_IPV4_ADDR) {
			value_data_t tmp;

			memset(&tmp, 0, sizeof(tmp));

			tmp.integer = ntohl((uint32_t)reply->integer);
			tmp.length = sizeof(map.rhs->tmpl_data_value.integer);

			if (value_data_cast(NULL, &map.rhs->tmpl_data_value, PW_TYPE_IPV4_ADDR,
					    NULL, PW_TYPE_INTEGER, NULL, &tmp)) {
				REDEBUG("Failed converting integer to IPv4 address: %s", fr_strerror());
				ret = IPPOOL_RCODE_FAIL;
				goto finish;
			}
		} else {
			map.rhs->tmpl_data_value.integer = ntohl((uint32_t)reply->integer);
			map.rhs->tmpl_data_length = sizeof(map.rhs->tmpl_data_value.integer);
			map.rhs->tmpl_data_type = PW_TYPE_INTEGER;
		}
	}
		break;

	case REDIS_REPLY_STRING:
		map.rhs->tmpl_data_value.strvalue = reply->str;
		map.rhs->tmpl_data_length = reply->len;
		map.rhs->tmpl_data_type = PW_TYPE_STRING;
		break;

	case REDIS_REPLY_NIL:
		RWDEBUG("No free IP addresses available in pool \"%s\"", key_prefix);
		ret = IPPOOL_RCODE_POOL_EMPTY;
		goto finish;

	case REDIS_REPLY_STATUS:
	default:
		REDEBUG("Server returned non-value type \"%s\"",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		fr_redis_reply_print(L_DBG_LVL_2, reply, request, 0);
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	/*
	 *	Ahhh abstraction...
	 */
	if (map.lhs) ret = map_to_request(request, &map, map_to_vp, NULL);

finish:
	fr_redis_reply_free(reply);
	return ret;
}

/** Update an existing IP address in a pool
 *
 */
static ippool_rcode_t redis_ippool_update(rlm_redis_ippool_t *inst, REQUEST *request,
					  uint8_t const *key_prefix, size_t key_prefix_len,
					  VALUE_PAIR *ip_vp,
					  uint8_t const *device_id, size_t device_id_len,
					  uint8_t const *gateway_id, size_t gateway_id_len,
					  uint32_t expires)
{
	struct				timeval now;
	redisReply			*reply = NULL;

	uint8_t				key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t				*key_p = key;

	uint8_t				ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t				*ip_key_p = ip_key;

	fr_redis_rcode_t		status;
	ippool_rcode_t			ret = IPPOOL_RCODE_SUCCESS;

	value_data_t			*ip = NULL;
	value_data_t			ip_value;
	PW_TYPE				ip_value_type;

	ip_value_type = (ip_vp->da->type == PW_TYPE_IPV4_ADDR) && inst->ipv4_integer ? PW_TYPE_INTEGER : PW_TYPE_STRING;

	/*
	 *	This speed up is likely specific to Redis
	 */
	if (ip_vp->da->type != ip_value_type) {
		memset(&ip_value, 0, sizeof(ip_value));
		if (value_data_cast(request, &ip_value, ip_value_type,
				    NULL, ip_vp->da->type, ip_vp->da, &ip_vp->data)) {
			REDEBUG("Failed converting %s to required type: %s", ip_vp->da->name, fr_strerror());
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
		ip = &ip_value;
	} else {
		ip = &ip_vp->data;
	}

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_BUILD_IP_KEY(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_vp);

	gettimeofday(&now, NULL);

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!device_id) device_id = (uint8_t const *)"";
	if (!gateway_id) gateway_id = (uint8_t const *)"";


	if (ip_value_type == PW_TYPE_INTEGER) {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, FR_TIMEVAL_TO_MS(&inst->wait_timeout),
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %b %u %u %u %b %b",
				       lua_update_digest,
				       key, key_p - key,
				       ip_key, ip_key_p - ip_key,
				       (unsigned int)now.tv_sec, (unsigned int)now.tv_sec + expires,
				       htonl(ip->integer),
				       device_id, device_id_len,
				       gateway_id, gateway_id_len);
	} else {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, FR_TIMEVAL_TO_MS(&inst->wait_timeout),
				       lua_update_digest, lua_update_cmd,
				       "EVALSHA %s 1 %b %b %u %u %s %b %b",
				       lua_update_digest,
				       key, key_p - key,
				       ip_key, ip_key_p - ip_key,
				       (unsigned int)now.tv_sec, (unsigned int)now.tv_sec + expires,
				       ip->strvalue,
				       device_id, device_id_len,
				       gateway_id, gateway_id_len);
	}
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		ret = reply->integer;	/* Update script uses the same set of rcodes */
		break;

	case REDIS_REPLY_STATUS:
	default:
		REDEBUG("Server returned non-value type \"%s\"",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		fr_redis_reply_print(L_DBG_LVL_2, reply, request, 0);
		ret = IPPOOL_RCODE_FAIL;
		break;
	}

finish:
	/*
	 *	Free our temporary IP string
	 */
	if ((ip_value_type == PW_TYPE_STRING) && (ip != &ip_vp->data)) rad_const_free(ip_value.strvalue);
	fr_redis_reply_free(reply);

	return ret;
}

/** Release an existing IP address in a pool
 *
 */
static ippool_rcode_t redis_ippool_release(rlm_redis_ippool_t *inst, REQUEST *request,
					   uint8_t const *key_prefix, size_t key_prefix_len,
					   VALUE_PAIR *ip_vp,
					   uint8_t const *device_id, size_t device_id_len)
{
	struct				timeval now;
	redisReply			*reply = NULL;

	uint8_t				key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t				*key_p = key;

	uint8_t				ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t				*ip_key_p = ip_key;

	fr_redis_rcode_t		status;
	ippool_rcode_t			ret = IPPOOL_RCODE_SUCCESS;

	value_data_t			*ip = NULL;
	value_data_t			ip_value;
	PW_TYPE				ip_value_type = inst->ipv4_integer ? PW_TYPE_INTEGER : PW_TYPE_STRING;

	/*
	 *	This speed up is likely specific to Redis
	 */
	if (ip_vp->da->type != ip_value_type) {
		memset(&ip_value, 0, sizeof(ip_value));
		if (value_data_cast(request, &ip_value, ip_value_type,
				    NULL, ip_vp->da->type, ip_vp->da, &ip_vp->data)) {
			REDEBUG("Failed converting %s to required type: %s", ip_vp->da->name, fr_strerror());
			ret = IPPOOL_RCODE_FAIL;
			goto finish;
		}
		ip = &ip_value;
	} else {
		ip = &ip_vp->data;
	}

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_BUILD_IP_KEY(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_vp);

	gettimeofday(&now, NULL);

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!device_id) device_id = (uint8_t const *)"";

	if (ip_value_type == PW_TYPE_INTEGER) {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, FR_TIMEVAL_TO_MS(&inst->wait_timeout),
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %b %u %u %b",
				       lua_release_digest,
				       key, key_p - key,
				       ip_key, ip_key_p - ip_key,
				       (unsigned int)now.tv_sec,
				       htonl(ip->integer),
				       device_id, device_id_len);
	} else {
		status = ippool_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, FR_TIMEVAL_TO_MS(&inst->wait_timeout),
				       lua_release_digest, lua_release_cmd,
				       "EVALSHA %s 1 %b %b %u %s %b",
				       lua_release_digest,
				       key, key_p - key,
				       ip_key, ip_key_p - ip_key,
				       (unsigned int)now.tv_sec,
				       ip->strvalue,
				       device_id, device_id_len);
	}
	if (status != REDIS_RCODE_SUCCESS) {
		ret = IPPOOL_RCODE_FAIL;
		goto finish;
	}

	switch (reply->type) {
	case REDIS_REPLY_INTEGER:
		ret = reply->integer;	/* Update script uses the same set of rcodes */
		break;

	case REDIS_REPLY_STATUS:
	default:
		REDEBUG("Server returned non-value type \"%s\"",
			fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		fr_redis_reply_print(L_DBG_LVL_2, reply, request, 0);
		ret = IPPOOL_RCODE_FAIL;
		break;
	}

finish:
	/*
	 *	Free our temporary IP string
	 */
	if ((ip_value_type == PW_TYPE_STRING) && (ip != &ip_vp->data)) rad_const_free(ip_value.strvalue);
	fr_redis_reply_free(reply);

	return ret;
}

static rlm_rcode_t mod_action(rlm_redis_ippool_t *inst, REQUEST *request, ippool_action_t action)
{
	uint8_t		key_prefix[IPPOOL_MAX_KEY_PREFIX_SIZE], device_id_buff[256], gateway_id_buff[256];
	uint8_t		*device_id = NULL, *gateway_id = NULL;
	size_t		key_prefix_len, device_id_len = 0, gateway_id_len = 0;
	ssize_t		slen;
	VALUE_PAIR	*ip;
	char		expires_buff[20];
	char const	*expires_str;
	unsigned long	expires = 0;
	char		*q;

	slen = ippool_pool_name((uint8_t *)&key_prefix, sizeof(key_prefix), inst, request);
	if (slen < 0) return RLM_MODULE_FAIL;

	key_prefix_len = (size_t)slen;

	if (inst->device_id) {
		slen = tmpl_expand((char const **)&device_id,
				   (char *)&device_id_buff, sizeof(device_id_buff),
				   request, inst->device_id, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Failed expanding device (%s)", inst->device_id->name);
			return RLM_MODULE_FAIL;
		}
		device_id_len = (size_t)slen;
	}

	if (inst->gateway_id) {
		slen = tmpl_expand((char const **)&gateway_id,
				   (char *)&gateway_id_buff, sizeof(gateway_id_buff),
				   request, inst->gateway_id, NULL, NULL);
		if (slen < 0) {
			REDEBUG("Failed expanding gateway (%s)", inst->gateway_id->name);
			return RLM_MODULE_FAIL;
		}
		gateway_id_len = (size_t)slen;
	}

	switch (action) {
	case POOL_ACTION_ALLOCATE:
		if (tmpl_expand(&expires_str, expires_buff, sizeof(expires_buff),
				request, inst->offer_time, NULL, NULL) < 0) {
			REDEBUG("Failed expanding offer_time (%s)", inst->offer_time->name);
			return RLM_MODULE_FAIL;
		}

		expires = strtoul(expires_str, &q, 10);
		if (q != (expires_str + strlen(expires_str))) {
			REDEBUG("Invalid offer_time.  Must be an integer value");
			return RLM_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len, NULL,
				    device_id, device_id_len, gateway_id, gateway_id_len, expires);
		switch (redis_ippool_allocate(inst, request, key_prefix, key_prefix_len,
					      device_id, device_id_len,
					      gateway_id, gateway_id_len, (uint32_t)expires)) {
		case IPPOOL_RCODE_SUCCESS:
			return RLM_MODULE_UPDATED;

		case IPPOOL_RCODE_POOL_EMPTY:
			return RLM_MODULE_NOTFOUND;

		default:
			return RLM_MODULE_FAIL;
		}

	case POOL_ACTION_UPDATE:
		if (tmpl_expand(&expires_str, expires_buff, sizeof(expires_buff),
				request, inst->lease_time, NULL, NULL) < 0) {
			REDEBUG("Failed expanding lease_time (%s)", inst->lease_time->name);
			return RLM_MODULE_FAIL;
		}

		expires = strtoul(expires_str, &q, 10);
		if (q != (expires_str + strlen(expires_str))) {
			REDEBUG("Invalid expires.  Must be an integer value");
			return RLM_MODULE_FAIL;
		}

		if (tmpl_find_vp(&ip, request, inst->renew_attr) < 0) {
			REDEBUG("Failed expanding renew_attr (%s)", inst->renew_attr->name);
			return RLM_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip, device_id, device_id_len, gateway_id, gateway_id_len, expires);
		switch (redis_ippool_update(inst, request, key_prefix, key_prefix_len,
					    ip, device_id, device_id_len,
					    gateway_id, gateway_id_len, (uint32_t)expires)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("IP address lease updated");
			return RLM_MODULE_UPDATED;

		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("IP address is not a member of the specified pool");
			return RLM_MODULE_NOTFOUND;

		case IPPOOL_RCODE_EXPIRED:
			REDEBUG("IP address lease already expired at time of renewal");
			return RLM_MODULE_INVALID;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("IP address lease allocated to another device");
			return RLM_MODULE_INVALID;

		default:
			return RLM_MODULE_FAIL;
		}

	case POOL_ACTION_RELEASE:
		if (tmpl_find_vp(&ip, request, inst->renew_attr) < 0)  {
			REDEBUG("Failed expanding renew_attr (%s)", inst->renew_attr->name);
			return RLM_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip, device_id, device_id_len, gateway_id, gateway_id_len, 0);
		switch (redis_ippool_release(inst, request, key_prefix, key_prefix_len,
					     ip, device_id, device_id_len)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("IP address released");
			return RLM_MODULE_UPDATED;

		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("IP address is not a member of the specified pool");
			return RLM_MODULE_NOTFOUND;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("IP address lease allocated to another device");
			return RLM_MODULE_INVALID;

		default:
			return RLM_MODULE_FAIL;
		}

	case POOL_ACTION_BULK_RELEASE:
		RDEBUG2("Bulk release not yet implemented");
		return RLM_MODULE_NOOP;

	default:
		rad_assert(0);
		return RLM_MODULE_FAIL;
	}
}

static rlm_rcode_t mod_accounting(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_accounting(void *instance, REQUEST *request)
{
	rlm_redis_ippool_t	*inst = instance;
	VALUE_PAIR		*vp;

	/*
	 *	Pool-Action override
	 */
	vp = fr_pair_find_by_num(request->config, PW_POOL_ACTION, 0, TAG_ANY);
	if (vp) return mod_action(inst, request, vp->vp_integer);

	/*
	 *	Otherwise, guess the action by Acct-Status-Type
	 */
	vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if (!vp) {
		RDEBUG2("Couldn't find &request:Acct-Status-Type or &control:Pool-Action, doing nothing...");
		return RLM_MODULE_NOOP;
	}

	switch (vp->vp_integer) {
	case PW_STATUS_START:
	case PW_STATUS_ALIVE:
		return mod_action(inst, request, POOL_ACTION_UPDATE);

	case PW_STATUS_STOP:
		return mod_action(inst, request, POOL_ACTION_RELEASE);

	case PW_STATUS_ACCOUNTING_OFF:
	case PW_STATUS_ACCOUNTING_ON:
		return mod_action(inst, request, POOL_ACTION_BULK_RELEASE);

	default:
		return RLM_MODULE_NOOP;
	}
}

static rlm_rcode_t mod_authorize(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_authorize(void *instance, REQUEST *request)
{
	rlm_redis_ippool_t	*inst = instance;
	VALUE_PAIR		*vp;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_num(request->config, PW_POOL_ACTION, 0, TAG_ANY);
	return mod_action(inst, request, vp ? vp->vp_integer : POOL_ACTION_ALLOCATE);
}

static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t mod_post_auth(void *instance, REQUEST *request)
{
	rlm_redis_ippool_t	*inst = instance;
	VALUE_PAIR		*vp;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_num(request->config, PW_POOL_ACTION, 0, TAG_ANY);
	return mod_action(inst, request, vp ? vp->vp_integer : POOL_ACTION_ALLOCATE);
}

static int mod_bootstrap(CONF_SECTION *conf, void *instance)
{
	rlm_redis_ippool_t *inst = instance;

	fr_redis_version_print();

	inst->name = cf_section_name2(conf);
	if (!inst->name) inst->name = cf_section_name1(conf);
	inst->conf.prefix = talloc_asprintf(inst, "rlm_redis (%s)", inst->name);

	return 0;
}

static int mod_instantiate(CONF_SECTION *conf, void *instance)
{
	static bool	done_hash = false;
	CONF_SECTION	*subcs = cf_subsection_find_next(conf, NULL, "redis");

	rlm_redis_ippool_t *inst = instance;

	rad_assert(inst->reply_attr->type == TMPL_TYPE_ATTR);
	rad_assert(inst->renew_attr->type == TMPL_TYPE_ATTR);
	rad_assert(subcs);

	inst->cluster = fr_redis_cluster_alloc(inst, subcs, &inst->conf);
	if (!inst->cluster) return -1;

	/*
	 *	Pre-Compute the SHA hashes of the Lua scripts
	 */
	if (!done_hash) {
		fr_sha1_ctx	sha1_ctx;
		uint8_t		digest[SHA1_DIGEST_LENGTH];

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_alloc_cmd, sizeof(lua_alloc_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(lua_alloc_digest, digest, sizeof(digest));

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_update_cmd, sizeof(lua_update_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(lua_update_digest, digest, sizeof(digest));

		fr_sha1_init(&sha1_ctx);
		fr_sha1_update(&sha1_ctx, (uint8_t const *)lua_release_cmd, sizeof(lua_release_cmd) - 1);
		fr_sha1_final(digest, &sha1_ctx);
		fr_bin2hex(lua_release_digest, digest, sizeof(digest));
	}

	/*
	 *	If we don't have a separate time specifically for offers
	 *	just use the lease time.
	 */
	if (!inst->offer_time) inst->offer_time = inst->lease_time;

	return 0;
}

extern module_t rlm_redis_ippool;
module_t rlm_redis_ippool = {
	.magic		= RLM_MODULE_INIT,
	.name		= "redis",
	.type		= RLM_TYPE_THREAD_SAFE,
	.inst_size	= sizeof(rlm_redis_ippool_t),
	.config		= module_config,
	.bootstrap	= mod_bootstrap,
	.instantiate	= mod_instantiate,
	.methods = {
		[MOD_ACCOUNTING]	= mod_accounting,
		[MOD_AUTHORIZE]		= mod_authorize,
		[MOD_POST_AUTH]		= mod_post_auth,
	},
};
