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
 * @file rlm_redis_ippool_tool.c
 * @brief IP population tool.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/server/rad_assert.h>

#include "base.h"
#include "cluster.h"
#include "redis_ippool.h"

#define MAX_PIPELINED 100000

/** Pool management actions
 *
 */
typedef enum ippool_tool_action {
	IPPOOL_TOOL_NOOP = 0,			//!< Do nothing.
	IPPOOL_TOOL_ADD,			//!< Add one or more IP addresses.
	IPPOOL_TOOL_REMOVE,			//!< Remove one or more IP addresses.
	IPPOOL_TOOL_RELEASE,			//!< Release one or more IP addresses.
	IPPOOL_TOOL_SHOW,			//!< Show one or more IP addresses.
	IPPOOL_TOOL_MODIFY			//!< Modify attributes of one or more IP addresses.
} ippool_tool_action_t;

/** A single pool operation
 *
 */
typedef struct {
	char const		*name;		//!< Original range or CIDR string.

	uint8_t const		*pool;		//!< Pool identifier.
	size_t			pool_len;	//!< Length of the pool identifier.

	uint8_t const		*range;		//!< Range identifier.
	size_t			range_len;	//!< Length of the range identifier.

	fr_ipaddr_t		start;		//!< Start address.
	fr_ipaddr_t		end;		//!< End address.
	uint8_t			prefix;		//!< Prefix - The bits between the address mask, and the prefix
						//!< form the addresses to be modified in the pool.
	ippool_tool_action_t	action;		//!< What to do to the leases described by net/prefix.
} ippool_tool_operation_t;

typedef struct {
	fr_ipaddr_t		ipaddr;		//!< Prefix or address.
	time_t			next_event;	//!< Last state change.
	uint8_t const		*range;		//!< Range the lease belongs to.
	size_t			range_len;
	uint8_t	const		*device;	//!< Last device id.
	size_t			device_len;
	uint8_t const		*gateway;	//!< Last gateway id.
	size_t			gateway_len;
} ippool_tool_lease_t;

typedef struct {
	uint64_t		total;		//!< Addresses available.
	uint64_t		free;		//!< Addresses in use.
	uint64_t		expiring_1m;	//!< Addresses that expire in the next minute.
	uint64_t		expiring_30m;	//!< Addresses that expire in the next 30 minutes.
	uint64_t		expiring_1h;	//!< Addresses that expire in the next hour.
	uint64_t		expiring_1d;	//!< Addresses that expire in the next day.
} ippool_tool_stats_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
	fr_redis_cluster_t	*cluster;
} redis_driver_conf_t;

typedef struct {
	void			*driver;
	CONF_SECTION		*cs;
} ippool_tool_t;

typedef int (*redis_ippool_queue_t)(redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				    uint8_t const *key_prefix, size_t key_prefix_len,
				    uint8_t const *range, size_t range_len,
				    fr_ipaddr_t *ipaddr, uint8_t prefix);

typedef int (*redis_ippool_process_t)(void *out, fr_ipaddr_t const *ipaddr, redisReply const *reply);

#define IPPOOL_BUILD_IP_KEY_FROM_STR(_buff, _p, _key, _key_len, _ip_str) \
do { \
	ssize_t _slen; \
	*_p++ = '{'; \
	memcpy(_p, _key, _key_len); \
	_p += _key_len; \
	_slen = strlcpy((char *)_p, "}:"IPPOOL_ADDRESS_KEY":", sizeof(_buff) - (_p - _buff)); \
	if (is_truncated((size_t)_slen, sizeof(_buff) - (_p - _buff))) { \
		ERROR("IP key too long"); \
		return 0;\
	} \
	_p += (size_t)_slen;\
	_p += strlcpy((char *)_p, _ip_str, sizeof(_buff) - (_p - _buff)); \
} while (0)

#define EOL "\n"

static char const *name;
/** Lua script for releasing a lease
 *
 * - KEYS[1] The pool name.
 * - ARGV[1] IP address to release.
 *
 * Removes the IP entry in the ZSET, then removes the address hash, and the device key
 * if one exists.
 *
 * Will do nothing if the lease is not found in the ZSET.
 *
 * Returns
 * - 0 if no ip addresses were removed.
 * - 1 if an ip address was removed.
 */
static char lua_release_cmd[] =
	"local found" EOL								/* 1 */
	"local ret" EOL									/* 2 */

	/*
	 *	Set expiry time to 0
	 */
	"ret = redis.call('ZADD', '{' .. KEYS[1] .. '}:"IPPOOL_POOL_KEY"', 'XX', 'CH', 0, ARGV[1])" EOL	/* 3 */
	"if ret == 0 then" EOL								/* 4 */
	"  return 0" EOL								/* 5 */
	"end" EOL									/* 6 */
	"found = redis.call('HGET', '{' .. KEYS[1] .. '}:"IPPOOL_ADDRESS_KEY":'"
			    " .. ARGV[1], 'device')" EOL				/* 7 */
	"if not found then" EOL								/* 8 */
	"  return ret"	EOL								/* 9 */
	"end" EOL									/* 10 */

	/*
	 *	Remove the association between the device and a lease
	 */
	"redis.call('DEL', '{' .. KEYS[1] .. '}:"IPPOOL_DEVICE_KEY":' .. found)" EOL	/* 11 */
	"return 1";									/* 12 */

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
	"if not found then" EOL								/* 7 */
	"  return ret"	EOL								/* 8 */
	"end" EOL									/* 9 */
	"redis.call('DEL', address_key)" EOL						/* 10 */

	/*
	 *	Remove the association between the device and a lease
	 */
	"redis.call('DEL', '{' .. KEYS[1] .. '}:"IPPOOL_DEVICE_KEY":' .. found)" EOL	/* 11 */
	"return 1" EOL;									/* 12 */

static void NEVER_RETURNS usage(int ret) {
	INFO("Usage: %s -adrsm range... [-p prefix_len]... [-x]... [-oShf] server[:port] [pool] [range id]", name);
	INFO("Pool management:");
	INFO("  -a range               Add address(es)/prefix(es) to the pool.");
	INFO("  -d range               Delete address(es)/prefix(es) in this range.");
	INFO("  -r range               Release address(es)/prefix(es) in this range.");
	INFO("  -s range               Show addresses/prefix in this range.");
	INFO("  -p prefix_len          Length of prefix to allocate (defaults to 32/128)");
	INFO("                         This is used primarily for IPv6 where a prefix is");
	INFO("                         allocated to an intermediary router, which in turn");
	INFO("                         allocates sub-prefixes to the devices it serves.");
	INFO("                         This argument changes the prefix_len for the previous");
	INFO("                         instance of an -adrsm argument, only.");
	INFO("  -m range               Change the range id to the one specified for addresses");
	INFO("                         in this range.");
	INFO("  -l                     List available pools.");
//	INFO("  -L                     List available ranges in pool [NYI]");
//	INFO("  -i file                Import entries from ISC lease file [NYI]");
	INFO(" ");	/* -Werror=format-zero-length */
//	INFO("Pool status:");
//	INFO("  -I                     Output active entries in ISC lease file format [NYI]");
	INFO("  -S                     Print pool statistics");
	INFO(" ");	/* -Werror=format-zero-length */
	INFO("Configuration:");
	INFO("  -h                     Print this help message and exit");
	INFO("  -x                     Increase the verbosity level");
//	INFO("  -o attr=value          Set option, these are specific to the backends [NYI]");
	INFO("  -f file                Load connection options from a FreeRADIUS format config file");
	INFO("                         This file should contain a pool { ... } section and one or more");
	INFO("                         `server = <fqdn>` pairs`");
	INFO(" ");
	INFO("<range> is range \"127.0.0.1-127.0.0.254\" or CIDR network \"127.0.0.1/24\" or host \"127.0.0.1\"");
	INFO("CIDR host bits set start address, e.g. 127.0.0.200/24 -> 127.0.0.200-127.0.0.254");
	exit(ret);
}

static uint32_t uint32_gen_mask(uint8_t bits)
{
	if (bits >= 32) return 0xffffffff;
	return (1 << bits) - 1;
}

/*
 *	128bit integers are not standard on many compilers
 *	despite SSE2 instructions for dealing with them
 *	specifically.
 */
#ifndef HAVE_128BIT_INTEGERS
/** Create a 128 bit integer value with n bits high
 *
 */
static uint128_t uint128_gen_mask(uint8_t bits)
{
	uint128_t ret;

	rad_assert(bits < 128);

	if (bits > 64) {
		ret.l = 0xffffffffffffffff;
		ret.h = (uint64_t)1 << (bits - 64);
		ret.h ^= (ret.h - 1);
		return ret;
	}
	ret.h = 0;
	ret.l = (uint64_t)1 << bits;
	ret.l ^= (ret.l - 1);

	return ret;
}
/** Left shift 128 bit integer
 *
 * @note shift must be 127 bits or less.
 */
static uint128_t uint128_lshift(uint128_t num, uint8_t bits)
{
	rad_assert(bits < 128);

	if (bits >= 64) {
		num.l = 0;
		num.h = num.l << (bits - 64);
		return num;
	}
	num.h = (num.h << bits) | (num.l >> (64 - bits));
	num.l <<= bits;

	return num;
}

/** Add two 128bit unsigned integers
 *
 * @author Jacob F. W
 * @note copied from http://www.codeproject.com/Tips/617214/UInt-Addition-Subtraction
 */
static uint128_t uint128_add(uint128_t a, uint128_t b)
{
	uint128_t ret;
	uint64_t tmp = (((a.l & b.l) & 1) + (a.l >> 1) + (b.l >> 1)) >> 63;
	ret.l = a.l + b.l;
	ret.h = a.h + b.h + tmp;
	return ret;
}

/** Subtract one 128bit integer from another
 *
 * @author Jacob F. W
 * @note copied from http://www.codeproject.com/Tips/617214/UInt-Addition-Subtraction
 */
static uint128_t uint128_sub(uint128_t a, uint128_t b)
{
	uint128_t ret;
	uint64_t c;

	ret.l = a.l - b.l;
	c = (((ret.l & b.l) & 1) + (b.l >> 1) + (ret.l >> 1)) >> 63;
	ret.h = a.h - (b.h + c);

	return ret;
}

/** Perform bitwise & of two 128bit unsigned integers
 *
 */
static uint128_t uint128_band(uint128_t a, uint128_t b)
{
	uint128_t ret;
	ret.l = a.l & b.l;
	ret.h = a.h & b.h;
	return ret;
}

/** Perform bitwise | of two 128bit unsigned integers
 *
 */
static uint128_t uint128_bor(uint128_t a, uint128_t b)
{
	uint128_t ret;
	ret.l = a.l | b.l;
	ret.h = a.h + b.h;
	return ret;
}

/** Return whether the integers are equal
 *
 */
static bool uint128_eq(uint128_t a, uint128_t b)
{
	return (a.h == b.h) && (a.l == b.l);
}

/** Return whether one integer is greater than the other
 *
 */
static bool uint128_gt(uint128_t a, uint128_t b)
{
	if (a.h < b.h) return false;
	if (a.h > b.h) return true;
	return (a.l > b.l);
}

/** Creates a new uint128_t from an uint64_t
 *
 */
static uint128_t uint128_new(uint64_t h, uint64_t l) {
	uint128_t ret;
	ret.l = l;
	ret.h = h;
	return ret;
}
#else
static uint128_t uint128_gen_mask(uint8_t bits)
{
	if (bits >= 128) return ~(uint128_t)0x00;
	return (((uint128_t)1) << bits) - 1;
}
#define uint128_lshift(_num, _bits) (_num << _bits)
//#define uint128_band(_a, _b) (_a & _b)
#define uint128_bor(_a, _b) (_a | _b)
#define uint128_eq(_a, _b) (_a == _b)
#define uint128_gt(_a, _b) (_a > _b)
#define uint128_add(_a, _b) (_a + _b)
#define uint128_sub(_a, _b) (_a - _b)
#define uint128_new(_a, _b) ((uint128_t)_b | ((uint128_t)_a << 64))
#endif

/** Iterate over range of IP addresses
 *
 * Mutates the ipaddr passed in, adding one to the prefix bits on each call.
 *
 * @param[in,out] ipaddr to increment.
 * @param[in] end ipaddr to stop at.
 * @param[in] prefix Length of the prefix.
 * @return
 *	- true if the prefix bits are not high (continue).
 *	- false if the prefix bits are high (stop).
 */
static bool ipaddr_next(fr_ipaddr_t *ipaddr, fr_ipaddr_t const *end, uint8_t prefix)
{
	switch (ipaddr->af) {
	default:
	case AF_UNSPEC:
		rad_assert(0);
		return false;

	case AF_INET6:
	{
		uint128_t ip_curr, ip_end;

		if (!fr_cond_assert((prefix > 0) && (prefix <= 128))) return false;

		/* Don't be tempted to cast */
		memcpy(&ip_curr, ipaddr->addr.v6.s6_addr, sizeof(ip_curr));
		memcpy(&ip_end, end->addr.v6.s6_addr, sizeof(ip_curr));

		ip_curr = ntohlll(ip_curr);
		ip_end = ntohlll(ip_end);

		/* We're done */
		if (uint128_eq(ip_curr, ip_end)) return false;

		/* Increment the prefix */
		ip_curr = uint128_add(ip_curr, uint128_lshift(uint128_new(0, 1), (128 - prefix)));
		ip_curr = htonlll(ip_curr);
		memcpy(&ipaddr->addr.v6.s6_addr, &ip_curr, sizeof(ipaddr->addr.v6.s6_addr));
		return true;
	}

	case AF_INET:
	{
		uint32_t ip_curr, ip_end;

		if (!fr_cond_assert((prefix > 0) && (prefix <= 32))) return false;

		ip_curr = ntohl(ipaddr->addr.v4.s_addr);
		ip_end = ntohl(end->addr.v4.s_addr);

		/* We're done */
		if (ip_curr == ip_end) return false;

		/* Increment the prefix */
		ip_curr += 1 << (32 - prefix);
		ipaddr->addr.v4.s_addr = htonl(ip_curr);
		return true;
	}
	}
}

/** Add a net to the pool
 *
 * @return the number of new addresses added.
 */
static int driver_do_lease(void *out, void *instance, ippool_tool_operation_t const *op,
			   redis_ippool_queue_t enqueue, redis_ippool_process_t process)
{
	redis_driver_conf_t		*inst = talloc_get_type_abort(instance, redis_driver_conf_t);

	int				i;
	bool				more = true;
	fr_redis_conn_t			*conn;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;

	fr_ipaddr_t			ipaddr = op->start;
	fr_redis_rcode_t		s_ret = REDIS_RCODE_SUCCESS;
	REQUEST				*request;
	redisReply			**replies = NULL;

	unsigned int			pipelined = 0;

	request = request_alloc(inst);
	while (more) {
		fr_ipaddr_t	acked = ipaddr; 	/* Record our progress */
		size_t		reply_cnt = 0;

		for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request,
							 op->pool, op->pool_len, false);
		     s_ret == REDIS_RCODE_TRY_AGAIN;
		     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &replies[0])) {
		     	more = true;	/* Reset to true, may have errored last loop */
			status = REDIS_RCODE_SUCCESS;

			/*
			 *	If we got a redirect, start back at the beginning of the block.
			 */
			ipaddr = acked;

			for (i = 0; (i < MAX_PIPELINED) && more; i++, more = ipaddr_next(&ipaddr, &op->end,
											 op->prefix)) {
				int enqueued;

				enqueued = enqueue(inst, conn, op->pool, op->pool_len,
						   op->range, op->range_len, &ipaddr, op->prefix);
				if (enqueued < 0) break;
				pipelined += enqueued;
			}

			if (!replies) replies = talloc_zero_array(inst, redisReply *, pipelined);
			if (!replies) return 0;

			reply_cnt = fr_redis_pipeline_result(&pipelined, &status, replies,
							     talloc_array_length(replies), conn);
			for (i = 0; (size_t)i < reply_cnt; i++) fr_redis_reply_print(L_DBG_LVL_3,
										     replies[i], request, i);
		}
		if (s_ret != REDIS_RCODE_SUCCESS) {
			fr_redis_pipeline_free(replies, reply_cnt);
			talloc_free(replies);
			talloc_free(request);
			return -1;
		}

		if (process) {
			fr_ipaddr_t to_process = acked;

			for (i = 0; (size_t)i < reply_cnt; i++) {
				int ret;

				ret = process(out, &to_process, replies[i]);
				if (ret < 0) continue;
				ipaddr_next(&to_process, &op->end, op->prefix);
			}
		}
		fr_redis_pipeline_free(replies, reply_cnt);
		TALLOC_FREE(replies);
	}
	talloc_free(request);

	return 0;
}

/** Enqueue commands to retrieve lease information
 *
 */
static int _driver_show_lease_process(void *out, fr_ipaddr_t const *ipaddr, redisReply const *reply)
{
	size_t existing;
	ippool_tool_lease_t ***modified = out;
	ippool_tool_lease_t *lease;

	if (!*modified) *modified = talloc_array(NULL, ippool_tool_lease_t *, 1);

	/*
	 *	The exec command is the only one that produces an array.
	 */
	if (reply->type != REDIS_REPLY_ARRAY) return -1;
	if (reply->elements < 4) return -1;

	if (reply->element[0]->type == REDIS_REPLY_NIL) return 0;	/* A nil result (IP didn't exist) */
	if (reply->element[0]->type != REDIS_REPLY_STRING) return -1;	/* Something bad */
	lease = talloc_zero(*modified, ippool_tool_lease_t);
	lease->ipaddr = *ipaddr;
	lease->next_event = (time_t)strtoull(reply->element[0]->str, NULL, 10);

	if (reply->element[1]->type == REDIS_REPLY_STRING) {
		lease->device = talloc_memdup(lease, reply->element[1]->str, reply->element[1]->len);
		lease->device_len = reply->element[1]->len;
	}
	if (reply->element[2]->type == REDIS_REPLY_STRING) {
		lease->gateway = talloc_memdup(lease, reply->element[2]->str, reply->element[2]->len);
		lease->gateway_len = reply->element[2]->len;
	}
	if (reply->element[3]->type == REDIS_REPLY_STRING) {
		lease->range = talloc_memdup(lease, reply->element[3]->str, reply->element[3]->len);
		lease->range_len = reply->element[3]->len;
	}

	/*
	 *	Grow the result array...
	 */
	existing = talloc_array_length(*modified);
	MEM(*modified = talloc_realloc(NULL, *modified, ippool_tool_lease_t *, existing + 1));
	(*modified)[existing - 1] = lease;

	return 0;
}

/** Enqueue commands to retrieve lease information
 *
 */
static int _driver_show_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				      uint8_t const *key_prefix, size_t key_prefix_len,
				      UNUSED uint8_t const *range, UNUSED size_t range_len,
				      fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	uint8_t		ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t		*ip_key_p = ip_key;

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);
	IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_buff);

	DEBUG("Retrieving lease info for %s from pool %s", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "MULTI");
	redisAppendCommand(conn->handle, "ZSCORE %b %s", key, key_p - key, ip_buff);
	redisAppendCommand(conn->handle, "HGET %b device", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "HGET %b gateway", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "HGET %b range", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "EXEC");
	return 6;
}

/** Show information about leases
 *
 */
static inline int driver_show_lease(void *out, void *instance, ippool_tool_operation_t const *op)
{
	return driver_do_lease(out, instance, op, _driver_show_lease_enqueue, _driver_show_lease_process);
}

/** Count the number of leases we released
 *
 */
static int _driver_release_lease_process(void *out, UNUSED fr_ipaddr_t const *ipaddr, redisReply const *reply)
{
	uint64_t *modified = out;
	/*
	 *	Record the actual number of addresses released.
	 *	Leases with a score of zero shouldn't be included,
	 *	in this count.
	 */
	if (reply->type != REDIS_REPLY_INTEGER) return -1;

	*modified += reply->integer;

	return 0;
}

/** Release a lease by setting its score back to zero
 *
 */
static int _driver_release_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
					 uint8_t const *key_prefix, size_t key_prefix_len,
					 UNUSED uint8_t const *range, UNUSED size_t range_len,
					 fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);

	DEBUG("Releasing %s to pool \"%s\"", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "EVAL %s 1 %b %s", lua_release_cmd, key_prefix, key_prefix_len, ip_buff);
	return 1;
}

/** Release a range of leases
 *
 */
static inline int driver_release_lease(void *out, void *instance, ippool_tool_operation_t const *op)
{
	return driver_do_lease(out, instance, op,
			       _driver_release_lease_enqueue, _driver_release_lease_process);
}

/** Count the number of leases we removed
 *
 * Because the ZREM and DEL have to occur in a transaction, we need
 * some fancier processing to just count the number of ZREMs.
 */
static int _driver_remove_lease_process(void *out, UNUSED fr_ipaddr_t const *ipaddr, redisReply const *reply)
{
	uint64_t *modified = out;
	/*
	 *	Record the actual number of addresses released.
	 *	Leases with a score of zero shouldn't be included,
	 *	in this count.
	 */
	if (reply->type != REDIS_REPLY_INTEGER) return -1;

	*modified += reply->integer;

	return 0;
}

/** Enqueue lease removal commands
 *
 * This removes the lease from the expiry heap, and the data associated with
 * the lease.
 */
static int _driver_remove_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
					uint8_t const *key_prefix, size_t key_prefix_len,
					UNUSED uint8_t const *range, UNUSED size_t range_len,
					fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);

	DEBUG("Removing %s from pool \"%s\"", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "EVAL %s 1 %b %s", lua_remove_cmd, key_prefix, key_prefix_len, ip_buff);
	return 1;
}

/** Remove a range of leases
 *
 */
static int driver_remove_lease(void *out, void *instance, ippool_tool_operation_t const *op)
{
	return driver_do_lease(out, instance, op,
			       _driver_remove_lease_enqueue, _driver_remove_lease_process);
}

/** Count the number of leases we actually added
 *
 * This isn't necessarily the same as the number of ZADDs, as leases may
 * already exist.
 */
static int _driver_add_lease_process(void *out, UNUSED fr_ipaddr_t const *ipaddr, redisReply const *reply)
{
	uint64_t *modified = out;
	/*
	 *	Record the actual number of addresses modified.
	 *	Existing addresses won't be included in this
	 *	count.
	 */
	if (reply->type != REDIS_REPLY_ARRAY) return -1;

	if ((reply->elements > 0) && (reply->element[0]->type == REDIS_REPLY_INTEGER)) {
		*modified += reply->element[0]->integer;
	}
	return 0;
}

/** Enqueue lease addition commands
 *
 */
static int _driver_add_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				     uint8_t const *key_prefix, size_t key_prefix_len,
				     uint8_t const *range, size_t range_len,
				     fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	uint8_t		ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t		*ip_key_p = ip_key;

	int		enqueued = 0;

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);
	IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_buff);

	DEBUG("Adding %s to pool \"%.*s\" (%zu)", ip_buff, (int)(key_p - key), key, key_p - key);
	redisAppendCommand(conn->handle, "MULTI");
	enqueued++;
	redisAppendCommand(conn->handle, "ZADD %b NX %u %s", key, key_p - key, 0, ip_buff);
	enqueued++;

	/*
	 *	Only add range if it's not NULL.
	 *
	 *	Zero length ranges are allowed, and should be preserved.
	 */
	if (range) {
		redisAppendCommand(conn->handle, "HSET %b range %b", ip_key, ip_key_p - ip_key, range, range_len);
		enqueued++;
	}
	redisAppendCommand(conn->handle, "EXEC");
	enqueued++;

	return enqueued;
}

/** Add a range of prefixes
 *
 */
static int driver_add_lease(void *out, void *instance, ippool_tool_operation_t const *op)
{
	return driver_do_lease(out, instance, op, _driver_add_lease_enqueue, _driver_add_lease_process);
}

/** Count the number of leases we modified
 */
static int _driver_modify_lease_process(void *out, UNUSED fr_ipaddr_t const *ipaddr, redisReply const *reply)
{
	uint64_t *modified = out;
	/*
	 *	Record the actual number of addresses released.
	 *	Leases with a score of zero shouldn't be included,
	 *	in this count.
	 */
	if (reply->type != REDIS_REPLY_INTEGER) return -1;

	/*
	 *	return code is 0 or 1 depending on if its a new
	 *	field, neither are useful
	 */
	*modified += 1;

	return 0;
}

/** Enqueue lease removal commands
 *
 * This modifys the lease from the expiry heap, and the data associated with
 * the lease.
 */
static int _driver_modify_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
					uint8_t const *key_prefix, size_t key_prefix_len,
					uint8_t const *range, size_t range_len,
					fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	uint8_t		ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t		*ip_key_p = ip_key;

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);
	IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_buff);

	DEBUG("Modifying %s in pool \"%s\"", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "HSET %b range %b", ip_key, ip_key_p - ip_key, range, range_len);

	return 1;
}

/** Remove a range of leases
 *
 */
static int driver_modify_lease(void *out, void *instance, ippool_tool_operation_t const *op)
{
	return driver_do_lease(out, instance, op,
			       _driver_modify_lease_enqueue, _driver_modify_lease_process);
}

/** Compare two pool names
 *
 */
static int8_t pool_cmp(void const *a, void const *b)
{
	size_t len_a;
	size_t len_b;
	int ret;

	len_a = talloc_array_length((uint8_t const *)a);
	len_b = talloc_array_length((uint8_t const *)b);

	ret = (len_a > len_b) - (len_a < len_b);
	if (ret != 0) return ret;

	ret = memcmp(a, b, len_a);
	return (ret > 0) - (ret < 0);
}

/** Return the pools available across the cluster
 *
 * @param[in] ctx to allocate range names in.
 * @param[out] out Array of pool names.
 * @param[in] instance Driver specific instance data.
 * @return
 *	- < 0 on failure.
 *	- >= 0 the number of ranges in the array we allocated.
 */
static ssize_t driver_get_pools(TALLOC_CTX *ctx, uint8_t **out[], void *instance)
{
	fr_socket_addr_t	*master;
	size_t			k;
	ssize_t			ret, i, used = 0;
	fr_redis_conn_t		*conn = NULL;
	redis_driver_conf_t	*inst = talloc_get_type_abort(instance, redis_driver_conf_t);
	uint8_t			key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t			*key_p = key;
	REQUEST			*request;
	uint8_t 		**result;

	request = request_alloc(inst);

	IPPOOL_BUILD_KEY(key, key_p, "*}:pool", 1);

	*out = NULL;	/* Initialise output pointer */

	/*
	 *	Get the addresses of all masters in the pool
	 */
	ret = fr_redis_cluster_node_addr_by_role(ctx, &master, inst->cluster, true, false);
	if (ret <= 0) {
		result = NULL;
		return ret;
	}

	result = talloc_zero_array(ctx, uint8_t *, 1);
	if (!result) {
		ERROR("Failed allocating array of pool names");
		talloc_free(master);
		return -1;
	}

	/*
	 *	Iterate over the masters, getting the pools on each
	 */
	for (i = 0; i < ret; i++) {
		fr_pool_t	*pool;
		redisReply		*reply;
		char const		*p;
		size_t			len;
		char			cursor[19] = "0";

		if (fr_redis_cluster_pool_by_node_addr(&pool, inst->cluster, &master[i], false) < 0) {
			ERROR("Failed retrieving pool for node");
		error:
			TALLOC_FREE(result);
			talloc_free(master);
			talloc_free(request);
			return -1;
		}

		conn = fr_pool_connection_get(pool, request);
		if (!conn) goto error;
		do {
			/*
			 *	Break up the scan so we don't block any single
			 *	Redis node too long.
			 */
			reply = redisCommand(conn->handle, "SCAN %s MATCH %b COUNT 20", cursor, key, key_p - key);
			if (!reply) {
				ERROR("Failed reading reply");
				fr_pool_connection_release(pool, request, conn);
				goto error;
			}
			fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0);
			if (fr_redis_command_status(conn, reply) != REDIS_RCODE_SUCCESS) {
				PERROR("Error retrieving keys %s", cursor);

			reply_error:
				fr_pool_connection_release(pool, request, conn);
				fr_redis_reply_free(&reply);
				goto error;
			}

			if (reply->type != REDIS_REPLY_ARRAY) {
				ERROR("Failed retrieving result, expected array got %s",
				      fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));

				goto reply_error;
			}

			if (reply->elements != 2) {
				ERROR("Failed retrieving result, expected array with two elements, got %zu elements",
				      reply->elements);
				fr_redis_reply_free(&reply);
				goto reply_error;
			}

			if (reply->element[0]->type != REDIS_REPLY_STRING) {
				ERROR("Failed retrieving result, expected string got %s",
				      fr_table_str_by_value(redis_reply_types, reply->element[0]->type, "<UNKNOWN>"));
				goto reply_error;
			}

			if (reply->element[1]->type != REDIS_REPLY_ARRAY) {
				ERROR("Failed retrieving result, expected array got %s",
				      fr_table_str_by_value(redis_reply_types, reply->element[1]->type, "<UNKNOWN>"));
				goto reply_error;
			}

			if ((talloc_array_length(result) - used) < reply->element[1]->elements) {
				MEM(result = talloc_realloc(ctx, result, uint8_t *,
							    used + reply->element[1]->elements));
				if (!result) {
					ERROR("Failed expanding array of pool names");
					goto reply_error;
				}
			}
			strlcpy(cursor, reply->element[0]->str, sizeof(cursor));

			for (k = 0; k < reply->element[1]->elements; k++) {
				redisReply *pool_key = reply->element[1]->element[k];

				/*
				 *	Skip over things which are not pool names
				 */
				if (pool_key->len < 7) continue; /* { + [<name>] + }:pool */

				if ((pool_key->str[0]) != '{') continue;
				p = memchr(pool_key->str + 1, '}', pool_key->len - 1);
				if (!p) continue;

				len = (pool_key->len - ((p + 1) - pool_key->str));
				if (len != (sizeof(IPPOOL_POOL_KEY) - 1) + 1) continue;
				if (memcmp(p + 1, ":" IPPOOL_POOL_KEY, (sizeof(IPPOOL_POOL_KEY) - 1) + 1) != 0) {
					continue;
				}

				/*
				 *	String between the curly braces is the pool name
				 */
				result[used++] = talloc_memdup(result, pool_key->str + 1, (p - pool_key->str) - 1);
			}

			fr_redis_reply_free(&reply);
		} while (!((cursor[0] == '0') && (cursor[1] == '\0')));	/* Cursor value of 0 means no more results */

		fr_pool_connection_release(pool, request, conn);
	}

	if (used == 0) {
		*out = NULL;
		talloc_free(result);
		return 0;
	}

	/*
	 *	Sort the results
	 */
	{
		uint8_t const **to_sort;

		memcpy(&to_sort, &result, sizeof(to_sort));

		fr_quick_sort((void const **)to_sort, 0, used, pool_cmp);
	}

	*out = talloc_array(ctx, uint8_t *, used);
	if (!*out) {
		ERROR("Failed allocating file pool name array");
		talloc_free(result);
		return -1;
	}

	/*
	 *	SCAN can produce duplicates, remove them here
	 */
	i = 0;
	k = 0;
	do {	/* stop before last entry */
		(*out)[k++] = talloc_steal(*out, result[i++]);
		while ((i < used) && (pool_cmp(result[i - 1], result[i]) == 0)) i++;
	} while (i < used);

	talloc_free(request);
	talloc_free(result);

	return used;
}

static int driver_get_stats(ippool_tool_stats_t *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len)
{
	redis_driver_conf_t		*inst = talloc_get_type_abort(instance, redis_driver_conf_t);
	uint8_t				key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t				*key_p = key;

	fr_redis_conn_t			*conn;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;
	fr_time_t			now;

	int				s_ret = REDIS_RCODE_SUCCESS;
	REQUEST				*request;
	redisReply			**replies = NULL, *reply;
	unsigned int			pipelined = 0;		/* Update if additional commands added */

	size_t				reply_cnt = 0, i = 0;

#define STATS_COMMANDS_TOTAL 8

	request = request_alloc(inst);

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);

	MEM(replies = talloc_zero_array(inst, redisReply *, STATS_COMMANDS_TOTAL));

	now = fr_time();

	for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key, key_p - key, false);
	     s_ret == REDIS_RCODE_TRY_AGAIN;
	     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &replies[0])) {
		status = REDIS_RCODE_SUCCESS;

		redisAppendCommand(conn->handle, "MULTI");
		redisAppendCommand(conn->handle, "ZCARD %b", key, key_p - key);		/* Total */
		redisAppendCommand(conn->handle, "ZCOUNT %b -inf %i",
				   key, key_p - key, fr_time_to_sec(now));		/* Free */
		redisAppendCommand(conn->handle, "ZCOUNT %b -inf %i",
				   key, key_p - key, fr_time_to_sec(now) + 60);		/* Free in next 60s */
		redisAppendCommand(conn->handle, "ZCOUNT %b -inf %i",
				   key, key_p - key, fr_time_to_sec(now) + (60 * 30));	/* Free in next 30 mins */
		redisAppendCommand(conn->handle, "ZCOUNT %b -inf %i",
				   key, key_p - key, fr_time_to_sec(now) + (60 * 60));	/* Free in next 60 mins */
		redisAppendCommand(conn->handle, "ZCOUNT %b -inf %i",
				   key, key_p - key, fr_time_to_sec(now) + (60 * 60 * 24));	/* Free in next day */
		redisAppendCommand(conn->handle, "EXEC");
		if (!replies) return -1;

		pipelined = STATS_COMMANDS_TOTAL;
		reply_cnt = fr_redis_pipeline_result(&pipelined, &status, replies,
						     talloc_array_length(replies), conn);
		for (i = 0; (size_t)i < reply_cnt; i++) fr_redis_reply_print(L_DBG_LVL_3,
									     replies[i], request, i);
	}
	if (s_ret != REDIS_RCODE_SUCCESS) {
	error:
		fr_redis_pipeline_free(replies, reply_cnt);
		talloc_free(replies);
		talloc_free(request);
		return -1;
	}

	if (reply_cnt != STATS_COMMANDS_TOTAL) {
		ERROR("Failed retrieving pool stats: Expected %i replies, got %zu", pipelined, reply_cnt);
		goto error;
	}

	reply = replies[reply_cnt - 1];

	if (reply->type != REDIS_REPLY_ARRAY) {
		ERROR("Failed retrieving pool stats: Expected array got %s",
		      fr_table_str_by_value(redis_reply_types, reply->element[1]->type, "<UNKNOWN>"));
		goto error;
	}

	if (reply->elements != (reply_cnt - 2)) {
		ERROR("Failed retrieving pool stats: Expected %zu results, got %zu", reply_cnt - 2, reply->elements);
		goto error;
	}

	if (reply->element[0]->integer == 0) {
		ERROR("Pool not found");
		goto error;
	}

	out->total = reply->element[0]->integer;
	out->free = reply->element[1]->integer;
	out->expiring_1m = reply->element[2]->integer - out->free;
	out->expiring_30m = reply->element[3]->integer - out->free;
	out->expiring_1h = reply->element[4]->integer - out->free;
	out->expiring_1d = reply->element[5]->integer - out->free;

	fr_redis_pipeline_free(replies, reply_cnt);
	talloc_free(replies);
	talloc_free(request);

	return 0;
}

/** Driver initialization function
 *
 */
static int driver_init(TALLOC_CTX *ctx, CONF_SECTION *conf, void **instance)
{
	redis_driver_conf_t	*this;
	int			ret;

	*instance = NULL;

	if (cf_section_rules_push(conf, redis_config) < 0) return -1;

	this = talloc_zero(ctx, redis_driver_conf_t);
	if (!this) return -1;

	ret = cf_section_parse(this, &this->conf, conf);
	if (ret < 0) {
		talloc_free(this);
		return -1;
	}

	this->cluster = fr_redis_cluster_alloc(this, conf, &this->conf, false,
					       "rlm_redis_ippool_tool", NULL, NULL);
	if (!this->cluster) {
		talloc_free(this);
		return -1;
	}
	*instance = this;

	return 0;
}

/** Convert an IP range or CIDR mask to a start and stop address
 *
 * @param[out] start_out Where to write the start address.
 * @param[out] end_out Where to write the end address.
 * @param[in] ip_str Unparsed IP string.
 * @param[in] prefix length of prefixes we'll be allocating.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int parse_ip_range(fr_ipaddr_t *start_out, fr_ipaddr_t *end_out, char const *ip_str, uint8_t prefix)
{
	fr_ipaddr_t	start, end;
	bool		ex_broadcast;
	char const	*p;

	p = strchr(ip_str, '-');
	if (p) {
		char	start_buff[INET6_ADDRSTRLEN + 4];
		char	end_buff[INET6_ADDRSTRLEN + 4];
		size_t	len;

		if ((size_t)(p - ip_str) >= sizeof(start_buff)) {
			ERROR("Start address too long");
			return -1;
		}

		len = strlcpy(start_buff, ip_str, (p - ip_str) + 1);
		if (is_truncated(len, sizeof(start_buff))) {
			ERROR("Start address too long");
			return -1;
		}

		len = strlcpy(end_buff, p + 1, sizeof(end_buff));
		if (is_truncated(len, sizeof(end_buff))) {
			ERROR("End address too long");
			return -1;
		}

		if (fr_inet_pton(&start, start_buff, -1, AF_UNSPEC, false, true) < 0) {
			PERROR("Failed parsing \"%s\" as start address", start_buff);
			return -1;
		}

		if (fr_inet_pton(&end, end_buff, -1, AF_UNSPEC, false, true) < 0) {
			PERROR("Failed parsing \"%s\" end address", end_buff);
			return -1;
		}

		if (start.af != end.af) {
			ERROR("Start and end address must be of the same address family");
			return -1;
		}

		if (!prefix) prefix = IPADDR_LEN(start.af);

		/*
		 *	IPv6 addresses
		 */
		if (start.af == AF_INET6) {
			uint128_t start_int, end_int;

			memcpy(&start_int, start.addr.v6.s6_addr, sizeof(start_int));
			memcpy(&end_int, end.addr.v6.s6_addr, sizeof(end_int));
			if (uint128_gt(ntohlll(start_int), ntohlll(end_int))) {
				ERROR("End address must be greater than or equal to start address");
				return -1;
			}
		/*
		 *	IPv4 addresses
		 */
		} else {
			if (ntohl((uint32_t)(start.addr.v4.s_addr)) >
			    ntohl((uint32_t)(end.addr.v4.s_addr))) {
			 	ERROR("End address must be greater than or equal to start address");
			 	return -1;
			}
		}

		/*
		 *	Mask start and end so we can do prefix ranges too
		 */
		fr_ipaddr_mask(&start, prefix);
		fr_ipaddr_mask(&end, prefix);
		start.prefix = prefix;
		end.prefix = prefix;

		*start_out = start;
		*end_out = end;

		return 0;
	}

	if (fr_inet_pton(&start, ip_str, -1, AF_UNSPEC, false, false) < 0) {
		ERROR("Failed parsing \"%s\" as IPv4/v6 subnet", ip_str);
		return -1;
	}

	if (!prefix) prefix = IPADDR_LEN(start.af);

	if (prefix < start.prefix) {
		ERROR("-p must be greater than or equal to /<mask> (%u)", start.prefix);
		return -1;
	}
	if (prefix > IPADDR_LEN(start.af)) {
		ERROR("-p must be less than or equal to address length (%u)", IPADDR_LEN(start.af));
		return -1;
	}

	if ((prefix - start.prefix) > 64) {
		ERROR("-p must be less than or equal to %u", start.prefix + 64);
		return -1;
	}

	/*
	 *	Exclude the broadcast address only if we're dealing with IPv4 addresses
	 *	if we're allocating IPv6 addresses or prefixes we don't need to.
	 */
	ex_broadcast = (start.af == AF_INET) && (IPADDR_LEN(start.af) == prefix);

	/*
	 *	Excluding broadcast, 31/32 or 127/128 start/end are the same
	 */
	if (ex_broadcast && (start.prefix >= (IPADDR_LEN(start.af) - 1))) {
		*start_out = start;
		*end_out = start;
		return 0;
	}

	/*
	 *	Set various fields (we only overwrite the IP later)
	 */
	end = start;

	if (start.af == AF_INET6) {
		uint128_t ip, p_mask;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 128))) return -1;

		/* Don't be tempted to cast */
		memcpy(&ip, start.addr.v6.s6_addr, sizeof(ip));
		ip = ntohlll(ip);

		/* Generate a mask that covers the prefix bits, and sets them high */
		p_mask = uint128_lshift(uint128_gen_mask(prefix - start.prefix), (128 - prefix));
		ip = htonlll(uint128_bor(p_mask, ip));

		/* Decrement by one */
		if (ex_broadcast) ip = uint128_sub(ip, uint128_new(0, 1));
		memcpy(&end.addr.v6.s6_addr, &ip, sizeof(end.addr.v6.s6_addr));
	} else {
		uint32_t ip;

		/* cond assert to satisfy clang scan */
		if (!fr_cond_assert((prefix > 0) && (prefix <= 32))) return -1;

		ip = ntohl(start.addr.v4.s_addr);

		/* Generate a mask that covers the prefix bits and sets them high */
		ip |= uint32_gen_mask(prefix - start.prefix) << (32 - prefix);

		/* Decrement by one */
		if (ex_broadcast) ip--;
		end.addr.v4.s_addr = htonl(ip);
	}

	*start_out = start;
	*end_out = end;

	return 0;
}

int main(int argc, char *argv[])
{
	static ippool_tool_operation_t	ops[128];
	ippool_tool_operation_t		*p = ops, *end = ops + (sizeof(ops) / sizeof(*ops));

	int				c;

	uint8_t				*range_arg = NULL;
	uint8_t				*pool_arg = NULL;
	bool				do_export = false, print_stats = false, list_pools = false;
	bool				need_pool = false;
	char				*do_import = NULL;
	char const			*filename = NULL;

	CONF_SECTION			*pool_cs;
	CONF_PAIR			*cp;
	ippool_tool_t			*conf;

	fr_debug_lvl = 0;
	rad_debug_lvl = 0;
	name = argv[0];

	conf = talloc_zero(NULL, ippool_tool_t);
	conf->cs = cf_section_alloc(conf, NULL, "main", NULL);
	if (!conf->cs) exit(EXIT_FAILURE);

#define ADD_ACTION(_action) \
do { \
	if (p >= end) { \
		ERROR("Too many actions, max is " STRINGIFY(sizeof(ops))); \
		usage(64); \
	} \
	p->action = _action; \
	p->name = optarg; \
	p++; \
	need_pool = true; \
} while (0);

	while ((c = getopt(argc, argv, "a:d:r:s:Sm:p:ilLhxo:f:")) != -1) switch (c) {
		case 'a':
			ADD_ACTION(IPPOOL_TOOL_ADD);
			break;

		case 'd':
			ADD_ACTION(IPPOOL_TOOL_REMOVE);
			break;

		case 'r':
			ADD_ACTION(IPPOOL_TOOL_RELEASE);
			break;

		case 's':
			ADD_ACTION(IPPOOL_TOOL_SHOW);
			break;

		case 'm':
			ADD_ACTION(IPPOOL_TOOL_MODIFY);
			break;

		case 'p':
		{
			unsigned long tmp;
			char *q;

			if (p == ops) {
				ERROR("Prefix may only be specified after a pool management action");
				usage(64);
			}

			tmp = strtoul(optarg, &q, 10);
			if (q != (optarg + strlen(optarg))) {
				ERROR("Prefix must be an integer value");

			}

			(p - 1)->prefix = (uint8_t)tmp & 0xff;
		}
			break;

		case 'i':
			do_import = optarg;
			break;

		case 'I':
			do_export = true;
			break;

		case 'l':
			if (list_pools) usage(1);	/* Only allowed once */
			list_pools = true;
			break;

		case 'S':
			print_stats = true;
			break;

		case 'h':
			usage(0);

		case 'x':
			fr_debug_lvl++;
			rad_debug_lvl++;
			break;

		case 'o':
			break;

		case 'f':
			filename = optarg;
			break;

		default:
			usage(1);
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		ERROR("Need server address/port");
		usage(64);
	}
	if ((argc == 1) && need_pool) {
		ERROR("Need pool to operate on");
		usage(64);
	}
	if (argc > 3) usage(64);

	/*
	 *	Read configuration files if necessary.
	 */
	if (filename && (cf_file_read(conf->cs, filename) < 0 || (cf_section_pass2(conf->cs) < 0))) {
		exit(EXIT_FAILURE);
	}

	cp = cf_pair_alloc(conf->cs, "server", argv[0], T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	if (!cp) {
		ERROR("Failed creating server pair");
		exit(EXIT_FAILURE);
	}
	cf_pair_add(conf->cs, cp);

	/*
	 *	Unescape sequences in the pool name
	 */
	if (argv[1] && (argv[1][0] != '\0')) {
		uint8_t	*arg;
		size_t	len;

		/*
		 *	Be forgiving about zero length strings...
		 */
		len = strlen(argv[1]);
		MEM(arg = talloc_array(conf, uint8_t, len));
		len = fr_value_str_unescape(arg, argv[1], len, '"');
		rad_assert(len);

		MEM(pool_arg = talloc_realloc(conf, arg, uint8_t, len));
	}

	if (argc >= 3 && (argv[2][0] != '\0')) {
		uint8_t	*arg;
		size_t	len;

		len = strlen(argv[2]);
		MEM(arg = talloc_array(conf, uint8_t, len));
		len = fr_value_str_unescape(arg, argv[2], len, '"');
		rad_assert(len);

		MEM(range_arg = talloc_realloc(conf, arg, uint8_t, len));
	}

	if (!do_import && !do_export && !list_pools && !print_stats && (p == ops)) {
		ERROR("Nothing to do!");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Set some alternative default pool settings
	 */
	pool_cs = cf_section_find(conf->cs, "pool", NULL);
	if (!pool_cs) {
		pool_cs = cf_section_alloc(conf->cs, conf->cs, "pool", NULL);
	}
	cp = cf_pair_find(pool_cs, "start");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "start", "0", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
		cf_pair_add(pool_cs, cp);
	}
	cp = cf_pair_find(pool_cs, "spare");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "spare", "0", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
		cf_pair_add(pool_cs, cp);
	}
	cp = cf_pair_find(pool_cs, "min");
	if (!cp) {
		cp = cf_pair_alloc(pool_cs, "min", "0", T_OP_EQ, T_BARE_WORD, T_BARE_WORD);
		cf_pair_add(pool_cs, cp);
	}

	if (driver_init(conf, conf->cs, &conf->driver) < 0) {
		ERROR("Driver initialisation failed");
		exit(EXIT_FAILURE);
	}

	if (do_import) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (do_export) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (print_stats) {
		ippool_tool_stats_t	stats;
		uint8_t			**pools;
		ssize_t			slen;
		size_t			i;

		if (pool_arg) {
			pools = talloc_zero_array(conf, uint8_t *, 1);
			slen = 1;
			pools[0] = pool_arg;
		} else {
			slen = driver_get_pools(conf, &pools, conf->driver);
			if (slen < 0) exit(EXIT_FAILURE);
		}

		for (i = 0; i < (size_t)slen; i++) {
			char *pool_str;
			uint64_t acum = 0;

			if (driver_get_stats(&stats, conf->driver,
					     pools[i], talloc_array_length(pools[i])) < 0) exit(EXIT_FAILURE);

			pool_str = fr_asprint(conf, (char *)pools[i], talloc_array_length(pools[i]), '"');
			INFO("pool             : %s", pool_str);
			talloc_free(pool_str);

			INFO("total            : %" PRIu64, stats.total);
			INFO("free             : %" PRIu64, stats.free);
			INFO("used             : %" PRIu64, stats.total - stats.free);
			if (stats.total) {
				INFO("used (%%)         : %.2Lf",
				     ((long double)(stats.total - stats.free) / (long double)stats.total) * 100);
			} else {
				INFO("used (%%)         : 0");
			}
			INFO("expiring 0-1m    : %" PRIu64, stats.expiring_1m);
			acum += stats.expiring_1m;
			INFO("expiring 1-30m   : %" PRIu64, stats.expiring_30m - acum);
			acum += stats.expiring_30m;
			INFO("expiring 30m-1h  : %" PRIu64, stats.expiring_1h - acum);
			acum += stats.expiring_1h;
			INFO("expiring 1h-1d   : %" PRIu64, stats.expiring_1d - acum);
			INFO("--");
		}
	}

	if (list_pools) {
		ssize_t		slen;
		size_t		i;
		uint8_t 	**pools;

		slen = driver_get_pools(conf, &pools, conf->driver);
		if (slen < 0) exit(EXIT_FAILURE);
		if (slen > 0) {
			for (i = 0; i < (size_t)slen; i++) {
				char *pool_str;

				pool_str = fr_asprint(conf, (char *)pools[i], talloc_array_length(pools[i]), '"');
				INFO("%s", pool_str);
				talloc_free(pool_str);
			}
			INFO("--");
		}

		talloc_free(pools);
	}

	/*
	 *	Fixup the operations without specific pools or ranges
	 *	and parse the IP ranges.
	 */
	end = p;
	for (p = ops; p < end; p++) {
		if (parse_ip_range(&p->start, &p->end, p->name, p->prefix) < 0) usage(64);
		if (!p->prefix) p->prefix = IPADDR_LEN(p->start.af);

		if (!p->pool) {
			p->pool = pool_arg;
			p->pool_len = talloc_array_length(pool_arg);
		}
		if (!p->range && range_arg) {
			p->range = range_arg;
			p->range_len = talloc_array_length(range_arg);
		}
	}

	for (p = ops; (p < end) && (p->start.af != AF_UNSPEC); p++) switch (p->action) {
	case IPPOOL_TOOL_ADD:
	{
		uint64_t count = 0;

		if (driver_add_lease(&count, conf->driver, p) < 0) {
			exit(EXIT_FAILURE);
		}
		INFO("Added %" PRIu64 " address(es)/prefix(es)", count);
	}
		break;

	case IPPOOL_TOOL_REMOVE:
	{
		uint64_t count = 0;

		if (driver_remove_lease(&count, conf->driver, p) < 0) {
			exit(EXIT_FAILURE);
		}
		INFO("Removed %" PRIu64 " address(es)/prefix(es)", count);
	}
		continue;

	case IPPOOL_TOOL_RELEASE:
	{
		uint64_t count = 0;

		if (driver_release_lease(&count, conf->driver, p) < 0) {
			exit(EXIT_FAILURE);
		}
		INFO("Released %" PRIu64 " address(es)/prefix(es)", count);
	}
		continue;

	case IPPOOL_TOOL_SHOW:
	{
		ippool_tool_lease_t **leases = NULL;
		size_t len, i;

		if (driver_show_lease(&leases, conf->driver, p) < 0) {
			exit(EXIT_FAILURE);
		}
		rad_assert(leases);

		len = talloc_array_length(leases);
		INFO("Retrieved information for %zu address(es)/prefix(es)", len - 1);
		for (i = 0; i < (len - 1); i++) {
			char	ip_buff[FR_IPADDR_PREFIX_STRLEN];
			char	time_buff[30];
			struct	tm tm;
			struct	timeval now;
			char	*device = NULL;
			char	*gateway = NULL;
			char	*range = NULL;
			bool	is_active;

			leases[i] = talloc_get_type_abort(leases[i], ippool_tool_lease_t);

			now = fr_time_to_timeval(fr_time());
			is_active = now.tv_sec <= leases[i]->next_event;
			if (leases[i]->next_event) {
				strftime(time_buff, sizeof(time_buff), "%b %e %Y %H:%M:%S %Z",
					 localtime_r(&(leases[i]->next_event), &tm));
			} else {
				time_buff[0] = '\0';
			}
			IPPOOL_SPRINT_IP(ip_buff, &(leases[i]->ipaddr), leases[i]->ipaddr.prefix);

			if (leases[i]->range) {
				range = fr_asprint(leases, (char const *)leases[i]->range,
						   leases[i]->range_len, '\0');
			}

			INFO("--");
			if (range) INFO("range           : %s", range);
			INFO("address/prefix  : %s", ip_buff);
			INFO("active          : %s", is_active ? "yes" : "no");

			if (leases[i]->device) {
				device = fr_asprint(leases, (char const *)leases[i]->device,
						    leases[i]->device_len, '\0');
			}
			if (leases[i]->gateway) {
				gateway = fr_asprint(leases, (char const *)leases[i]->gateway,
						     leases[i]->gateway_len, '\0');
			}
			if (is_active) {
				if (*time_buff) INFO("lease expires   : %s", time_buff);
				if (device) INFO("device id       : %s", device);
				if (gateway) INFO("gateway id      : %s", gateway);
			} else {
				if (*time_buff) INFO("lease expired   : %s", time_buff);
				if (device) INFO("last device id  : %s", device);
				if (gateway) INFO("last gateway id : %s", gateway);
			}
		}
		talloc_free(leases);
	}
		continue;

	case IPPOOL_TOOL_MODIFY:
	{
		uint64_t count = 0;

		if (driver_modify_lease(&count, conf->driver, p) < 0) {
			exit(EXIT_FAILURE);
		}
		INFO("Modified %" PRIu64 " address(es)/prefix(es)", count);
	}
		continue;

	case IPPOOL_TOOL_NOOP:
		break;
	}

	talloc_free(conf);

	return 0;
}
