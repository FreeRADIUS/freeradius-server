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
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/rad_assert.h>

#include "redis.h"
#include "cluster.h"
#include "redis_ippool.h"

#define IPADDR_LEN(_af) ((_af == AF_UNSPEC) ? 0 : ((_af == AF_INET6) ? 128 : 32))
#define MAX_PIPELINED 1000

#include <sys/wait.h>

#undef rad_waitpid
pid_t rad_fork(void)
{
	return fork();
}

pid_t rad_waitpid(pid_t pid, int *status)
{
	return waitpid(pid, status, 0);
}

/** Pool management actions
 *
 */
typedef enum ippool_tool_action {
	IPPOOL_TOOL_NOOP = 0,
	IPPOOL_TOOL_ADD,
	IPPOOL_TOOL_REMOVE,
	IPPOOL_TOOL_RELEASE,
	IPPOOL_TOOL_SHOW
} ippool_tool_action_t;

/** net and prefix associated with an action
 *
 */
typedef struct ippool_tool_net {
	fr_ipaddr_t		net;		//!< Base network address.
	uint8_t			prefix;		//!< Prefix - The bits between the address mask, and the prefix
						//!< form the addresses to be modified in the pool.
	ippool_tool_action_t	action;		//!< What to do to the leases described by net/prefix.
} ippool_tool_operation_t;

typedef struct ippool_tool_lease {
	fr_ipaddr_t		ipaddr;		//!< Prefix or address.
	time_t			next_event;	//!< Last state change.
	uint8_t	const		*device_id;	//!< Last device id.
	size_t			device_id_len;
	uint8_t const		*gateway_id;	//!< Last gateway id.
	size_t			gateway_id_len;
} ippool_tool_lease_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

typedef struct redis_driver_conf {
	fr_redis_conf_t		conf;		//!< Connection parameters for the Redis server.
	fr_redis_cluster_t	*cluster;
} redis_driver_conf_t;

typedef struct ippool_tool {
	void			*driver;
	CONF_SECTION		*cs;
} ippool_tool_t;

typedef int (*redis_ippool_queue_t)(redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				    uint8_t const *key_prefix, size_t key_prefix_len, fr_ipaddr_t *ipaddr,
				    uint8_t prefix);

typedef int (*redis_ippool_process_t)(void *out, fr_ipaddr_t const *ipaddr, redisReply const *reply);

static char const *name;

static void NEVER_RETURNS usage(int ret) {
	INFO("Usage: %s [[-a|-r|-c] -p] [options] <server[:port]> <pool>", name);
	INFO("Pool management:");
	INFO("  -a <addr>[/<cidr>]     Add addresses/prefixes to the pool");
	INFO("  -r <addr>[/<cidr>]     Remove addresses/prefixes in this range");
	INFO("  -c <addr>[/<cidr>]     Release addresses/prefixes in this range");
	INFO("  -s <addr>[/<cidr>]     Show addresses/prefix in this range");
	INFO("  -p <prefix_len>        Length of prefix to allocate (defaults to 32/128)");
//	INFO("  -i <file>              Import entries from ISC lease file [NYI]");
	INFO(" ");	/* -Werror=format-zero-length */
//	INFO("Pool status:");
//	INFO("  -I                     Output active entries in ISC lease file format [NYI]");
//	INFO("  -S                     Print pool statistics [NYI]");
	INFO(" ");	/* -Werror=format-zero-length */
	INFO("Configuration:");
	INFO("  -h                     Print this help message and exit");
	INFO("  -x                     Increase the verbosity level");
//	INFO("  -o <attr>=<value>      Set option, these are specific to the backends [NYI]");
	INFO("  -f <file>              Load options from a FreeRADIUS style config file");

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
static uint128_t uint128_lshift(uint128_t num, bits)
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
static uint128_t uint128_add(uint128 a, uint128 b)
{
    	uint64_t tmp = (((a.l & b.l) & 1) + (a.l >> 1) + (b.l >> 1)) >> 63;
    	return { .l = a.l + b.l, .h = a.h + b.h + tmp };
}

/** Perform bitwise & of two 128bit unsigned integers
 *
 */
static uint128_t uint128_band(uint128_t a, uint128_t b)
{
	return { .l = a.l & b.l, .h = a.h & b.h };
}

/** Return whether the integers are equal
 *
 */
static bool uint128_eq(uint128_t a, uint128_t b) {
	return (a.h == b.h) && (a.l == b.l);
}
#else
static uint128_t uint128_gen_mask(uint8_t bits)
{
	if (bits >= 128) return ~(uint128_t)0x00;
	return (1 << bits) - 1;
}
#define uint128_lshift(_num, _bits) (_num << _bits)
#define uint128_band(_a, _b) (_a & _b)
#define uint128_eq(_a, _b) (_a == _b)
#define uint128_add(_a, _b) (_a + _b)
#endif

/** Iterate over range of IP addresses
 *
 * Mutates the ipaddr passed in, adding one to the prefix bits on each call.
 *
 * @param[in,out] ipaddr to increment.
 * @param[in] prefix Length of the prefix.
 * @return
 *	- true if the prefix bits are not high (continue).
 *	- false if the prefix bits are high (stop).
 */
static bool ipaddr_next(fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	/*
	 *	Single IP addresses
	 */
	if (prefix == ipaddr->prefix) return false;

	rad_assert(prefix > ipaddr->prefix);

	switch (ipaddr->af) {
	default:
	case AF_UNSPEC:
		rad_assert(0);
		return false;

	case AF_INET6:
	{
		uint128_t ip, p_mask, p_curr;

		rad_assert((prefix > 0) && (prefix <= 128));

		/* Don't be tempted to cast */
		memcpy(&ip, ipaddr->ipaddr.ip6addr.s6_addr, sizeof(ip));

		ip = ntohlll(ip);

		/* Generate a mask that covers the prefix bits */
		p_mask = uint128_gen_mask(prefix - ipaddr->prefix) << (128 - prefix);
		p_curr = uint128_band(ip, p_mask);

		/* Stopping condition - all prefix bits high (and busy attempting to locate maltesers) */
		if (uint128_eq(p_mask, p_curr)) return false;

		/* Increment the prefix */
		ip = uint128_add(ip, uint128_lshift((uint128_t)1, (128 - prefix)));
		ip = htonlll(ip);
		memcpy(&ipaddr->ipaddr.ip6addr.s6_addr, &ip, sizeof(ipaddr->ipaddr.ip6addr.s6_addr));
		return true;
	}

	case AF_INET:
	{
		uint32_t ip, p_mask, p_curr;

		rad_assert((prefix > 0) && (prefix <= 32));

		ip = ntohl(ipaddr->ipaddr.ip4addr.s_addr);

		/* Generate a mask that covers the prefix bits */
		p_mask = uint32_gen_mask(prefix - ipaddr->prefix) << (32 - prefix);
		p_curr = ip & p_mask;

		/* Stopping condition (all prefix bits high) */
		if (p_curr == p_mask) return false;

		/* Increment the prefix */
		ip += 1 << (32 - prefix);
		ipaddr->ipaddr.ip4addr.s_addr = htonl(ip);
		return true;
	}
	}
}

/** Add a net to the pool
 *
 * @return the number of new addresses added.
 */
static int driver_do_lease(void *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len,
			   fr_ipaddr_t const *net, uint8_t prefix,
			   redis_ippool_queue_t enqueue, redis_ippool_process_t process)
{
	redis_driver_conf_t		*inst = talloc_get_type_abort(instance, redis_driver_conf_t);

	int				i;
	bool				more = true;
	fr_redis_conn_t			*conn;

	fr_redis_cluster_state_t	state;
	fr_redis_rcode_t		status;

	fr_ipaddr_t			ipaddr = *net, acked;
	int				s_ret = REDIS_RCODE_SUCCESS;
	REQUEST				*request = request_alloc(inst);
	redisReply			**replies = NULL;


	while (more) {
		size_t	reply_cnt = 0;

		/* Record our progress */
		acked = ipaddr;
		for (s_ret = fr_redis_cluster_state_init(&state, &conn, inst->cluster, request, key_prefix,
							 key_prefix_len, false);
		     s_ret == REDIS_RCODE_TRY_AGAIN;
		     s_ret = fr_redis_cluster_state_next(&state, &conn, inst->cluster, request, status, &replies[0])) {
		     	int	pipelined = 0;

			status = REDIS_RCODE_SUCCESS;

			/*
			 *	If we got a redirect, start back at the beginning of the block.
			 */
			if (s_ret == REDIS_RCODE_TRY_AGAIN) ipaddr = acked;

			/*
			 *	Iterate over all possible prefixes (or IP addresses)
			 */
			for (i = 0; (i < MAX_PIPELINED) && more; i++, more = ipaddr_next(&ipaddr, prefix)) {
				int enqueued;

				enqueued = enqueue(inst, conn, key_prefix, key_prefix_len, &ipaddr, prefix);
				if (enqueued < 0) break;
				pipelined += enqueued;
			}

			if (!replies) replies = talloc_zero_array(inst, redisReply *, pipelined);
			if (!replies) return 0;

			reply_cnt = fr_redis_pipeline_result(&status, replies,
							     talloc_array_length(replies), conn, pipelined);
			for (i = 0; (size_t)i < reply_cnt; i++) fr_redis_reply_print(L_DBG_LVL_3,
										     replies[i], request, i);
		}
		if (s_ret != REDIS_RCODE_SUCCESS) {
			fr_redis_pipeline_free(replies, reply_cnt);
			talloc_free(replies);
			return -1;
		}

		if (process) {
			fr_ipaddr_t to_process = acked;

			for (i = 0; (size_t)i < reply_cnt; i++) {
				int ret;

				ret = process(out, &to_process, replies[i]);
				if (ret < 0) continue;
				ipaddr_next(&to_process, prefix);
			}
		}
		fr_redis_pipeline_free(replies, reply_cnt);
		talloc_free(replies);
	}

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
	if (reply->elements < 3) return -1;

	if (reply->element[0]->type != REDIS_REPLY_STRING) return -1;
	lease = talloc_zero(*modified, ippool_tool_lease_t);
	lease->ipaddr = *ipaddr;
	lease->next_event = (time_t)strtoull(reply->element[0]->str, NULL, 10);

	if (reply->element[1]->type == REDIS_REPLY_STRING) {
		lease->device_id = talloc_memdup(lease, reply->element[1]->str, reply->element[1]->len);
		lease->device_id_len = reply->element[1]->len;
	}
	if (reply->element[2]->type == REDIS_REPLY_STRING) {
		lease->gateway_id = talloc_memdup(lease, reply->element[2]->str, reply->element[2]->len);
		lease->gateway_id_len = reply->element[2]->len;
	}
	existing = talloc_array_length(*modified);
	*modified = talloc_realloc(NULL, *modified, ippool_tool_lease_t *, existing + 1);
	(*modified)[existing - 1] = lease;

	return 0;
}

/** Enqueue commands to retrieve lease information
 *
 */
static int _driver_show_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				      uint8_t const *key_prefix, size_t key_prefix_len,
				      fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[INET6_ADDRSTRLEN + 4];

	uint8_t		ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t		*ip_key_p = ip_key;

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);
	IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_buff);

	DEBUG("Retrieving lease info for %s from pool %s", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "MULTI");
	redisAppendCommand(conn->handle, "ZSCORE %b %s", key, key_p - key, ip_buff);
	redisAppendCommand(conn->handle, "HGET %b device_id", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "HGET %b gateway_id", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "EXEC");
	return 5;
}

/** Show information about leases
 *
 */
static inline int driver_show_lease(void *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len,
				    fr_ipaddr_t const *net, uint8_t prefix)
{
	return driver_do_lease(out, instance, key_prefix, key_prefix_len, net, prefix,
			       _driver_show_lease_enqueue, _driver_show_lease_process);
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
					 fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;

	char		ip_buff[INET6_ADDRSTRLEN + 4];

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);

	DEBUG("Releasing %s to pool %s", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "ZADD %b XX CH 0 %s", key, key_p - key, ip_buff);
	return 1;
}

/** Release a range of leases
 *
 */
static inline int driver_release_lease(void *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len,
				       fr_ipaddr_t const *net, uint8_t prefix)
{
	return driver_do_lease(out, instance, key_prefix, key_prefix_len, net, prefix,
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

/** Enqueue lease removal commands
 *
 * This removes the lease from the expiry heap, and the data associated with
 * the lease.
 */
static int _driver_remove_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
					uint8_t const *key_prefix, size_t key_prefix_len,
					fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[INET6_ADDRSTRLEN + 4];

	uint8_t		ip_key[IPPOOL_MAX_IP_KEY_SIZE];
	uint8_t		*ip_key_p = ip_key;

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);
	IPPOOL_BUILD_IP_KEY_FROM_STR(ip_key, ip_key_p, key_prefix, key_prefix_len, ip_buff);

	DEBUG("Removing %s from pool %s, and removing hash at %s", ip_buff, key_prefix, ip_key);
	redisAppendCommand(conn->handle, "MULTI");
	redisAppendCommand(conn->handle, "ZREM %b %s", key, key_p - key, ip_buff);
	redisAppendCommand(conn->handle, "DEL %b", ip_key, ip_key_p - ip_key);
	redisAppendCommand(conn->handle, "EXEC");
	return 4;
}

/** Remove a range of leases
 *
 */
static int driver_remove_lease(void *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len,
			       fr_ipaddr_t const *net, uint8_t prefix)
{
	return driver_do_lease(out, instance, key_prefix, key_prefix_len, net, prefix,
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
	if (reply->type != REDIS_REPLY_INTEGER) return -1;

	*modified += reply->integer;
	return 0;
}

/** Enqueue lease addition commands
 *
 */
static int _driver_add_lease_enqueue(UNUSED redis_driver_conf_t *inst, fr_redis_conn_t *conn,
				     uint8_t const *key_prefix, size_t key_prefix_len,
				     fr_ipaddr_t *ipaddr, uint8_t prefix)
{
	uint8_t		key[IPPOOL_MAX_POOL_KEY_SIZE];
	uint8_t		*key_p = key;
	char		ip_buff[INET6_ADDRSTRLEN + 4];

	IPPOOL_BUILD_KEY(key, key_p, key_prefix, key_prefix_len);
	IPPOOL_SPRINT_IP(ip_buff, ipaddr, prefix);

	DEBUG("Adding %s to pool %s", ip_buff, key_prefix);
	redisAppendCommand(conn->handle, "ZADD %b NX %u %s", key, key_p - key, 0, ip_buff);
	return 1;
}

/** Add a range of prefixes
 *
 */
static int driver_add_lease(void *out, void *instance, uint8_t const *key_prefix, size_t key_prefix_len,
	                    fr_ipaddr_t const *net, uint8_t prefix)
{
	return driver_do_lease(out, instance, key_prefix, key_prefix_len, net, prefix,
			       _driver_add_lease_enqueue, _driver_add_lease_process);
}

/** Driver initialization function
 *
 */
static int driver_init(TALLOC_CTX *ctx, CONF_SECTION *conf, void **instance)
{
	redis_driver_conf_t	*this;
	int			ret;

	*instance = NULL;

	this = talloc_zero(ctx, redis_driver_conf_t);
	if (!this) return -1;

	ret = cf_section_parse(conf, &this->conf, redis_config);
	if (ret < 0) {
		talloc_free(this);
		return -1;
	}

	this->cluster = fr_redis_cluster_alloc(this, conf, &this->conf);
	if (!this->cluster) {
		talloc_free(this);
		return -1;
	}
	*instance = this;

	return 0;
}

int main(int argc, char *argv[])
{
	static ippool_tool_operation_t	nets[128];
	ippool_tool_operation_t		*p = nets, *end = nets + (sizeof(nets) / sizeof(*nets));

	int				opt;

	char const			*pool;
	bool				do_export = false, print_stats = false;
	char				*do_import = NULL;

	CONF_SECTION			*pool_cs;
	CONF_PAIR			*cp;
	ippool_tool_t			*conf;

	fr_debug_lvl = 1;
	name = argv[0];

	conf = talloc_zero(NULL, ippool_tool_t);
	conf->cs = cf_section_alloc(NULL, "main", NULL);
	if (!conf->cs) exit(1);

	exec_trigger_set_conf(conf->cs);

#define ADD_ACTION(_action) \
do { \
	if ((size_t)(p - nets) >= sizeof(nets)) { \
		ERROR("Too many actions, max is " STRINGIFY(sizeof(nets))); \
		usage(64); \
	} \
	if (fr_pton(&p->net, optarg, -1, AF_UNSPEC, false, false) < 0) { \
		ERROR("Failed parsing -a %s as IPv4/v6 subnet", optarg); \
		usage(64); \
	} \
	p->action = _action; \
	p->prefix = IPADDR_LEN(p->net.af); \
	p++; \
} while (0);

	while ((opt = getopt(argc, argv, "a:r:c:s:p:ihxo:f:")) != EOF)
	switch (opt) {
	case 'a':
		ADD_ACTION(IPPOOL_TOOL_ADD);
		break;

	case 'r':
		ADD_ACTION(IPPOOL_TOOL_REMOVE);
		break;

	case 'c':
		ADD_ACTION(IPPOOL_TOOL_RELEASE);
		break;

	case 's':
		ADD_ACTION(IPPOOL_TOOL_SHOW);
		break;

	case 'p':
	{
		unsigned long tmp;
		uint8_t prefix;
		char *q;

		if (p == nets) {
			ERROR("Prefix may only be specified after a pool management action");
			usage(64);
		}

		tmp = strtoul(optarg, &q, 10);
		if (q != (optarg + strlen(optarg))) {
			ERROR("Prefix must be an integer value");

		}

		prefix = (uint8_t)tmp & 0xff;

		if (prefix < (p - 1)->net.prefix) {
			ERROR("-p must be greater than or equal to /<mask> (%u)", (p - 1)->net.prefix);
			usage(64);
		}
		if (prefix > IPADDR_LEN((p - 1)->net.af)) {
			ERROR("-p must be less than or equal to address length (%u)", IPADDR_LEN((p - 1)->net.af));
			usage(64);
		}
		(p - 1)->prefix = prefix;

		if ((prefix - (p - 1)->prefix) > 64) {
			ERROR("-p must be less than or equal to %u", (p - 1)->prefix + 64);
			usage(64);
		}
	}
		break;

	case 'i':
		do_import = optarg;
		break;

	case 'I':
		do_export = true;
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
		if (cf_file_read(conf->cs, optarg) < 0) exit(1);

	default:
		usage(1);
	}
	argc -= optind;
	argv += optind;

	if (argc < 2) {
		ERROR("Need server and pool name");
		usage(64);
	}
	if (argc > 2) usage(64);

	cp = cf_pair_alloc(conf->cs, "server", argv[0], T_OP_EQ, T_BARE_WORD, T_DOUBLE_QUOTED_STRING);
	if (!cp) {
		ERROR("Failed creating server pair");
		exit(1);
	}
	cf_pair_add(conf->cs, cp);
	pool = argv[1];

	if (p == nets) {
		ERROR("Nothing to do!");
		exit(1);
	}

	/*
	 *	Set some alternative default pool settings
	 */
	pool_cs = cf_section_sub_find(conf->cs, "pool");
	if (!pool_cs) {
		pool_cs = cf_section_alloc(conf->cs, "pool", NULL);
		cf_section_add(conf->cs, pool_cs);
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

	if (driver_init(conf, conf->cs, &conf->driver) < 0) exit(1);

	for (p = nets; (p < end) && (p->net.af != AF_UNSPEC); p++) switch (p->action) {
	case IPPOOL_TOOL_ADD:
	{
		uint64_t count = 0;

		if (driver_add_lease(&count, conf->driver, (uint8_t const *)pool,
				     strlen(pool), &p->net, p->prefix) < 0) {
			exit(1);
		}
		INFO("Added %" PRIu64 " addresses/prefixes", count);
	}
		break;

	case IPPOOL_TOOL_REMOVE:
	{
		uint64_t count = 0;

		if (driver_remove_lease(&count, conf->driver, (uint8_t const *)pool,
					strlen(pool), &p->net, p->prefix) < 0) {
			exit(1);
		}
		INFO("Removed %" PRIu64 " addresses/prefixes", count);
	}
		continue;

	case IPPOOL_TOOL_RELEASE:
	{
		uint64_t count = 0;

		if (driver_release_lease(&count, conf->driver, (uint8_t const *)pool,
					 strlen(pool), &p->net, p->prefix) < 0) {
			exit(1);
		}
		INFO("Released %" PRIu64 " addresses/prefixes", count);
	}
		continue;

	case IPPOOL_TOOL_SHOW:
	{
		ippool_tool_lease_t **leases = NULL;
		size_t len, i;

		if (driver_show_lease(&leases, conf->driver, (uint8_t const *)pool,
				      strlen(pool), &p->net, p->prefix) < 0) {
			exit(1);
		}

		len = talloc_array_length(leases);
		INFO("Retrieved information for %zu addresses/prefixes", len - 1);
		for (i = 0; i < (len - 1); i++) {
			char	ip_buff[INET6_ADDRSTRLEN + 4];
			char	time_buff[30];
			struct	tm tm;
			struct	timeval now;
			char	*device_id = NULL;
			char	*gateway_id = NULL;
			bool	is_active;

			talloc_get_type_abort(leases[i], ippool_tool_lease_t);

			gettimeofday(&now, NULL);
			is_active = now.tv_sec <= leases[i]->next_event;
			if (leases[i]->next_event) {
				strftime(time_buff, sizeof(time_buff), "%b %e %Y %H:%M:%S %Z",
					 localtime_r(leases[i]->next_event, &tm));
			} else {
				time_buff[0] = '\0';
			}
			IPPOOL_SPRINT_IP(ip_buff, &(leases[i]->ipaddr), leases[i]->ipaddr.prefix);

			INFO("--");
			INFO("address/prefix  : %s", ip_buff);
			INFO("active          : %s", is_active ? "yes" : "no");

			if (leases[i]->device_id) fr_asprint(conf, (char const *)leases[i]->device_id,
							     leases[i]->device_id_len, '\0');
			if (leases[i]->gateway_id) fr_asprint(conf, (char const *)leases[i]->gateway_id,
							      leases[i]->gateway_id_len, '\0');
			if (is_active) {
				INFO("lease expires   : %s", time_buff);
				if (*time_buff) INFO("lease expired   : %s", time_buff);
				if (device_id) INFO("device id       : %s", device_id);
				if (gateway_id) INFO("gateway id      : %s", gateway_id);
			} else {
				if (*time_buff) INFO("lease expired   : %s", time_buff);
				if (device_id) INFO("last device id  : %s", device_id);
				if (gateway_id) INFO("last gateway id : %s", gateway_id);
			}
		}
		talloc_free(leases);
	}
		continue;

	case IPPOOL_TOOL_NOOP:
		break;
	}

	if (do_import) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (do_export) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (print_stats) {
		ERROR("NOT YET IMPLEMENTED");
	}

	talloc_free(conf);

	return 0;
}
