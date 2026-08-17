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
 * @file rlm_redis_ippool_tool.c
 * @brief IP population tool.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 The FreeRADIUS server project
 */
RCSID("$Id$")
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/unlang/base.h>
#include <freeradius-devel/io/thread.h>

#include "base.h"
#include "redis_ippool.h"

#define EXIT_WITH_FAILURE \
do { \
	ret = EXIT_FAILURE; \
	goto cleanup; \
} while (0)

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t redis_ippool_tool_dict[];
fr_dict_autoload_t redis_ippool_tool_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_ippool;
static fr_dict_attr_t const *attr_ippool_name;
static fr_dict_attr_t const *attr_ippool_lease;
static fr_dict_attr_t const *attr_ippool_lease_address;
static fr_dict_attr_t const *attr_ippool_lease_active;
static fr_dict_attr_t const *attr_ippool_lease_expires;
static fr_dict_attr_t const *attr_ippool_lease_device;
static fr_dict_attr_t const *attr_ippool_lease_gateway;
static fr_dict_attr_t const *attr_ippool_lease_range;
static fr_dict_attr_t const *attr_ippool_stats;
static fr_dict_attr_t const *attr_ippool_stats_total;
static fr_dict_attr_t const *attr_ippool_stats_dynamic;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_total;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_free;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_expire1m;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_expire30m;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_expire1h;
static fr_dict_attr_t const *attr_ippool_stats_dynamic_expire1d;
static fr_dict_attr_t const *attr_ippool_stats_static;
static fr_dict_attr_t const *attr_ippool_stats_static_total;
static fr_dict_attr_t const *attr_ippool_stats_static_free;
static fr_dict_attr_t const *attr_ippool_stats_static_renew1m;
static fr_dict_attr_t const *attr_ippool_stats_static_renew30m;
static fr_dict_attr_t const *attr_ippool_stats_static_renew1h;
static fr_dict_attr_t const *attr_ippool_stats_static_renew1d;

extern fr_dict_attr_autoload_t redis_ippool_tool_dict_attr[];
fr_dict_attr_autoload_t redis_ippool_tool_dict_attr[] = {
	{ .out = &attr_ippool, .name = "IP-Pool", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_ippool_name, .name = "IP-Pool.Name", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease, .name = "IP-Pool.Lease", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_address, .name = "IP-Pool.Lease.Address", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_active, .name = "IP-Pool.Lease.Active", .type = FR_TYPE_BOOL, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_expires, .name = "IP-Pool.Lease.Expires", .type = FR_TYPE_DATE, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_device, .name = "IP-Pool.Lease.Device", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_gateway, .name = "IP-Pool.Lease.Gateway", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ippool_lease_range, .name = "IP-Pool.Lease.Range", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats, .name = "IP-Pool.Stats", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_total, .name = "IP-Pool.Stats.Total", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic, .name = "IP-Pool.Stats.Dynamic", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_total, .name = "IP-Pool.Stats.Dynamic.Total", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_free, .name = "IP-Pool.Stats.Dynamic.Free", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_expire1m, .name = "IP-Pool.Stats.Dynamic.Expire-1m", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_expire30m, .name = "IP-Pool.Stats.Dynamic.Expire-30m", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_expire1h, .name = "IP-Pool.Stats.Dynamic.Expire-1h", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_dynamic_expire1d, .name = "IP-Pool.Stats.Dynamic.Expire-1d", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static, .name = "IP-Pool.Stats.Static", .type = FR_TYPE_TLV, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_total, .name = "IP-Pool.Stats.Static.Total", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_free, .name = "IP-Pool.Stats.Static.Free", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_renew1m, .name = "IP-Pool.Stats.Static.Renew-1m", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_renew30m, .name = "IP-Pool.Stats.Static.Renew-30m", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_renew1h, .name = "IP-Pool.Stats.Static.Renew-1h", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	{ .out = &attr_ippool_stats_static_renew1d, .name = "IP-Pool.Stats.Static.Renew-1d", .type = FR_TYPE_UINT64, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

/** Pool management actions
 *
 */
typedef enum ippool_tool_action {
	IPPOOL_TOOL_NOOP = 0,			//!< Do nothing.
	IPPOOL_TOOL_ADD,			//!< Add one or more IP addresses.
	IPPOOL_TOOL_REMOVE,			//!< Remove one or more IP addresses.
	IPPOOL_TOOL_RELEASE,			//!< Release one or more IP addresses.
	IPPOOL_TOOL_SHOW,			//!< Show one or more IP addresses.
	IPPOOL_TOOL_MODIFY,			//!< Modify attributes of one or more IP addresses.
	IPPOOL_TOOL_ASSIGN,			//!< Assign a static IP address to a device.
	IPPOOL_TOOL_UNASSIGN			//!< Remove static IP address assignment.
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

static char const *name;

#define EOL "\n"

/** Static server config split into two parts
 *
 * The command line provided server value is inserted between
 * the two sections, along with an optional $INCLUDE if the -f option is provided
 */
static char server_conf1[] =
"thread { num_workers = 1}" EOL \
"trigger { }" EOL \
"client test { ipaddr = 127.0.0.1; secret = supersecret }" EOL \
"modules {" EOL \
"	redis_ippool {" EOL \
"		owner = request.IP-Pool.Lease.Device" EOL \
"		pool_name = control.IP-Pool.Name" EOL \
"		requested_address = IP-Pool.Lease.Address[*]" EOL \
"		redis {" EOL \
"			virtual_server = redis" EOL \
"			pool { start = 0 }" EOL;

static char server_conf2[] =
"		}" EOL \
"	}" EOL \
"}" EOL \
"server redis { namespace = redis } " EOL \
"server default {" EOL \
"	namespace = radius" EOL \
"	recv Access-Request { redis_ippool.stats }" EOL \
"	recv Accounting-Request { redis_ippool.show }" EOL \
"}";

static NEVER_RETURNS void usage(int ret) {
	INFO("Usage: %s -adrsm range... [-p prefix_len]... [-x]... [-oShf] server[:port] [pool] [range id]", name);
	INFO("Pool management:");
	INFO("  -a range               Add address(es)/prefix(es) to the pool.");
	INFO("  -d range               Delete address(es)/prefix(es) in this range.");
	INFO("  -r range               Release address(es)/prefix(es) in this range.");
	INFO("  -s range               Show addresses/prefix in this range.");
	INFO("  -A address/prefix      Assign a static lease.");
	INFO("  -O owner               To use when assigning a static lease.");
	INFO("  -U address/prefix      Un-assign a static lease");
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
	INFO("  -D dictdir             Set main dictionary directory (defaults to " DICTDIR);
	INFO("  -f file                Load connection options from a FreeRADIUS format config file");
	INFO("                         This file should contain one or more `server = <fqdn>` pairs`");
	INFO("                         and, optionally `port = <port>`, `password = secret`");
	INFO(" ");
	INFO("<range> is range \"127.0.0.1-127.0.0.254\" or CIDR network \"127.0.0.1/24\" or host \"127.0.0.1\"");
	INFO("CIDR host bits set start address, e.g. 127.0.0.200/24 -> 127.0.0.200-127.0.0.254");
	fr_exit_now(ret);
}

static uint32_t uint32_gen_mask(uint8_t bits)
{
	if (bits >= 32) return 0xffffffff;
	return (1U << bits) - 1;
}

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
		fr_assert(0);
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

/** Run the redis_ippool.stats module method to fetch pool statistics
 */
static int redis_ippool_get_stats(request_t *request, fr_value_box_t *pool_name,
				  CONF_SECTION *section, fr_event_list_t *el)
{
	rlm_rcode_t	rcode;
	fr_pair_t	*vp;

	/*
	 *	Make sure the control list is empty before pools.list populates it.
	 */
	fr_pair_list_free(&request->control_pairs);

	/*
	 *	Add the pool name for to fetch stats for
	 */
	MEM(vp = fr_pair_afrom_da_nested(request->control_ctx, &request->control_pairs, attr_ippool_name));
	if (fr_value_box_copy(vp, &vp->data, pool_name) < 0) return -1;

	if (unlang_interpret_push_section(NULL, request, section,
					  FRAME_CONF(RLM_MODULE_OK, UNLANG_TOP_FRAME)) < 0) return -1;

	rcode = unlang_interpret_synchronous(el, request);
	switch (rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return -1;

	default:
		return 0;
	}
}

/** Run the redis_ippool.show module method to fetch lease details
 */
static int redis_ippool_show(request_t *request, ippool_tool_operation_t const *op, CONF_SECTION *section,
			     fr_event_list_t *el)
{
	rlm_rcode_t	rcode;
	fr_pair_t	*vp;
	fr_ipaddr_t	ipaddr = op->start;
	char		ip_buff[FR_IPADDR_PREFIX_STRLEN];

	fr_pair_list_free(&request->control_pairs);
	fr_pair_list_free(&request->request_pairs);

	MEM(vp = fr_pair_afrom_da_nested(request->control_ctx, &request->control_pairs, attr_ippool_name));
	if (fr_value_box_bstrndup(vp, &vp->data, NULL, (char const *)op->pool, op->pool_len, false) < 0) return -1;

	ipaddr.prefix = (ipaddr.af == AF_INET6) ? 128 : 32;

	do {
		IPPOOL_SPRINT_IP(ip_buff, &ipaddr, ipaddr.prefix);
		MEM(vp = fr_pair_afrom_da_nested(request->request_ctx, &request->request_pairs,
						 attr_ippool_lease_address));
		if (fr_value_box_from_str(vp, &vp->data, vp->da->type, NULL, ip_buff,
					  strlen(ip_buff), NULL) < 0) return -1;
	} while (ipaddr_next(&ipaddr, &op->end, op->prefix));

	if (unlang_interpret_push_section(NULL, request, section,
					  FRAME_CONF(RLM_MODULE_OK, UNLANG_TOP_FRAME)) < 0) return -1;

	rcode = unlang_interpret_synchronous(el, request);
	switch (rcode) {
	case RLM_MODULE_USER_SECTION_REJECT:
		return -1;

	default:
		return 0;
	}
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

static int run_xlat(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request, fr_sbuff_t *xlat, fr_event_list_t *el)
{
	xlat_exp_head_t	*ex;

	if (xlat_tokenize(ctx, &ex,
	  	xlat,
		&(fr_sbuff_parse_rules_t){
			.escapes = &(fr_sbuff_unescape_rules_t) {
				.name = "xlat",
				.chr = '\\',
				.subs = {
					['%'] = '%',
					['\\'] = '\\',
				},
		}}, &(tmpl_rules_t) {
			.attr = {
				.allow_unknown = false,
				.dict_def = dict_freeradius
			},
			.xlat = {
				.runtime_el = el
			},
			.at_runtime = true
		}) < 0) return -1;

	if (xlat_needs_resolving(ex) &&
	    (xlat_resolve(ex, &(xlat_res_rules_t){ .allow_unresolved = false }) < 0)) {
		talloc_free(ex);
		return -1;
	}

	if (unlang_xlat_push(ctx, NULL, list, request, ex, UNLANG_TOP_FRAME) < 0) return -1;
	unlang_interpret_synchronous(el, request);

	return 0;
}

static int xlat_add_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list,
			  request_t *request, ippool_tool_operation_t *op, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	op->start.prefix = op->end.prefix = IPADDR_LEN(op->start.af);
	if (op->range) {
		xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
					       "%%redis_ippool.addresses.add('%s', '%pV', '%pV', %d, '%s')", op->pool,
					       fr_box_ipaddr(op->start), fr_box_ipaddr(op->end), op->prefix, op->range);
	} else {
		xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
					       "%%redis_ippool.addresses.add('%s', '%pV', '%pV', %d)", op->pool,
					       fr_box_ipaddr(op->start), fr_box_ipaddr(op->end), op->prefix);
	}
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

static int xlat_remove_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list,
			     request_t *request, ippool_tool_operation_t *op, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	op->start.prefix = op->end.prefix = IPADDR_LEN(op->start.af);
	xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
				       "%%redis_ippool.addresses.remove('%s', '%pV', '%pV', %d)", op->pool,
				       fr_box_ipaddr(op->start), fr_box_ipaddr(op->end), op->prefix);
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

static int xlat_release_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
			      ippool_tool_operation_t *op, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	op->start.prefix = op->end.prefix = IPADDR_LEN(op->start.af);
	xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
				       "%%redis_ippool.addresses.release('%s', '%pV', '%pV', %d)", op->pool,
				       fr_box_ipaddr(op->start), fr_box_ipaddr(op->end), op->prefix);
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

static int xlat_modify_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
			     ippool_tool_operation_t *op, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	op->start.prefix = op->end.prefix = IPADDR_LEN(op->start.af);
	xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
				       "%%redis_ippool.addresses.modify('%s', '%pV', '%pV', '%s', %d)", op->pool,
				       fr_box_ipaddr(op->start), fr_box_ipaddr(op->end), op->range, op->prefix);
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

static int xlat_assign_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
			     ippool_tool_operation_t *op, char const *owner, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	if (op->range) {
		xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
					       "%%redis_ippool.address.assign('%s', '%pV', '%s', '%s')", op->pool,
					       fr_box_ipaddr(op->start), owner, op->range);
	} else {
		xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
					       "%%redis_ippool.address.assign('%s', '%pV', '%s')", op->pool,
					       fr_box_ipaddr(op->start), owner);
	}
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

static int xlat_unassign_lease(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request,
			       ippool_tool_operation_t *op, char const *owner, fr_event_list_t *el)
{
	char	xlat[1024];
	size_t	xlat_len;

	xlat_len = fr_sbuff_in_sprintf(&FR_SBUFF_OUT(xlat, sizeof(xlat)),
				       "%%redis_ippool.address.unassign('%s', '%pV', '%s')", op->pool,
				       fr_box_ipaddr(op->start), owner);
	if (xlat_len == 0) return -1;

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, xlat_len), el);
}

/** Run the redis_ippool.pools.list xlat to fetch the list of pools across the cluster.
 */
static int redis_ippool_get_pools(TALLOC_CTX *ctx, fr_value_box_list_t *list, request_t *request, fr_event_list_t *el)
{
	char	xlat[] = "%redis_ippool.pools.list()";

	return run_xlat(ctx, list, request, &FR_SBUFF_IN(xlat, sizeof(xlat) - 1), el);
}

static request_t *request_from_internal(TALLOC_CTX *ctx)
{
	request_t *request;

	/*
	 *	Create and initialize the new request.
	 */
	request = request_local_alloc_internal(ctx, NULL);
	if (!request->packet) request->packet = fr_packet_alloc(request, false);
	if (!request->reply) request->reply = fr_packet_alloc(request, false);

	request->packet->socket = (fr_socket_t){
		.type = SOCK_DGRAM,
		.inet = {
			.src_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.src_port = 18120,
			.dst_ipaddr = {
				.af = AF_INET,
				.prefix = 32,
				.addr = {
					.v4 = {
						.s_addr = htonl(INADDR_LOOPBACK)
					}
				}
			},
			.dst_port = 1812
		}
	};

	request->log.dst = talloc_zero(request, log_dst_t);
	request->log.dst->func = vlog_request;
	request->log.dst->uctx = &default_log;
	request->log.dst->lvl = fr_debug_lvl;

	request->master_state = REQUEST_ACTIVE;
	request->log.lvl = fr_debug_lvl;
	request->async = talloc_zero(request, fr_async_t);

	if (fr_packet_pairs_from_packet(request->request_ctx, &request->request_pairs, request->packet) < 0) {
		talloc_free(request);
		fprintf(stderr, "Failed converting packet IPs to attributes");
		return NULL;
	}

	return request;
}

int main(int argc, char *argv[])
{
	static ippool_tool_operation_t	ops[128];
	ippool_tool_operation_t		*p = ops, *end = ops + (NUM_ELEMENTS(ops));

	int				c, ret = EXIT_SUCCESS;

	uint8_t				*range_arg = NULL;
	uint8_t				*pool_arg = NULL;
	bool				do_export = false, print_stats = false, list_pools = false;
	bool				need_pool = false;
	char				*do_import = NULL;
	char				*filename = NULL;
	char const			*owner = NULL;

	request_t			*request = NULL;
	fr_event_list_t			*el = NULL;
	fr_dict_t			*dict = NULL;

	TALLOC_CTX			*autofree;
	TALLOC_CTX			*thread_ctx;

	char				*n;
	main_config_t			*config;
	char				tmpdir[] = "/tmp/ippool_toolXXXXXX";
	char				filepath[sizeof("/tmp/ippool_toolXXXXXX/rlm_redis_ippool_tool.conf")];
	FILE				*conf_file;

	fr_value_box_list_t		vb_list;			// To store results of xlat calls.

	virtual_server_t const		*vs;
	module_instance_t		*mi;
	CONF_SECTION			*pool_stats, *pool_show;	// Process sections used to call module methods

	fr_value_box_list_init(&vb_list);

	name = argv[0];

	fr_atexit_global_setup();

	autofree = talloc_autofree_context();
	thread_ctx = talloc_new(autofree);

	config = main_config_alloc(autofree);
	if (!config) {
		fr_perror("%s", name);
		fr_exit_now(EXIT_FAILURE);
	}

	n = strrchr(name, FR_DIR_SEP);
	if (!n) {
		main_config_name_set_default(config, name, false);
	} else {
		main_config_name_set_default(config, n + 1, false);
	}

	fr_talloc_fault_setup();

#ifndef NDEBUG
	if (fr_fault_setup(autofree, getenv("PANIC_ACTION"), name, PANIC_ACTION_SIGNALS) < 0) {
		fr_perror("%s", config->name);
		fr_exit_now(EXIT_FAILURE);
	}
#else
	fr_disable_null_tracking_on_free(autofree);
#endif

	fr_debug_lvl = 0;
	fr_time_start();

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
} while (0)

	while ((c = getopt(argc, argv, "a:d:D:r:s:Sm:A:U:O:p:ilLhxo:f:")) != -1) switch (c) {
		case 'a':
			ADD_ACTION(IPPOOL_TOOL_ADD);
			break;

		case 'd':
			ADD_ACTION(IPPOOL_TOOL_REMOVE);
			break;

		case 'D':
			main_config_dict_dir_set(config, optarg);
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

		case 'A':
			ADD_ACTION(IPPOOL_TOOL_ASSIGN);
			break;

		case 'U':
			ADD_ACTION(IPPOOL_TOOL_UNASSIGN);
			break;

		case 'O':
			owner = optarg;
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
				usage(64);
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

	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		fr_perror("%s", config->name);
		ret = EXIT_FAILURE;
		goto cleanup;
	}

	modules_init(config->lib_dir);

	if (!fr_dict_global_ctx_init(NULL, true, config->dict_dir)) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_internal_afrom_file(&dict, FR_DICTIONARY_INTERNAL_DIR, __FILE__) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_autoload(redis_ippool_tool_dict) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_dict_attr_autoload(redis_ippool_tool_dict_attr) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (request_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (main_loop_init() < 0) {
		PERROR("Failed initialising main event loop");
		EXIT_WITH_FAILURE;
	}

	if (unlang_global_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (modules_rlm_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}
	if (virtual_servers_init() < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	/*
	 *	Build a temporary configuration file, merging in command
	 *	line provided options.
	 */
	if (!mkdtemp(tmpdir)) EXIT_WITH_FAILURE;
	main_config_confdir_set(config, tmpdir);
	snprintf(filepath, sizeof(filepath), "%s/%s.conf", config->confdir, config->name);
	conf_file = fopen(filepath, "w");
	if (!conf_file) EXIT_WITH_FAILURE;
	fputs(server_conf1, conf_file);
	if (filename) {
		fprintf(conf_file, "$INCLUDE %s\n", filename);
	} else {
		fprintf(conf_file, "server = %s\n", argv[0]);
	}
	fputs(server_conf2, conf_file);
	fclose(conf_file);

	ret = main_config_init(config);
	unlink(filepath);
	rmdir(tmpdir);

	if (ret < 0) EXIT_WITH_FAILURE;

	if (!client_find(NULL, &(fr_ipaddr_t) { .af = AF_INET, .prefix = 32, .addr.v4.s_addr = htonl(INADDR_LOOPBACK) },
			 IPPROTO_IP)) EXIT_WITH_FAILURE;

	if (server_init(config->root_cs, config->confdir, dict) < 0) EXIT_WITH_FAILURE;

	el = main_loop_event_list();
	fr_assert(el);

	fr_coords_create(autofree, el);

	fr_schedule_worker_id_set(0);
	if (fr_thread_instantiate(thread_ctx, el) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (modules_rlm_coord_attach(el) < 0) {
		fr_perror("%s", config->name);
		EXIT_WITH_FAILURE;
	}

	if (fr_coord_pre_event_insert(el) < 0) {
		fr_strerror_const("Failed adding coordinator pre-check to event list");
		EXIT_WITH_FAILURE;
	}

	if (fr_coord_post_event_insert(el) < 0) {
		fr_strerror_const("Failed adding coordinator pre-check to event list");
		EXIT_WITH_FAILURE;
	}

	request = request_from_internal(autofree);

	vs = virtual_server_find("default");
	mi = module_rlm_static_by_name(NULL, "redis_ippool");
	if (!mi) EXIT_WITH_FAILURE;

	/*
	 *	The module methods for these functions use call_env - which
	 *	preclude them being used with unlang_module_push.  Instead they
	 *	need to be called from compiled process sections.
	 *	To avoid inventing another process module, these have been
	 *	wrapped in standard RADIUS process sections.
	 */
	pool_stats = cf_section_find(virtual_server_cs(vs), "recv", "Access-Request");
	if (!pool_stats) EXIT_WITH_FAILURE;
	pool_show = cf_section_find(virtual_server_cs(vs), "recv", "Accounting-Request");
	if (!pool_show) EXIT_WITH_FAILURE;

	/*
	 *	Unescape sequences in the pool name
	 */
	if (argv[1] && (argv[1][0] != '\0')) {
		fr_sbuff_t		out;
		fr_sbuff_uctx_talloc_t	tctx;

		MEM(fr_sbuff_init_talloc(autofree, &out, &tctx, strlen(argv[1]) + 1, SIZE_MAX));
		(void) fr_value_str_unescape(&out,
					     &FR_SBUFF_IN_STR(argv[1]), SIZE_MAX, '"');
		talloc_realloc(autofree, out.buff, uint8_t, fr_sbuff_used(&out));
		pool_arg = (uint8_t *)out.buff;
	}

	if (argc >= 3 && (argv[2][0] != '\0')) {
		fr_sbuff_t		out;
		fr_sbuff_uctx_talloc_t	tctx;

		MEM(fr_sbuff_init_talloc(autofree, &out, &tctx, strlen(argv[1]) + 1, SIZE_MAX));
		(void) fr_value_str_unescape(&out,
					     &FR_SBUFF_IN_STR(argv[2]), SIZE_MAX, '"');
		talloc_realloc(autofree, out.buff, uint8_t, fr_sbuff_used(&out));
		range_arg = (uint8_t *)out.buff;
	}

	if (!do_import && !do_export && !list_pools && !print_stats && (p == ops)) {
		ERROR("Nothing to do!");
		fr_exit_now(EXIT_FAILURE);
	}

	if (do_import) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (do_export) {
		ERROR("NOT YET IMPLEMENTED");
	}

	if (print_stats) {
		fr_value_box_list_t	pools;
		fr_pair_t	*stats, *st, *dyn;
		fr_pair_t	*total, *static_total, *static_free, *dyn_free;
		fr_pair_t	*exp1m, *exp30m, *exp1h, *exp1d;

		fr_value_box_list_init(&pools);
		if (pool_arg) {
			fr_value_box_t	*vb;
			MEM(vb = fr_value_box_alloc(autofree, FR_TYPE_STRING, NULL));
			fr_value_box_bstrndup(vb, vb, NULL, (char *)pool_arg, talloc_array_length(pool_arg), false);
			fr_value_box_list_insert_tail(&pools, vb);
		} else {
			if (redis_ippool_get_pools(autofree, &pools, request, el) < 0) EXIT_WITH_FAILURE;
		}

		fr_value_box_list_foreach(&pools, vb) {
			if (redis_ippool_get_stats(request, vb, pool_stats, el) < 0) EXIT_WITH_FAILURE;

			INFO("pool                : %pV", vb);
			stats = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_ippool_stats);
			if (!stats) EXIT_WITH_FAILURE;

			st = fr_pair_find_by_da(&stats->vp_group, NULL, attr_ippool_stats_static);
			dyn = fr_pair_find_by_da(&stats->vp_group, NULL, attr_ippool_stats_dynamic);
			if (!st || !dyn) EXIT_WITH_FAILURE;

			total = fr_pair_find_by_da_nested(&stats->vp_group, NULL, attr_ippool_stats_total);
			if (!total) EXIT_WITH_FAILURE;
			INFO("total               : %pV", &total->data);

			static_total = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_total);
			if (!static_total) EXIT_WITH_FAILURE;
			INFO("dynamic total       : %" PRIu64, total->vp_uint64 - static_total->vp_uint64);

			dyn_free = fr_pair_find_by_da(&dyn->vp_group, NULL, attr_ippool_stats_dynamic_free);
			if (!dyn_free) EXIT_WITH_FAILURE;
			INFO("dynamic free        : %pV", &dyn_free->data);
			INFO("dynamic used        : %" PRIu64, total->vp_uint64 - static_total->vp_uint64 - dyn_free->vp_uint64);
			if ((total->vp_uint64 - static_total->vp_uint64) > 0) {
				INFO("dynamic used (%%)    : %.2Lf",
				     ((long double)(total->vp_uint64 - dyn_free->vp_uint64 - static_total->vp_uint64) /
				      (long double)(total->vp_uint64 - static_total->vp_uint64)) * 100);
			} else {
				INFO("used (%%)            : 0");
			}

			exp1m = fr_pair_find_by_da(&dyn->vp_group, NULL, attr_ippool_stats_dynamic_expire1m);
			exp30m = fr_pair_find_by_da(&dyn->vp_group, NULL, attr_ippool_stats_dynamic_expire30m);
			exp1h = fr_pair_find_by_da(&dyn->vp_group, NULL, attr_ippool_stats_dynamic_expire1h);
			exp1d = fr_pair_find_by_da(&dyn->vp_group, NULL, attr_ippool_stats_dynamic_expire1d);
			if (!exp1m || !exp30m || !exp1h || !exp1d) EXIT_WITH_FAILURE;

			INFO("expiring 0-1m       : %" PRIu64, exp1m->vp_uint64);
			INFO("expiring 1-30m      : %" PRIu64, exp30m->vp_uint64 - exp1m->vp_uint64);
			INFO("expiring 30m-1h     : %" PRIu64, exp1h->vp_uint64 - exp30m->vp_uint64);
			INFO("expiring 1h-1d      : %" PRIu64, exp1d->vp_uint64 - exp1h->vp_uint64);
			INFO("static total        : %pV", &static_total->data);

			static_free = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_free);
			if (!static_free) EXIT_WITH_FAILURE;
			INFO("static 'free'       : %pV", &static_free->data);
			INFO("static issued       : %" PRIu64, static_total->vp_uint64 - static_free->vp_uint64);
			if (static_total->vp_uint64) {
				INFO("static issued (%%)   : %.2Lf",
				     ((long double)(static_total->vp_uint64 - static_free->vp_uint64) /
				      (long double)(static_total->vp_uint64)) * 100);
			} else {
				INFO("static issued (%%)   : 0");
			}

			exp1m = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_renew1m);
			exp30m = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_renew30m);
			exp1h = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_renew1h);
			exp1d = fr_pair_find_by_da(&st->vp_group, NULL, attr_ippool_stats_static_renew1d);
			if (!exp1m || !exp30m || !exp1h || !exp1d) EXIT_WITH_FAILURE;

			INFO("static renew 0-1m   : %" PRIu64, exp1m->vp_uint64);
			INFO("static renew 1-30m  : %" PRIu64, exp30m->vp_uint64 - exp1m->vp_uint64);
			INFO("static renew 30m-1h : %" PRIu64, exp1h->vp_uint64 - exp30m->vp_uint64);
			INFO("static renew 1h-1d  : %" PRIu64, exp1d->vp_uint64 - exp1h->vp_uint64);
			INFO("--");
		}
		fr_value_box_list_talloc_free(&pools);
	}

	if (list_pools) {
		fr_value_box_list_t	pools;

		fr_value_box_list_init(&pools);
		if (redis_ippool_get_pools(autofree, &pools, request, el) < 0) EXIT_WITH_FAILURE;
		fr_value_box_list_foreach(&pools, vb) INFO("%pV", vb);
		INFO("--");
		fr_value_box_list_talloc_free(&pools);
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
		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_add_lease(autofree, &vb_list, request, p, el) < 0) EXIT_WITH_FAILURE;

		INFO("Added %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_REMOVE:
		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_remove_lease(autofree, &vb_list, request, p, el) < 0) EXIT_WITH_FAILURE;

		INFO("Removed %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_RELEASE:
		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_release_lease(autofree, &vb_list, request, p, el) < 0) EXIT_WITH_FAILURE;

		INFO("Released %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_SHOW:
	{
		fr_pair_t	*ippool, *vp, *device, *gateway, *expires;

		if (redis_ippool_show(request, p, pool_show, el) < 0) EXIT_WITH_FAILURE;

		vp = fr_pair_find_by_da_nested(&request->control_pairs, NULL, attr_ippool_lease);
		if (vp) {
			ippool = fr_pair_parent(vp);
		} else {
			ippool = fr_pair_find_by_da(&request->control_pairs, NULL, attr_ippool);
		}
		if (!ippool) EXIT_WITH_FAILURE;

		INFO("Retrieved information for %u address(es)/prefix(es)",
		     fr_pair_count_by_da(&ippool->vp_group, attr_ippool_lease));
		fr_pair_list_foreach(&ippool->vp_group, lease) {
			if (lease->da != attr_ippool_lease) continue;

			INFO("--");
			vp = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_range);
			if (vp) INFO("range           : %pV", &vp->data);

			vp = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_address);
			if (!vp) EXIT_WITH_FAILURE;
			INFO("address/prefix  : %pV", &vp->data);

			vp = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_active);
			if (!vp) EXIT_WITH_FAILURE;
			INFO("active          : %s", vp->vp_bool ? "yes" : "no");

			device = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_device);
			gateway = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_gateway);
			expires = fr_pair_find_by_da(&lease->vp_group, NULL, attr_ippool_lease_expires);

			if (vp->vp_bool) {
				if (expires) INFO("lease expires   : %pV", &expires->data);
				if (device) INFO("device id       : %pV", &device->data);
				if (gateway) INFO("gateway id      : %pV", &gateway->data);
			} else {
				if (expires) INFO("lease expired   : %pV", &expires->data);
				if (device) INFO("last device id  : %pV", &device->data);
				if (gateway) INFO("last gateway id : %pV", &gateway->data);
			}
		}
	}
		continue;

	case IPPOOL_TOOL_MODIFY:
		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_modify_lease(autofree, &vb_list, request, p, el) < 0) EXIT_WITH_FAILURE;

		INFO("Modified %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_ASSIGN:
		if (fr_ipaddr_cmp(&p->start, &p->end) != 0) {
			ERROR("Static assignment requires a single IP");
			fr_exit_now(EXIT_FAILURE);
		}
		if (!owner) {
			ERROR("Static assignment requires an owner");
			fr_exit_now(EXIT_FAILURE);
		}

		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_assign_lease(autofree, &vb_list, request, p, owner, el) < 0) EXIT_WITH_FAILURE;
		INFO("Assigned %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_UNASSIGN:
		if (fr_ipaddr_cmp(&p->start, &p->end) != 0) {
			ERROR("Static lease un-assignment requires a single IP");
			fr_exit_now(EXIT_FAILURE);
		}
		if (!owner) {
			ERROR("Static lease un-assignment requires an owner");
			fr_exit_now(EXIT_FAILURE);
		}

		fr_value_box_list_talloc_free(&vb_list);
		if (xlat_unassign_lease(autofree, &vb_list, request, p, owner, el) < 0) EXIT_WITH_FAILURE;
		INFO("Un-assigned %pV address(es)/prefix(es)", fr_value_box_list_head(&vb_list));
		continue;

	case IPPOOL_TOOL_NOOP:
		break;
	}

cleanup:

	/*
	 *	The same clean up sequence as unit_test_module.c
	 */
	talloc_free(thread_ctx);
	fr_coords_destroy();
	fr_atexit_thread_trigger_all();
	main_loop_free();
	fr_atexit_thread_trigger_all();
	server_free();
	virtual_servers_free();
	modules_rlm_free();
	main_config_free(&config);
	fr_dict_autofree(redis_ippool_tool_dict);
	fr_dict_free(&dict, __FILE__);
	talloc_free(autofree);
	fr_atexit_global_trigger_all();

	return ret;
}
