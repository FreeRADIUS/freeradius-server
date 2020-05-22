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
 *     * device  - Device identifier for the device which last bound this address.
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

#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster.h>
#include "redis_ippool.h"

#ifdef WITH_DHCP
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#endif

/** rlm_redis module instance
 *
 */
typedef struct {
	fr_redis_conf_t			conf;		//!< Connection parameters for the Redis server.
							//!< Must be first field in this struct.

	char const			*name;		//!< Instance name.

	vp_tmpl_t			*pool_name;	//!< Name of the pool we're allocating IP addresses from.

	vp_tmpl_t			*offer_time;	//!< How long we should reserve a lease for during
							//!< the pre-allocation stage (typically responding
							//!< to DHCP discover).
	vp_tmpl_t			*lease_time;	//!< How long an IP address should be allocated for.

	uint32_t			wait_num;	//!< How many slaves we want to acknowledge allocations
							//!< or updates.

	fr_time_delta_t			wait_timeout;	//!< How long we wait for slaves to acknowledge writing.

	vp_tmpl_t			*device_id;	//!< Unique device identifier.  Could be mac-address
							//!< or a combination of User-Name and something
							//!< unique to the device.

	vp_tmpl_t			*gateway_id;	//!< Gateway identifier, usually
							//!< NAS-Identifier or the actual Option 82 gateway.
							//!< Used for bulk lease cleanups.

	vp_tmpl_t			*requested_address;		//!< Attribute to read the IP for renewal from.

	vp_tmpl_t			*allocated_address_attr;	//!< IP attribute and destination.

	vp_tmpl_t			*range_attr;	//!< Attribute to write the range ID to.

	vp_tmpl_t			*expiry_attr;	//!< Time at which the lease will expire.

	bool				ipv4_integer;	//!< Whether IPv4 addresses should be cast to integers,
							//!< for renew operations.

	bool				copy_on_update; //!< Copy the address provided by ip_address to the
							//!< allocated_address_attr if updates are successful.

	const char			*lua_preamble_file;
	redis_ippool_lua_script_t	lua_alloc;
	redis_ippool_lua_script_t	lua_release;
	redis_ippool_lua_script_t	lua_update;

	fr_redis_cluster_t		*cluster;	//!< Redis cluster.
} rlm_redis_ippool_t;

static CONF_PARSER redis_config[] = {
	REDIS_COMMON_CONFIG,
	CONF_PARSER_TERMINATOR
};

static CONF_PARSER module_config[] = {
	{ FR_CONF_OFFSET("pool_name", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, pool_name) },

	{ FR_CONF_OFFSET("device", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, device_id) },
	{ FR_CONF_OFFSET("gateway", FR_TYPE_TMPL, rlm_redis_ippool_t, gateway_id) },\

	{ FR_CONF_OFFSET("offer_time", FR_TYPE_TMPL, rlm_redis_ippool_t, offer_time) },
	{ FR_CONF_OFFSET("lease_time", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lease_time) },

	{ FR_CONF_OFFSET("wait_num", FR_TYPE_UINT32, rlm_redis_ippool_t, wait_num) },
	{ FR_CONF_OFFSET("wait_timeout", FR_TYPE_TIME_DELTA, rlm_redis_ippool_t, wait_timeout) },

	{ FR_CONF_OFFSET("requested_address", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, requested_address), .dflt = "%{%{DHCP-Requested-IP-Address}:-%{DHCP-Client-IP-Address}}", .quote = T_DOUBLE_QUOTED_STRING },
	{ FR_CONF_DEPRECATED("ip_address", FR_TYPE_TMPL | FR_TYPE_REQUIRED, rlm_redis_ippool_t, NULL) },

	{ FR_CONF_OFFSET("allocated_address_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, allocated_address_attr), .dflt = "&reply:DHCP-Your-IP-Address", .quote = T_BARE_WORD },
	{ FR_CONF_DEPRECATED("reply_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, NULL) },

	{ FR_CONF_OFFSET("range_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE | FR_TYPE_REQUIRED, rlm_redis_ippool_t, range_attr), .dflt = "&reply:Pool-Range", .quote = T_BARE_WORD },
	{ FR_CONF_OFFSET("expiry_attr", FR_TYPE_TMPL | FR_TYPE_ATTRIBUTE, rlm_redis_ippool_t, expiry_attr) },

	{ FR_CONF_OFFSET("ipv4_integer", FR_TYPE_BOOL, rlm_redis_ippool_t, ipv4_integer) },
	{ FR_CONF_OFFSET("copy_on_update", FR_TYPE_BOOL, rlm_redis_ippool_t, copy_on_update), .dflt = "yes", .quote = T_BARE_WORD },

	{ FR_CONF_OFFSET("lua_preamble", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lua_preamble_file), .dflt = "${modconfdir}/redis_ippool/preamble.lua" },
	{ FR_CONF_OFFSET("lua_alloc", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lua_alloc.file), .dflt = "${modconfdir}/redis_ippool/alloc.lua" },
	{ FR_CONF_OFFSET("lua_release", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lua_release.file), .dflt = "${modconfdir}/redis_ippool/release.lua" },
	{ FR_CONF_OFFSET("lua_update", FR_TYPE_FILE_INPUT | FR_TYPE_REQUIRED, rlm_redis_ippool_t, lua_update.file), .dflt = "${modconfdir}/redis_ippool/update.lua" },

	/*
	 *	Split out to allow conversion to universal ippool module with
	 *	minimum of config changes.
	 */
	{ FR_CONF_POINTER("redis", FR_TYPE_SUBSECTION, NULL), .subcs = redis_config },
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;
#ifdef WITH_DHCP
static fr_dict_t const *dict_dhcpv4;
#endif

extern fr_dict_autoload_t rlm_redis_ippool_dict[];
fr_dict_autoload_t rlm_redis_ippool_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_radius, .proto = "radius" },
#ifdef WITH_DHCP
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
#endif
	{ NULL }
};

static fr_dict_attr_t const *attr_pool_action;
static fr_dict_attr_t const *attr_acct_status_type;
#ifdef WITH_DHCP
static fr_dict_attr_t const *attr_message_type;
#endif

extern fr_dict_attr_autoload_t rlm_redis_ippool_dict_attr[];
fr_dict_attr_autoload_t rlm_redis_ippool_dict_attr[] = {
	{ .out = &attr_pool_action, .name = "Pool-Action", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_acct_status_type, .name = "Acct-Status-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
#ifdef WITH_DHCP
	{ .out = &attr_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
#endif
	{ NULL }
};

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

static void ippool_action_print(REQUEST *request, ippool_action_t action,
				fr_log_lvl_t lvl,
				uint8_t const *key_prefix, size_t key_prefix_len,
				char const *ip_str,
				uint8_t const *device_id, size_t device_id_len,
				uint8_t const *gateway_id, size_t gateway_id_len,
				uint32_t expires)
{
	char *key_prefix_str, *device_str = NULL, *gateway_str = NULL;

	key_prefix_str = fr_asprint(request, (char const *)key_prefix, key_prefix_len, '"');
	if (gateway_id) gateway_str = fr_asprint(request, (char const *)gateway_id, gateway_id_len, '"');
	if (device_id) device_str = fr_asprint(request, (char const *)device_id, device_id_len, '"');

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

/** Allocate a new IP address from a pool
 *
 */
static ippool_rcode_t redis_ippool_allocate(rlm_redis_ippool_t const *inst, REQUEST *request,
					    uint8_t const *key_prefix, size_t key_prefix_len,
					    uint8_t const *device_id, size_t device_id_len,
					    uint8_t const *gateway_id, size_t gateway_id_len,
					    uint32_t expires)
{
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	fr_assert(key_prefix);
	fr_assert(device_id);

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!gateway_id) gateway_id = (uint8_t const *)"";

	status = fr_redis_script(&reply, request, inst->cluster,
			       key_prefix, key_prefix_len,
			       inst->wait_num, inst->wait_timeout,
			       inst->lua_alloc.script,
			       "EVALSHA %s 1 %b %u %b %b",
			       inst->lua_alloc.digest,
			       key_prefix, key_prefix_len,
			       expires,
			       device_id, device_id_len,
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
		vp_tmpl_t ip_rhs;
		vp_map_t ip_map = {
			.lhs = inst->allocated_address_attr,
			.op = T_OP_SET,
			.rhs = &ip_rhs
		};

		tmpl_init(&ip_rhs, TMPL_TYPE_DATA, "", 0, T_BARE_WORD);
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
			vp_tmpl_t range_rhs;
			vp_map_t range_map = {
				.lhs = inst->range_attr,
				.op = T_OP_SET,
				.rhs = &range_rhs
			};

			tmpl_init(&range_rhs, TMPL_TYPE_DATA, "", 0, T_DOUBLE_QUOTED_STRING);
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
		vp_tmpl_t expiry_rhs;
		vp_map_t expiry_map = {
			.lhs = inst->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};

		tmpl_init(&expiry_rhs, TMPL_TYPE_DATA, "", 0, T_DOUBLE_QUOTED_STRING);
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
static ippool_rcode_t redis_ippool_update(rlm_redis_ippool_t const *inst, REQUEST *request,
					  uint8_t const *key_prefix, size_t key_prefix_len,
					  fr_ipaddr_t *ip,
					  uint8_t const *device_id, size_t device_id_len,
					  uint8_t const *gateway_id, size_t gateway_id_len,
					  uint32_t expires)
{
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	vp_tmpl_t		range_rhs;
	vp_map_t		range_map = { .lhs = inst->range_attr, .op = T_OP_SET, .rhs = &range_rhs };

	tmpl_init(&range_rhs, TMPL_TYPE_DATA, "", 0, T_DOUBLE_QUOTED_STRING);

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!device_id) device_id = (uint8_t const *)"";
	if (!gateway_id) gateway_id = (uint8_t const *)"";

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = fr_redis_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       inst->lua_update.script,
				       "EVALSHA %s 1 %b %u %u %b %b",
				       inst->lua_update.digest,
				       key_prefix, key_prefix_len,
				       expires,
				       htonl(ip->addr.v4.s_addr),
				       device_id, device_id_len,
				       gateway_id, gateway_id_len);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = fr_redis_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       inst->lua_update.script,
				       "EVALSHA %s 1 %b %u %s %b %b",
				       inst->lua_update.digest,
				       key_prefix, key_prefix_len,
				       expires,
				       ip_buff,
				       device_id, device_id_len,
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
		vp_tmpl_t expiry_rhs;
		vp_map_t expiry_map = {
			.lhs = inst->expiry_attr,
			.op = T_OP_SET,
			.rhs = &expiry_rhs
		};


		tmpl_init(&expiry_rhs, TMPL_TYPE_DATA, "", 0, T_DOUBLE_QUOTED_STRING);

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
static ippool_rcode_t redis_ippool_release(rlm_redis_ippool_t const *inst, REQUEST *request,
					   uint8_t const *key_prefix, size_t key_prefix_len,
					   fr_ipaddr_t *ip,
					   uint8_t const *device_id, size_t device_id_len)
{
	redisReply		*reply = NULL;

	fr_redis_rcode_t	status;
	ippool_rcode_t		ret = IPPOOL_RCODE_SUCCESS;

	/*
	 *	hiredis doesn't deal well with NULL string pointers
	 */
	if (!device_id) device_id = (uint8_t const *)"";

	if ((ip->af == AF_INET) && inst->ipv4_integer) {
		status = fr_redis_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       inst->lua_release.script,
				       "EVALSHA %s 1 %b %u %b",
				       inst->lua_release.digest,
				       key_prefix, key_prefix_len,
				       htonl(ip->addr.v4.s_addr),
				       device_id, device_id_len);
	} else {
		char ip_buff[FR_IPADDR_PREFIX_STRLEN];

		IPPOOL_SPRINT_IP(ip_buff, ip, ip->prefix);
		status = fr_redis_script(&reply, request, inst->cluster,
				       key_prefix, key_prefix_len,
				       inst->wait_num, inst->wait_timeout,
				       inst->lua_release.script,
				       "EVALSHA %s 1 %b %s %b",
				       inst->lua_release.digest,
				       key_prefix, key_prefix_len,
				       ip_buff,
				       device_id, device_id_len);
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
				       rlm_redis_ippool_t const *inst, REQUEST *request)
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

static rlm_rcode_t mod_action(rlm_redis_ippool_t const *inst, REQUEST *request, ippool_action_t action)
{
	uint8_t		key_prefix_buff[IPPOOL_MAX_KEY_PREFIX_SIZE], device_id_buff[256], gateway_id_buff[256];
	uint8_t const	*key_prefix, *device_id = NULL, *gateway_id = NULL;
	size_t		key_prefix_len, device_id_len = 0, gateway_id_len = 0;
	ssize_t		slen;
	fr_ipaddr_t	ip;
	char		expires_buff[20];
	char const	*expires_str;
	unsigned long	expires = 0;
	char		*q;

	slen = ippool_pool_name(&key_prefix, (uint8_t *)&key_prefix_buff, sizeof(key_prefix_len), inst, request);
	if (slen < 0) return RLM_MODULE_FAIL;
	if (slen == 0) return RLM_MODULE_NOOP;

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
			RDEBUG2("IP address lease allocated");
			return RLM_MODULE_UPDATED;

		case IPPOOL_RCODE_POOL_EMPTY:
			RWDEBUG("Pool contains no free addresses");
			return RLM_MODULE_NOTFOUND;

		default:
			return RLM_MODULE_FAIL;
		}

	case POOL_ACTION_UPDATE:
	{
		char		ip_buff[INET6_ADDRSTRLEN + 4];
		char const	*ip_str;

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

		if (tmpl_expand(&ip_str, ip_buff, sizeof(ip_buff), request, inst->requested_address, NULL, NULL) < 0) {
			REDEBUG("Failed expanding requested_address (%s)", inst->requested_address->name);
			return RLM_MODULE_FAIL;
		}

		if (fr_inet_pton(&ip, ip_str, -1, AF_UNSPEC, false, true) < 0) {
			RPEDEBUG("Failed parsing address");
			return RLM_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip_str, device_id, device_id_len, gateway_id, gateway_id_len, expires);
		switch (redis_ippool_update(inst, request, key_prefix, key_prefix_len,
					    &ip, device_id, device_id_len,
					    gateway_id, gateway_id_len, (uint32_t)expires)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("Requested IP address' \"%s\" lease updated", ip_str);

			/*
			 *	Copy over the input IP address to the reply attribute
			 */
			if (inst->copy_on_update) {
				vp_tmpl_t ip_rhs = {
					.name = "",
					.type = TMPL_TYPE_DATA,
					.quote = T_BARE_WORD,
				};
				vp_map_t ip_map = {
					.lhs = inst->allocated_address_attr,
					.op = T_OP_SET,
					.rhs = &ip_rhs
				};

				fr_value_box_strdup_shallow(&ip_rhs.data.literal, NULL, ip_str, false);

				if (map_to_request(request, &ip_map, map_to_vp, NULL) < 0) return RLM_MODULE_FAIL;
			}
			return RLM_MODULE_UPDATED;

		/*
		 *	It's useful to be able to identify the 'not found' case
		 *	as we can relay to a server where the IP address might
		 *	be found.  This extremely useful for migrations.
		 */
		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("Requested IP address \"%s\" is not a member of the specified pool", ip_str);
			return RLM_MODULE_NOTFOUND;

		case IPPOOL_RCODE_EXPIRED:
			REDEBUG("Requested IP address' \"%s\" lease already expired at time of renewal", ip_str);
			return RLM_MODULE_INVALID;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("Requested IP address' \"%s\" lease allocated to another device", ip_str);
			return RLM_MODULE_INVALID;

		default:
			return RLM_MODULE_FAIL;
		}
	}

	case POOL_ACTION_RELEASE:
	{
		char		ip_buff[INET6_ADDRSTRLEN + 4];
		char const	*ip_str;

		if (tmpl_expand(&ip_str, ip_buff, sizeof(ip_buff), request, inst->requested_address, NULL, NULL) < 0) {
			REDEBUG("Failed expanding requested_address (%s)", inst->requested_address->name);
			return RLM_MODULE_FAIL;
		}

		if (fr_inet_pton(&ip, ip_str, -1, AF_UNSPEC, false, true) < 0) {
			RPEDEBUG("Failed parsing address");
			return RLM_MODULE_FAIL;
		}

		ippool_action_print(request, action, L_DBG_LVL_2, key_prefix, key_prefix_len,
				    ip_str, device_id, device_id_len, gateway_id, gateway_id_len, 0);
		switch (redis_ippool_release(inst, request, key_prefix, key_prefix_len,
					     &ip, device_id, device_id_len)) {
		case IPPOOL_RCODE_SUCCESS:
			RDEBUG2("IP address \"%s\" released", ip_str);
			return RLM_MODULE_UPDATED;

		/*
		 *	It's useful to be able to identify the 'not found' case
		 *	as we can relay to a server where the IP address might
		 *	be found.  This extremely useful for migrations.
		 */
		case IPPOOL_RCODE_NOT_FOUND:
			REDEBUG("Requested IP address \"%s\" is not a member of the specified pool", ip_str);
			return RLM_MODULE_NOTFOUND;

		case IPPOOL_RCODE_DEVICE_MISMATCH:
			REDEBUG("Requested IP address' \"%s\" lease allocated to another device", ip_str);
			return RLM_MODULE_INVALID;

		default:
			return RLM_MODULE_FAIL;
		}
	}

	case POOL_ACTION_BULK_RELEASE:
		RDEBUG2("Bulk release not yet implemented");
		return RLM_MODULE_NOOP;

	default:
		fr_assert(0);
		return RLM_MODULE_FAIL;
	}
}

static rlm_rcode_t CC_HINT(nonnull) mod_accounting(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	VALUE_PAIR			*vp;

	/*
	 *	Pool-Action override
	 */
	vp = fr_pair_find_by_da(request->control, attr_pool_action, TAG_ANY);
	if (vp) return mod_action(inst, request, vp->vp_uint32);

	/*
	 *	Otherwise, guess the action by Acct-Status-Type
	 */
	vp = fr_pair_find_by_da(request->packet->vps, attr_acct_status_type, TAG_ANY);
	if (!vp) {
		RDEBUG2("Couldn't find &request:Acct-Status-Type or &control:Pool-Action, doing nothing...");
		return RLM_MODULE_NOOP;
	}

	switch (vp->vp_uint32) {
	case FR_STATUS_START:
	case FR_STATUS_ALIVE:
		return mod_action(inst, request, POOL_ACTION_UPDATE);

	case FR_STATUS_STOP:
		return mod_action(inst, request, POOL_ACTION_RELEASE);

	case FR_STATUS_ACCOUNTING_OFF:
	case FR_STATUS_ACCOUNTING_ON:
		return mod_action(inst, request, POOL_ACTION_BULK_RELEASE);

	default:
		return RLM_MODULE_NOOP;
	}
}

static rlm_rcode_t CC_HINT(nonnull) mod_authorize(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	VALUE_PAIR			*vp;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_da(request->control, attr_pool_action, TAG_ANY);
	return mod_action(inst, request, vp ? vp->vp_uint32 : POOL_ACTION_ALLOCATE);
}

static rlm_rcode_t CC_HINT(nonnull) mod_post_auth(module_ctx_t const *mctx, REQUEST *request)
{
	rlm_redis_ippool_t const	*inst = talloc_get_type_abort_const(mctx->instance, rlm_redis_ippool_t);
	VALUE_PAIR			*vp;
	ippool_action_t			action = POOL_ACTION_ALLOCATE;

	/*
	 *	Unless it's overridden the default action is to allocate
	 *	when called in Post-Auth.
	 */
	vp = fr_pair_find_by_da(request->control, attr_pool_action, TAG_ANY);
	if (vp) {
		if ((vp->vp_uint32 > 0) && (vp->vp_uint32 <= POOL_ACTION_BULK_RELEASE)) {
			action = vp->vp_uint32;

		} else {
			RWDEBUG("Ignoring invalid action %d", vp->vp_uint32);
			return RLM_MODULE_NOOP;
		}
#ifdef WITH_DHCP
	} else if (request->dict == dict_dhcpv4) {
		vp = fr_pair_find_by_da(request->control, attr_message_type, TAG_ANY);
		if (!vp) goto run;

		if (vp->vp_uint8 == FR_DHCP_REQUEST) action = POOL_ACTION_UPDATE;
#endif
	}

run:
	return mod_action(inst, request, action);
}

static int mod_instantiate(void *instance, CONF_SECTION *conf)
{
	CONF_SECTION			*subcs = cf_section_find(conf, "redis", NULL);

	rlm_redis_ippool_t		*inst = instance;

	fr_assert(tmpl_is_attr(inst->allocated_address_attr));
	fr_assert(subcs);

	inst->cluster = fr_redis_cluster_alloc(inst, subcs, &inst->conf, true, NULL, NULL, NULL);
	if (!inst->cluster) goto err;

	if (!fr_redis_cluster_min_version(inst->cluster, "3.0.2")) {
		PERROR("Cluster error");
		goto err;
	}

	redis_ippool_lua_script_t lua_preamble = {
		.file   = inst->lua_preamble_file,
		.script = NULL
	};

	if (fr_redis_ippool_loadscript_buf(conf, NULL, &lua_preamble) == -1)
		goto err;

	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &inst->lua_alloc))
		goto err2;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &inst->lua_update))
		goto err3;
	if (fr_redis_ippool_loadscript(conf, &lua_preamble, &inst->lua_release))
		goto err4;

	/*
	 *	If we don't have a separate time specifically for offers
	 *	just use the lease time.
	 */
	if (!inst->offer_time) inst->offer_time = inst->lease_time;

	talloc_free(lua_preamble.script);

	return 0;

err4:
	talloc_free(inst->lua_update.script);
err3:
	talloc_free(inst->lua_alloc.script);
err2:
	talloc_free(lua_preamble.script);
err:
	return -1;
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
};
