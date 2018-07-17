/*
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
 */

/*
 * $Id$
 *
 * @file src/lib/server/snmp.c
 * @brief Implements an SNMP-like interface using FreeRADIUS attributes
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 *
 * @copyright 2016 The FreeRADIUS server project
 * @copyright 2016 Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/freeradius.snmp.h>

#define FR_FREERADIUS_SNMP_TYPE_OBJECT 0

#define SNMP_MAP_TERMINATOR	{ .name = NULL, .da = NULL, .type = 0 }

typedef struct fr_snmp_map fr_snmp_map_t;

typedef int (*fr_snmp_get_func_t)(TALLOC_CTX *ctx, fr_value_box_t *out, fr_snmp_map_t const *map, void *snmp_ctx);
typedef int (*fr_snmp_set_func_t)(fr_snmp_map_t const *map, void *snmp_ctx, fr_value_box_t *data);
typedef int (*fr_snmp_index_func_t)(TALLOC_CTX *ctx, void **snmp_ctx_out,
				    fr_snmp_map_t const *map, void const *snmp_ctx_in, uint32_t index);

/** Maps a VALUE_PAIR to the source of a value
 *
 * @note Arrays of maps must be in ascending attribute order.
 *	This is because the lookup is performed using a binary
 *	search, not by index.
 *
 * Mappings between attributes and snmp values are more complex in
 * an SNMP based interface, because we need to traverse the tree,
 * looking at indexes in multiple levels of mapping tables.
 */
struct fr_snmp_map {
	char const		*name;			//!< Attribute number.  Table entries must be in
							//!< attribute number order.
	fr_dict_attr_t const	*da;			//!< Dictionary attribute (resolved from attribute number).
	unsigned int		type;			//!< SNMP type - More specific than attribute type.

	fr_snmp_get_func_t	get;			//!< Function to retrieve value.
	fr_snmp_set_func_t	set;			//!< Function to write a new value.
	fr_snmp_index_func_t	index;			//!< Function for traversing indexes.

	union {
		size_t			offset;		//!< Offset in snmp_ctx (passed to index function).
		fr_snmp_map_t		*last;		//!< Last sibling at this level.
	};

	fr_snmp_map_t		*child;			//!< Child map.
};

static fr_dict_attr_t const *fr_snmp_op_attr;
static fr_dict_attr_t const *fr_snmp_type;
static fr_dict_attr_t const *fr_snmp_root;
static fr_dict_attr_t const *fr_snmp_failure;

static struct timeval uptime;
static struct timeval reset_time;
static int reset_state = FR_RADIUS_AUTH_SERV_CONFIG_RESET_VALUE_RUNNING;

static int snmp_value_serv_ident_get(TALLOC_CTX *ctx, fr_value_box_t *out, NDEBUG_UNUSED fr_snmp_map_t const *map,
				     UNUSED void *snmp_ctx)
{
	rad_assert(map->da->type == FR_TYPE_STRING);

	out->vb_strvalue = talloc_typed_asprintf(ctx, "FreeRADIUS %s", radiusd_version_short);
	out->datum.length = talloc_array_length(out->vb_strvalue) - 1;
	return 0;
}

static int snmp_value_uptime_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out, NDEBUG_UNUSED fr_snmp_map_t const *map,
				 UNUSED void *snmp_ctx)
{
	struct timeval now;
	struct timeval diff;

	rad_assert(map->da->type == FR_TYPE_UINT32);

	gettimeofday(&now, NULL);
	fr_timeval_subtract(&diff, &now, &uptime);

	out->vb_uint32 = diff.tv_sec * 100;
	out->vb_uint32 += diff.tv_usec / 10000;

	return 0;
}

static int snmp_config_reset_time_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out, NDEBUG_UNUSED fr_snmp_map_t const *map,
				      UNUSED void *snmp_ctx)
{
	struct timeval now;
	struct timeval diff;

	rad_assert(map->da->type == FR_TYPE_UINT32);

	gettimeofday(&now, NULL);
	fr_timeval_subtract(&diff, &now, &reset_time);

	out->vb_uint32 = diff.tv_sec * 100;
	out->vb_uint32 += diff.tv_usec / 10000;

	return 0;
}

static int snmp_config_reset_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out, NDEBUG_UNUSED fr_snmp_map_t const *map,
				 UNUSED void *snmp_ctx)
{
	rad_assert(map->da->type == FR_TYPE_UINT32);

	out->vb_uint32 = reset_state;

	return 0;
}

static int snmp_config_reset_set(NDEBUG_UNUSED fr_snmp_map_t const *map, UNUSED void *snmp_ctx, fr_value_box_t *in)
{
	rad_assert(map->da->type == FR_TYPE_UINT32);

	switch (in->vb_uint32) {
	case FR_RADIUS_AUTH_SERV_CONFIG_RESET_VALUE_RESET:
		radius_signal_self(RADIUS_SIGNAL_SELF_HUP);
		gettimeofday(&reset_time, NULL);
		return 0;

	default:
		return -(FR_FREERADIUS_SNMP_FAILURE_VALUE_WRONG_VALUE);
	}

}

static int snmp_auth_stats_offset_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out,
				      fr_snmp_map_t const *map, UNUSED void *snmp_ctx)
{
	rad_assert(map->da->type == FR_TYPE_UINT32);

	out->vb_uint32 = *(uint32_t *)((uint8_t *)(&radius_auth_stats) + map->offset);

	return 0;
}

static int snmp_client_index(UNUSED TALLOC_CTX *ctx, void **snmp_ctx_out,
			     UNUSED fr_snmp_map_t const *map,
			     NDEBUG_UNUSED void const *snmp_ctx_in, uint32_t index_num)
{
	RADCLIENT *client;

	rad_assert(!snmp_ctx_in);

	client = client_findbynumber(NULL, index_num - 1);	/* Clients indexed from 0 */
	if (!client) return 1;		/* No more clients */

	*snmp_ctx_out = client;

	return 0;
}

static int snmp_client_index_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out,
				 UNUSED fr_snmp_map_t const *map, void *snmp_ctx)
{
	RADCLIENT *client = snmp_ctx;

	rad_assert(client);

	out->vb_uint32 = client->number + 1;		/* Clients indexed from 0 */

	return 0;
}

static int snmp_client_ipv4addr_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out,
				    NDEBUG_UNUSED fr_snmp_map_t const *map, void *snmp_ctx)
{
	RADCLIENT *client = snmp_ctx;

	rad_assert(client);
	rad_assert(map->da->type == FR_TYPE_IPV4_ADDR);

	/*
	 *	The old SNMP MIB only allowed access
	 *	to the IPv4 address.
	 *
	 *	The EXT mib allows access to either
	 *	address.
	 */
	if (client->ipaddr.af != AF_INET) return 0;
	memcpy(&out->vb_ip, &client->ipaddr, sizeof(out->vb_ip));

	return 0;
}

static int snmp_client_id_get(TALLOC_CTX *ctx, fr_value_box_t *out,
			      NDEBUG_UNUSED fr_snmp_map_t const *map, void *snmp_ctx)
{
	RADCLIENT *client = snmp_ctx;
	size_t len;

	rad_assert(client);
	rad_assert(map->da->type == FR_TYPE_STRING);

	len = talloc_array_length(client->longname) - 1;

	out->vb_strvalue = talloc_bstrndup(ctx, client->longname, len);
	out->datum.length = len;

	return 0;
}

static int snmp_auth_client_stats_offset_get(UNUSED TALLOC_CTX *ctx, fr_value_box_t *out,
				  	     fr_snmp_map_t const *map, void *snmp_ctx)
{
	RADCLIENT *client = snmp_ctx;

	rad_assert(client);
	rad_assert(map->da->type == FR_TYPE_UINT32);

	out->vb_uint32 = *(uint32_t *)((uint8_t *)(&client->auth) + map->offset);

	return 0;
}

static fr_snmp_map_t snmp_auth_client_entry_counters[] = {
	{ .name = "Radius-Auth-Client-Index",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_INTEGER,
	  .get = snmp_client_index_get },
	{ .name = "Radius-Auth-Client-Address",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_IPADDRESS,
	  .get = snmp_client_ipv4addr_get },
	{ .name = "Radius-Auth-Client-ID",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_STRING,
	  .get = snmp_client_id_get },
	{ .name = "Radius-Auth-Serv-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_requests),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Dup-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_dup_requests),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Access-Accepts",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_accepts),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Access-Rejects",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_rejects),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Access-Challenges",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_challenges),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Malformed-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_malformed_requests),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Bad-Authenticators",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_bad_authenticators),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Packets-Dropped",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_packets_dropped),
	  .get = snmp_auth_client_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Unknown-Types",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_unknown_types),
	  .get = snmp_auth_client_stats_offset_get },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_auth_client_entry[] = {
	{ .name = "Radius-Auth-Client-Entry",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .index = snmp_client_index,
	  .child = snmp_auth_client_entry_counters },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_auth_serv_counters[] = {
	{ .name = "Radius-Auth-Serv-Ident",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_STRING,
	  .get = snmp_value_serv_ident_get },
	{ .name = "Radius-Auth-Serv-Up-Time",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_TIMETICKS,
	  .get = snmp_value_uptime_get },
	{ .name = "Radius-Auth-Serv-Reset-Time",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_TIMETICKS,
	  .get = snmp_config_reset_time_get},
	{ .name = "Radius-Auth-Serv-Config-Reset",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_INTEGER,
	  .get = snmp_config_reset_get,
	  .set = snmp_config_reset_set },
	{ .name = "Radius-Auth-Serv-Total-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_requests),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Invalid-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_invalid_requests),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Dup-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_dup_requests),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Access-Accepts",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_accepts),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Access-Rejects",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_rejects),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Access-Challenges",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_access_challenges),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Malformed-Access-Requests",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_malformed_requests),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Bad-Authenticators",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_bad_authenticators),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Packets-Dropped",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_packets_dropped),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Serv-Total-Unknown-Types",
	  .type = FR_FREERADIUS_SNMP_TYPE_VALUE_COUNTER,
	  .offset = offsetof(fr_stats_t, total_unknown_types),
	  .get = snmp_auth_stats_offset_get },
	{ .name = "Radius-Auth-Client-table",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_auth_client_entry},
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_auth_serv[] = {
	{ .name = "Radius-Auth-Serv",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_auth_serv_counters },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_auth_serv_mib_objects[] = {
	{ .name = "Radius-Auth-Serv-Mib-Objects",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_auth_serv },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_auth_serv_mib[] = {
	{ .name = "Radius-Auth-Serv-Mib",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_auth_serv_mib_objects },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_authentication[] = {
	{ .name = "Radius-Authentication",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_auth_serv_mib },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_radius_mib[] = {
	{ .name = "Radius-Mib",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_authentication },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_mib_2[] = {
	{ .name = "FreeRADIUS-Mib-2",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_radius_mib },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_mgmt[] = {
	{ .name = "FreeRADIUS-Mgmt",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_mib_2 },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_internet[] = {
	{ .name = "FreeRADIUS-Internet",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_mgmt },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_dod[] = {
	{ .name = "FreeRADIUS-Dod",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_internet },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_org[] = {
	{ .name = "FreeRADIUS-Org",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_dod },
	SNMP_MAP_TERMINATOR
};

static fr_snmp_map_t snmp_iso[] = {
	{ .name = "FreeRADIUS-Iso",
	  .type = FR_FREERADIUS_SNMP_TYPE_OBJECT,
	  .child = snmp_org },
	SNMP_MAP_TERMINATOR
};

static ssize_t snmp_process(fr_cursor_t *out, REQUEST *request,
			    fr_dict_attr_t const *tlv_stack[], unsigned int depth,
			    fr_cursor_t *cursor,
			    fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op);

/** Perform a binary search to find a map matching a da
 *
 * @param map to search in.
 * @param da to search for.
 * @return
 *	- Matching map if da was found.
 *	- NULL if da was not found.
 */
static fr_snmp_map_t const *snmp_map_search(fr_snmp_map_t const map[], fr_dict_attr_t const *da)
{
	fr_snmp_map_t const *p = &map[1], *q = map[0].last, *m;

	rad_assert(p <= q);

	/*
	 *	Fast path...
	 */
	if (p == q) {
		rad_assert(p->da);

		if (p->da->attr == da->attr) return p;
		return NULL;
	}

	m = p + ((q - p) / 2);

	while (p <= q) {
		if (m->da->attr < da->attr) p = m + 1;
		else if (m->da->attr == da->attr) break;
		else q = m - 1;
		m = p + ((q - p) / 2);
	}
	if (p > q) return NULL;

	return m;
}

/** Perform depth first traversal of the tree until we hit a leaf node
 *
 * This is used for building a fake tlv_stack, for findNext, so that if
 * we get a findNext operation on something that's not a leaf, we can
 * find the first leaf under that branch of the tree.
 *
 * @param[out] tlv_stack to rewrite.
 * @param[in] depth at which to start rewriting.
 * @param[in] map at this level.
 */
static void snmp_next_leaf(fr_dict_attr_t const *tlv_stack[], unsigned int depth, fr_snmp_map_t const *map)
{
	uint32_t i;
	fr_snmp_map_t const *map_p = map;

	for (i = depth; (i < FR_DICT_MAX_TLV_STACK) && map_p; i++) {
		tlv_stack[i] = map_p->da;
		map_p = map_p->child;
	}
	tlv_stack[i] = NULL;
}

static ssize_t snmp_process_index(fr_cursor_t *out, REQUEST *request,
				  fr_dict_attr_t const *tlv_stack[], unsigned int depth,
				  fr_cursor_t cursor,
				  fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op,
				  uint32_t index_num)
{
	ssize_t		ret;
	uint32_t 	i;

	/*
	 *	Can't modify snmp_ctx, as we may need to go back up
	 *	the stack, and retry when performing a getNext.
	 */
	void		*this_snmp_ctx = NULL;
	TALLOC_CTX	*tmp_ctx;

	for (i = index_num; i < UINT32_MAX; i++) {
		fr_dict_attr_t const	*da;
		VALUE_PAIR		*vp;

		tmp_ctx = talloc_new(request);
		if (!tmp_ctx) {
			fr_strerror_printf("Out Of Memory");
			return -(depth);
		}

		ret = map->index(tmp_ctx, &this_snmp_ctx, map, snmp_ctx, i);
		if (ret < 0) {
			talloc_free(tmp_ctx);
			return ret;		/* error */
		}
		if (ret > 0) {
			talloc_free(tmp_ctx);

			if (snmp_op != FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT) {
			invalid:
				fr_strerror_printf("Invalid OID: Match stopped here");
				return -(depth);
			}

			return ret;		/* no more entries at this level, findNext at lower level */
		}

		ret = snmp_process(out, request,
				   tlv_stack, depth + 1,
				   &cursor,
				   map->child, this_snmp_ctx, snmp_op);
		TALLOC_FREE(tmp_ctx);

		if (ret < 0) return ret;	/* error */
		if (ret > 0) {			/* findNext */
			if (snmp_op != FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT) goto invalid;

			/*
			 *	Rebuild the stack to point to the first
			 *	leaf (usually .1) of the entry.
			 *
			 *	If we've unwound to this level then we're
			 *	going to try again with a new entry.
			 *	We need to start at the start of that
			 *	entry, not at the end (where we previously
			 *	were).
			 */
			fr_proto_tlv_stack_build(tlv_stack, map->da);
			this_snmp_ctx = NULL;
			continue;
		}

		/*
		 *	Success! - Build and prepend an index
		 *	attribute to let the client know which entry
		 *	we processed.
		 */
		da = fr_dict_attr_child_by_num(map->da->parent, 0);
		if (!da) {
			fr_strerror_printf("No index attribute defined for \"%s\"", map->name);
			return -(depth);
		}

		vp = fr_pair_afrom_da(request->reply, da);
		if (!vp) return 0;

		vp->vp_uint32 = i;
		fr_cursor_prepend(out, vp);

		return 0;			/* done */
	}

	fr_strerror_printf("Invalid OID: Hit max index");

	return -(depth);
}

static ssize_t snmp_process_index_attr(fr_cursor_t *out, REQUEST *request,
				       fr_dict_attr_t const *tlv_stack[], unsigned int depth,
				       fr_cursor_t *cursor,
				       fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op)
{
	VALUE_PAIR	*next;
	uint32_t	index_num;
	VALUE_PAIR	*vp;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	if (map[0].last < &map[1]) {
		fr_strerror_printf("Invalid OID: Empty map");
	error:
		return -(ssize_t)depth;
	}

	if (map[1].type != FR_FREERADIUS_SNMP_TYPE_OBJECT) {
		fr_strerror_printf("Invalid OID: Cannot traverse leaf");
		goto error;
	}

	if (!map[1].index) {
		fr_strerror_printf("Invalid OID: Got index attribute, but SNMP object is not "
				   "a table entry");
		goto error;
	}

	if (tlv_stack[depth]->type != FR_TYPE_UINT32) {
		fr_strerror_printf("Bad index attribute: Index attribute \"%s\" should be a integer, "
				   "but is a %s", tlv_stack[depth]->name,
				   fr_int2str(dict_attr_types, tlv_stack[depth]->type, "?Unknown?"));
		goto error;
	}

	/*
	 *	Get the index from the index attribute's value.
	 */
	vp = fr_cursor_current(cursor);
	index_num = vp->vp_uint32;

	/*
	 *	Advance the cursor to the next index attribute
	 *	if it is an index attribute...
	 */
	next = fr_cursor_next_peek(cursor);
	if (next && fr_dict_parent_common(vp->da, next->da, true)) {
		fr_proto_tlv_stack_build(tlv_stack, next->da);

		while ((next = fr_cursor_next(cursor))) if (fr_dict_parent_common(vp->da, next->da, true)) break;
	}

	return snmp_process_index(out, request,
				  tlv_stack, depth,
				  *cursor,
				  &map[1], snmp_ctx, snmp_op,
				  index_num);
}

static ssize_t snmp_process_tlv(fr_cursor_t *out, REQUEST *request,
				fr_dict_attr_t const *tlv_stack[], unsigned int depth,
				fr_cursor_t *cursor,
				fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op)
{
	fr_snmp_map_t const	*map_p;
	ssize_t			ret;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	Return element in map that matches the da at this
	 *	level in the tlv_stack.
	 */
	map_p = snmp_map_search(map, tlv_stack[depth]);
	if (!map_p) {
	invalid:
		fr_strerror_printf("Invalid OID: Match stopped here");
	error:
		return -(ssize_t)depth;
	}

	if (!map_p->child) {
		fr_strerror_printf("Internal error: Dictionary and SNMP map structure mismatch");
		goto error;
	}

	/*
	 *	Allow for attributes that represent fixed indexes
	 *	usually *-Entry attributes.
	 *
	 *	This allows a complete SNMP OID to be represented
	 *	as a single attribute (with index 1 being used for
	 *	each traversal).
	 *
	 *	The real purpose is to allow the fake tlv_stack
	 *	code to work correctly without needing to add
	 *	fake index attributes
	 */
	if (map_p->index) {
		return snmp_process_index(out, request,
					  tlv_stack, depth,
					  *cursor,
					  map_p, snmp_ctx, snmp_op,
					  tlv_stack[depth]->attr);
	}

	for (;;) {
		ret = snmp_process(out, request,
				   tlv_stack, depth + 1,
				   cursor,
				   map_p->child, snmp_ctx, snmp_op);
		if (ret < 0) return ret;	/* error */
		if (ret > 0) {			/* findNext */
			if (snmp_op != FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT) goto invalid;
			if (++map_p <= map[0].last) continue;
			return 1;		/* findNext at lower level */
		}
		return 0;			/* done */
	}
}

static ssize_t snmp_process_leaf(fr_cursor_t *out, REQUEST *request,
				 fr_dict_attr_t const *tlv_stack[], unsigned int depth,
				 fr_cursor_t *cursor,
				 fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op)
{
	VALUE_PAIR		*vp;
	fr_snmp_map_t const	*map_p;

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	vp = fr_cursor_current(cursor);

	/*
	 *	Return element in map that matches the da at this
	 *	level in the tlv_stack.
	 */
	map_p = snmp_map_search(map, tlv_stack[depth]);
	if (!map_p) {
		fr_strerror_printf("Invalid OID: Match stopped here");
	error:
		return -(ssize_t)depth;
	}

	/*
	 *	It's a leaf attribute, call the correct get/set function
	 */
	switch (snmp_op) {
	case FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT:
		if (map_p == map[0].last) {
			return 1;	/* findNext at lower level */
		}
		if (map_p->da == vp->da) {		/* Next unless we faked part of the stack */
			map_p++;

			/*
			 *	We were called with a leaf map, but advanced
			 *	to a non-leaf map.
			 */
			if (map_p->type == FR_FREERADIUS_SNMP_TYPE_OBJECT) {
				return snmp_process(out, request,
						    tlv_stack, depth + 1,
						    cursor,
						    map_p->child, snmp_ctx, snmp_op);
			}
		}
		/* FALL-THROUGH */

	case FR_FREERADIUS_SNMP_OPERATION_VALUE_GET:
	{
		fr_value_box_t data;

		memset(&data, 0, sizeof(data));

		/*
		 *	Verify map is a leaf
		 */
		if (map_p->type == FR_FREERADIUS_SNMP_TYPE_OBJECT) {
			fr_strerror_printf("Invalid OID: Is not a leaf node");
			goto error;
		}

		if (!map_p->get) {
			fr_strerror_printf("Invalid operation: Node does not support GET operations");
			goto error;
		}

		/*
		 *	Get functions can only return a single
		 *	attribute.  To reduce boilerplate code
		 *	in callbacks, we handled allocating and
		 *	inserting VALUE_PAIRs, and pass in a
		 *	fr_value_box_t struct for the callback
		 *	to complete.
		 */
		if (map_p->get(request->reply, &data, map_p, snmp_ctx) < 0) goto error;

		vp = fr_pair_afrom_da(request->reply, map_p->da);
		if (!vp) return 0;
		fr_value_box_steal(vp, &vp->data, &data);
		fr_cursor_append(out, vp);

		vp = fr_pair_afrom_da(request->reply, fr_snmp_type);
		if (!vp) return 0;
		vp->vp_uint32 = map_p->type;
		fr_cursor_append(out, vp);
	}
		return 0;

	case FR_FREERADIUS_SNMP_OPERATION_VALUE_SET:
	{
		ssize_t ret;

		if (!map_p->set || (map_p->type == FR_FREERADIUS_SNMP_TYPE_OBJECT)) {
			vp = fr_pair_afrom_da(request->reply, fr_snmp_failure);
			if (!vp) return 0;
			vp->vp_uint32 = FR_FREERADIUS_SNMP_FAILURE_VALUE_NOT_WRITABLE;
			fr_cursor_append(out, vp);
			return 0;
		}

		vp = fr_cursor_current(cursor);
		ret = map_p->set(map_p, snmp_ctx, &vp->data);
		if (ret < 0) switch (-(ret)) {
		case FR_FREERADIUS_SNMP_FAILURE_VALUE_NOT_WRITABLE:
		case FR_FREERADIUS_SNMP_FAILURE_VALUE_WRONG_TYPE:
		case FR_FREERADIUS_SNMP_FAILURE_VALUE_WRONG_LENGTH:
		case FR_FREERADIUS_SNMP_FAILURE_VALUE_WRONG_VALUE:
		case FR_FREERADIUS_SNMP_FAILURE_VALUE_INCONSISTENT_VALUE:
			vp = fr_pair_afrom_da(request->reply, fr_snmp_failure);
			if (!vp) break;

			vp->vp_uint32 = -(ret);
			fr_cursor_append(out, vp);
			break;

		default:
			goto error;
		}
	}
		return 0;

	default:
		rad_assert(0);
		goto error;
	}
}

/** Traverse a tree of SNMP maps
 *
 * @param[out] out		Where to write response attributes.
 * @param[in] request		The current request.
 * @param[in,out] tlv_stack	we're traversing.
 * @param[in] depth		we're currently at in the tlv_stack.
 * @param[in] cursor		representing the current attribute we're processing.
 * @param[in] map		matching the current depth in the tlv_stack.
 * @param[in] snmp_ctx		allocated by the previous index traversal function.
 * @param[in] snmp_op		we're performing.
 * @return
 *	- 0 on success.
 *	- 1 to signal caller that it should find the next OID at this level
 *	and recurse again.
 *	- <0 the depth at which an error occurred, as a negative integer.
 */
static ssize_t snmp_process(fr_cursor_t *out, REQUEST *request,
			    fr_dict_attr_t const *tlv_stack[], unsigned int depth,
			    fr_cursor_t *cursor,
			    fr_snmp_map_t const *map, void *snmp_ctx, unsigned int snmp_op)
{
	rad_assert(map);

	FR_PROTO_STACK_PRINT(tlv_stack, depth);

	/*
	 *	We've run out of stack... This is an error unless
	 *	we're performing a getNext operation, in which
	 *	case we fake the rest of the stack.
	 */
	if (!tlv_stack[depth]) {
		if (snmp_op != FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT) {
			fr_strerror_printf("Invalid OID: Not a leaf");
			return -(ssize_t)(depth - 1);
		}
		snmp_next_leaf(tlv_stack, depth, &map[1]);
	}

	/*
	 *	It's an index attribute, use the value of
	 *	the index attribute to traverse the index.
	 */
	if (tlv_stack[depth]->attr == 0) return snmp_process_index_attr(out, request,
									tlv_stack, depth,
									cursor,
									map, snmp_ctx, snmp_op);

	/*
	 *	It's a TLV, recurse, and locate the map
	 *	matching the next deepest DA in the
	 *	tlv_stack.
	 */
	if (tlv_stack[depth]->type == FR_TYPE_TLV) return snmp_process_tlv(out, request,
									   tlv_stack, depth,
									   cursor,
									   map, snmp_ctx, snmp_op);

	/*
	 *	Must be a leaf, call the appropriate get/set function
	 *	and create attributes for the response.
	 */
	return snmp_process_leaf(out, request,
				 tlv_stack, depth,
				 cursor,
				 map, snmp_ctx, snmp_op);
}

int fr_snmp_process(REQUEST *request)
{
	fr_cursor_t		request_cursor, op_cursor, out_cursor, reply_cursor;
	VALUE_PAIR		*head = NULL, *vp;

	char			oid_str[FR_DICT_MAX_TLV_STACK * 4];	/* .<num>{1,3} */
	size_t			oid_len, len;

	fr_dict_attr_t const	*tlv_stack[FR_DICT_MAX_TLV_STACK + 1];
	unsigned int		depth;
	ssize_t			ret;

	VALUE_PAIR		*op;

	fr_cursor_init(&request_cursor, &request->packet->vps);
	fr_cursor_iter_by_da_init(&op_cursor, &request->packet->vps, fr_snmp_op_attr);
	fr_cursor_init(&reply_cursor, &request->reply->vps);
	fr_cursor_init(&out_cursor, &head);

	RDEBUG2("Processing SNMP stats request");

	/*
	 *	First take a pass over the request, converting
	 *	any unknown types back to real attributes.
	 *
	 *	This hack is required because empty TLVs are
	 *	not allowed in the RADIUS protocol, so we
	 *	encode the TLV as an octet type attribute
	 */
	for (vp = fr_cursor_head(&request_cursor);
	     vp;
	     vp = fr_cursor_next(&request_cursor)) {
		fr_dict_attr_t const *da;

		if (!vp->da->flags.is_unknown) continue;

		da = fr_dict_attr_known(NULL, vp->da);
		if (!da) {
			WARN("Failed converting \"%s\" to a known attribute", vp->da->name);
			continue;
		}

		RDEBUG2("Unknown attribute \"%s\" resolves to \"%s\"", vp->da->name, da->name);

		/*
		 *	Clear out any junk values
		 */
		if (da->type == FR_TYPE_TLV) {
			switch (vp->vp_type) {
			case FR_TYPE_OCTETS:
			case FR_TYPE_STRING:
				talloc_free(vp->data.datum.ptr);

			/* FALL-THROUGH */
			default:
				memset(&vp->data, 0, sizeof(vp->data));
			}
		}
		vp->da = da;
	}

	for (vp = fr_cursor_iter_by_ancestor_init(&request_cursor, &request->packet->vps, fr_snmp_root);
	     vp;
	     vp = fr_cursor_next(&request_cursor)) {
		fr_proto_tlv_stack_build(tlv_stack, vp->da);

		/*
		 *	Wind to the frame in the TLV stack that matches our
		 *	SNMP root.
		 */
		for (depth = 0; tlv_stack[depth]; depth++) if (fr_snmp_root == tlv_stack[depth]) break;

		/*
		 *	Any attribute returned by fr_cursor_next_by_ancestor
		 *	should have the SNMP root attribute as an ancestor.
		 */
		rad_assert(tlv_stack[depth]);
		rad_assert(tlv_stack[depth] == fr_snmp_root);

		/*
		 *	Operator attribute acts as a request delimiter
		 */
		op = fr_cursor_current(&op_cursor);
		if (!op) {
			ERROR("Missing operation (%s)", fr_snmp_op_attr->name);
			return -1;
		}
		fr_cursor_next(&op_cursor);

		switch (op->vp_uint32) {
		case FR_FREERADIUS_SNMP_OPERATION_VALUE_PING:
		case FR_FREERADIUS_SNMP_OPERATION_VALUE_GET:
		case FR_FREERADIUS_SNMP_OPERATION_VALUE_GETNEXT:
		case FR_FREERADIUS_SNMP_OPERATION_VALUE_SET:
			break;

		default:
			ERROR("Invalid operation %u", vp->vp_uint32);
			return -1;
		}

		/*
		 *	Returns depth (as negative integer) at which the error occurred
		 */
		ret = snmp_process(&out_cursor, request,
				   tlv_stack, depth,
				   &request_cursor,
				   snmp_iso, NULL, op->vp_uint32);
		if (ret < 0) {
			fr_pair_list_free(&head);

			oid_str[0] = '.';

			/* Get the length of the matching part */
			oid_len = fr_dict_print_attr_oid(oid_str + 1, sizeof(oid_str) - 1, fr_snmp_root, tlv_stack[-(ret)]);

			/* Get the last frame in the current stack */
			for (depth = 0; tlv_stack[depth + 1]; depth++);
			len = fr_dict_print_attr_oid(oid_str + 1, sizeof(oid_str) - 1, fr_snmp_root, tlv_stack[depth]);

			/* Use the difference in OID string length to place the marker */
			REMARKER(oid_str, oid_len - (len - oid_len), fr_strerror());

			return -1;
		}
	}

	fr_cursor_head(&out_cursor);
	fr_cursor_merge(&reply_cursor, &out_cursor);

	return 0;
}

/** Internal SNMP initialisation function (used for recursion)
 *
 */
static int _fr_snmp_init(fr_snmp_map_t map[])
{
	unsigned int i;

	for (i = 0; map[i].name; i++) {
		if (map[i].type == FR_FREERADIUS_SNMP_TYPE_OBJECT) {
			int ret;

			rad_assert(map[i].child);

			map[i].da = fr_dict_attr_by_name(NULL, map[i].name);
			if (!map[i].da) {
				ERROR("Incomplete dictionary: Missing definition for \"%s\"", map[i].name);
				return -1;
			}

			ret = _fr_snmp_init(map[i].child);
			if (ret < 0) return -1;

			continue;
		}

		map[i].da = fr_dict_attr_by_name(NULL, map[i].name);
		if (!map[i].da) {
			ERROR("Incomplete dictionary: Missing definition for \"%s\"", map[i].name);
			return -1;
		}
	}

	/*
	 *	Shift the contents of the map, clearing the first entry.
	 *
	 *	@note We could also do a quicksort here but we assume
	 *	that future developers will heed this warning to list
	 *	attributes in ascending order.
	 */
	memmove(&map[1], map, sizeof(*map) * i);
	memset(&map[0], 0, sizeof(*map));
	map[0].name = "Not the map offset you were looking for";
	map[0].last = &map[i];	/* This allows us to perform a binary search in the array */

	return 0;
}

/** Initialise the tree of SNMP map structures used to attach callbacks to OIDs
 *
 */
int fr_snmp_init(void)
{

#define CACHE_DA(_v, _n) \
do { \
	_v = fr_dict_attr_by_name(NULL, _n); \
	if (!_v) { \
		ERROR("Incomplete dictionary: Missing definition for \"%s\"", _n); \
		return -1; \
	} \
} while(0);

	gettimeofday(&uptime, NULL);
	reset_time = uptime;

	CACHE_DA(fr_snmp_op_attr, "FreeRADIUS-SNMP-Operation");
	CACHE_DA(fr_snmp_type, "FreeRADIUS-SNMP-Type");
	CACHE_DA(fr_snmp_failure, "FreeRADIUS-SNMP-Failure");
	CACHE_DA(fr_snmp_root, "FreeRADIUS-Iso");		/* Common root for all SNMP OID TLVs */

	return _fr_snmp_init(snmp_iso);	/* The SNMP root node */
}
