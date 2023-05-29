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
 * @file rlm_stats.c
 * @brief Keep RADIUS statistics. Eventually, also non-RADIUS statistics
 *
 * @copyright 2017 Network RADIUS SAS (license@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/radius/radius.h>

#include <freeradius-devel/protocol/radius/freeradius.h>

/*
 *	@todo - also get the statistics from the network side for
 *		that, though, we need a way to find other network
 *		sockets (i.e. not this one), and then query them for
 *		statistics.
 */

#include <pthread.h>

/*
 *	@todo - MULTI_PROTOCOL - make this protocol agnostic.
 *	Perhaps keep stats in a hash table by (request->dict, request->code) ?
 */

typedef struct {
	pthread_mutex_t		mutex;
	fr_dict_attr_t const	*type_da;			//!< FreeRADIUS-Stats4-Type
	fr_dict_attr_t const	*ipv4_da;			//!< FreeRADIUS-Stats4-IPv4-Address
	fr_dict_attr_t const	*ipv6_da;			//!< FreeRADIUS-Stats4-IPv6-Address
	fr_dlist_head_t		list;				//!< for threads to know about each other

	uint64_t		stats[FR_RADIUS_CODE_MAX];
} rlm_stats_t;

typedef struct {
	fr_rb_node_t		src_node;
	fr_rb_node_t		dst_node;
	fr_ipaddr_t		ipaddr;				//!< IP address of this thing
	fr_time_t		created;			//!< when it was created
	fr_time_t		last_packet;			//!< when we last saw a packet
	uint64_t		stats[FR_RADIUS_CODE_MAX];	//!< actual statistic
} rlm_stats_data_t;

typedef struct {
	rlm_stats_t		*inst;

	fr_time_t		last_global_update;
	fr_dlist_t		entry;				//!< for threads to know about each other

	fr_time_t		last_manage;			//!< when we deleted old things

	fr_rb_tree_t		*src;				//!< stats by source
	fr_rb_tree_t		*dst;				//!< stats by destination

	uint64_t		stats[FR_RADIUS_CODE_MAX];

	pthread_mutex_t		mutex;
} rlm_stats_thread_t;

static const CONF_PARSER module_config[] = {
	CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_stats_dict[];
fr_dict_autoload_t rlm_stats_dict[] = {
	{ .out = &dict_radius, .proto = "radius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_freeradius_stats4_ipv4_address;
static fr_dict_attr_t const *attr_freeradius_stats4_ipv6_address;
static fr_dict_attr_t const *attr_freeradius_stats4_type;

extern fr_dict_attr_autoload_t rlm_stats_dict_attr[];
fr_dict_attr_autoload_t rlm_stats_dict_attr[] = {
	{ .out = &attr_freeradius_stats4_ipv4_address, .name = "Vendor-Specific.FreeRADIUS.Stats4.Stats4-IPv4-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_freeradius_stats4_ipv6_address, .name = "Vendor-Specific.FreeRADIUS.Stats4.Stats4-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_radius },
	{ .out = &attr_freeradius_stats4_type, .name = "Vendor-Specific.FreeRADIUS.Stats4.Stats4-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

static void coalesce(uint64_t final_stats[FR_RADIUS_CODE_MAX], rlm_stats_thread_t *t,
		     size_t tree_offset, rlm_stats_data_t *mydata)
{
	rlm_stats_data_t *stats;
	rlm_stats_thread_t *other;
	fr_rb_tree_t **tree;
	uint64_t local_stats[FR_RADIUS_CODE_MAX];

	tree = (fr_rb_tree_t **) (((uint8_t *) t) + tree_offset);

	/*
	 *	Bootstrap with my statistics, where we don't need a
	 *	lock.
	 */
	stats = fr_rb_find(*tree, mydata);
	if (!stats) {
		memset(final_stats, 0, sizeof(uint64_t) * FR_RADIUS_CODE_MAX);
	} else {
		memcpy(final_stats, stats->stats, sizeof(stats->stats));
	}

	/*
	 *	Loop over all of the other thread instances, locking
	 *	them, and adding their statistics in.
	 */
	for (other = fr_dlist_head(&t->inst->list);
	     other != NULL;
	     other = fr_dlist_next(&t->inst->list, other)) {
		int i;

		if (other == t) continue;

		tree = (fr_rb_tree_t **) (((uint8_t *) other) + tree_offset);
		pthread_mutex_lock(&other->mutex);
		stats = fr_rb_find(*tree, mydata);

		if (!stats) {
			pthread_mutex_unlock(&other->mutex);
			continue;
		}
		memcpy(&local_stats, stats->stats, sizeof(stats->stats));

		for (i = 0; i < FR_RADIUS_CODE_MAX; i++) {
			final_stats[i] += local_stats[i];
		}

		pthread_mutex_unlock(&other->mutex);
	}
}


/*
 *	Do the statistics
 */
static unlang_action_t CC_HINT(nonnull) mod_stats(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_stats_t		*inst = talloc_get_type_abort(mctx->inst->data, rlm_stats_t);
	rlm_stats_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_stats_thread_t);
	int			i;
	uint32_t		stats_type;


	fr_pair_t *vp;
	rlm_stats_data_t mydata;
	char buffer[64];
	uint64_t local_stats[NUM_ELEMENTS(inst->stats)];

	/*
	 *	Increment counters only in "send foo" sections.
	 *
	 *	i.e. only when we have a reply to send.
	 *
	 *	FIXME - Nothing sets request_state anymore
	 */
#if 0
	if (request->request_state == REQUEST_SEND) {
		int src_code, dst_code;
		rlm_stats_data_t *stats;

		src_code = request->packet->code;
		if (src_code >= FR_RADIUS_CODE_MAX) src_code = 0;

		dst_code = request->reply->code;
		if (dst_code >= FR_RADIUS_CODE_MAX) dst_code = 0;

		pthread_mutex_lock(&t->mutex);
		t->stats[src_code]++;
		t->stats[dst_code]++;

		/*
		 *	Update source statistics
		 */
		mydata.ipaddr = request->packet->socket.inet.src_ipaddr;
		stats = fr_rb_find(t->src, &mydata);
		if (!stats) {
			MEM(stats = talloc_zero(t, rlm_stats_data_t));

			stats->ipaddr = request->packet->socket.inet.src_ipaddr;
			stats->created = request->async->recv_time;

			(void) fr_rb_insert(t->src, stats);
		}

		stats->last_packet = request->async->recv_time;
		stats->stats[src_code]++;
		stats->stats[dst_code]++;

		/*
		 *	Update destination statistics
		 */
		mydata.ipaddr = request->packet->socket.inet.dst_ipaddr;
		stats = fr_rb_find(t->dst, &mydata);
		if (!stats) {
			MEM(stats = talloc_zero(t, rlm_stats_data_t));

			stats->ipaddr = request->packet->socket.inet.dst_ipaddr;
			stats->created = request->async->recv_time;

			(void) fr_rb_insert(t->dst, stats);
		}

		stats->last_packet = request->async->recv_time;
		stats->stats[src_code]++;
		stats->stats[dst_code]++;
		pthread_mutex_unlock(&t->mutex);

		/*
		 *	@todo - periodically clean up old entries.
		 */

		if ((t->last_global_update + NSEC) > request->async->recv_time) {
			RETURN_MODULE_UPDATED;
		}

		t->last_global_update = request->async->recv_time;

		pthread_mutex_lock(&inst->mutex);
		for (i = 0; i < FR_RADIUS_CODE_MAX; i++) {
			inst->stats[i] += t->stats[i];
			t->stats[i] = 0;
		}
		pthread_mutex_unlock(&inst->mutex);

		RETURN_MODULE_UPDATED;
	}
#endif

	/*
	 *	Ignore "authenticate" and anything other than Status-Server
	 */
	if ((request->packet->code != FR_RADIUS_CODE_STATUS_SERVER)) {
		RETURN_MODULE_NOOP;
	}

	vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_freeradius_stats4_type);
	if (!vp) {
		stats_type = FR_STATS4_TYPE_VALUE_GLOBAL;
	} else {
		stats_type = vp->vp_uint32;
	}

	/*
	 *	Create attributes based on the statistics.
	 */
	MEM(pair_update_reply(&vp, attr_freeradius_stats4_type) >= 0);
	vp->vp_uint32 = stats_type;

	switch (stats_type) {
	case FR_STATS4_TYPE_VALUE_GLOBAL:			/* global */
		/*
		 *	Merge our stats with the global stats, and then copy
		 *	the global stats to a thread-local variable.
		 *
		 *	The copy helps minimize mutex contention.
		 */
		pthread_mutex_lock(&inst->mutex);
		for (i = 0; i < FR_RADIUS_CODE_MAX; i++) {
			inst->stats[i] += t->stats[i];
			t->stats[i] = 0;
		}
		memcpy(&local_stats, inst->stats, sizeof(inst->stats));
		pthread_mutex_unlock(&inst->mutex);
		vp = NULL;
		break;

	case FR_STATS4_TYPE_VALUE_CLIENT:			/* src */
		vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_freeradius_stats4_ipv4_address);
		if (!vp) vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_freeradius_stats4_ipv6_address);
		if (!vp) RETURN_MODULE_NOOP;

		mydata.ipaddr = vp->vp_ip;
		coalesce(local_stats, t, offsetof(rlm_stats_thread_t, src), &mydata);
		break;

	case FR_STATS4_TYPE_VALUE_LISTENER:			/* dst */
		vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_freeradius_stats4_ipv4_address);
		if (!vp) vp = fr_pair_find_by_da_nested(&request->request_pairs, NULL, attr_freeradius_stats4_ipv6_address);
		if (!vp) RETURN_MODULE_NOOP;

		mydata.ipaddr = vp->vp_ip;
		coalesce(local_stats, t, offsetof(rlm_stats_thread_t, dst), &mydata);
		break;

	default:
		REDEBUG("Invalid value '%d' for FreeRADIUS-Stats4-type", stats_type);
		RETURN_MODULE_FAIL;
	}

	if (vp ) {
		vp = fr_pair_copy(request->reply_ctx, vp);
		if (vp) {
			fr_pair_append(&request->reply_pairs, vp);
		}
	}

	/*
	 *	@todo - do this only for RADIUS
	 *	key off of packet ID, and Stats4-Packet-Counters TLV.
	 */
	strcpy(buffer, "FreeRADIUS-Stats4-");

	for (i = 0; i < FR_RADIUS_CODE_MAX; i++) {
		fr_dict_attr_t const *da;

		if (!local_stats[i]) continue;

		strlcpy(buffer + 18, fr_radius_packet_names[i], sizeof(buffer) - 18);
		da = fr_dict_attr_by_name(NULL, fr_dict_root(dict_radius), buffer);
		if (!da) continue;

		MEM(vp = fr_pair_afrom_da(request->reply_ctx, da));
		vp->vp_uint64 = local_stats[i];

		fr_pair_append(&request->reply_pairs, vp);
	}

	RETURN_MODULE_OK;
}


static int8_t data_cmp(const void *one, const void *two)
{
	rlm_stats_data_t const *a = one;
	rlm_stats_data_t const *b = two;

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_stats_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_stats_t);
	rlm_stats_thread_t *t = talloc_get_type_abort(mctx->thread, rlm_stats_thread_t);

	(void) talloc_set_type(t, rlm_stats_thread_t);

	t->inst = inst;

	t->src = fr_rb_inline_talloc_alloc(t, rlm_stats_data_t, src_node, data_cmp, NULL);
	if (unlikely(!t->src)) return -1;

	t->dst = fr_rb_inline_talloc_alloc(t, rlm_stats_data_t, dst_node, data_cmp, NULL);
	if (unlikely(!t->dst)) {
		TALLOC_FREE(t->src);
		return -1;
	}
	pthread_mutex_init(&t->mutex, 0);

	pthread_mutex_lock(&inst->mutex);
	fr_dlist_insert_head(&inst->list, t);
	pthread_mutex_unlock(&inst->mutex);

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_stats_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_stats_thread_t);
	rlm_stats_t		*inst = t->inst;
	int			i;

	pthread_mutex_lock(&inst->mutex);
	for (i = 0; i < FR_RADIUS_CODE_MAX; i++) {
		inst->stats[i] += t->stats[i];
	}
	fr_dlist_remove(&inst->list, t);
	pthread_mutex_unlock(&inst->mutex);
	pthread_mutex_destroy(&t->mutex);

	return 0;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	rlm_stats_t	*inst = talloc_get_type_abort(mctx->inst->data, rlm_stats_t);

	pthread_mutex_init(&inst->mutex, NULL);
	fr_dlist_init(&inst->list, rlm_stats_thread_t, entry);

	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(module_detach_ctx_t const *mctx)
{
	rlm_stats_t *inst = talloc_get_type_abort(mctx->inst->data, rlm_stats_t);

	pthread_mutex_destroy(&inst->mutex);

	/* free things here */
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to MODULE_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern module_rlm_t rlm_stats;

module_rlm_t rlm_stats = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "stats",
		.inst_size		= sizeof(rlm_stats_t),
		.thread_inst_size	= sizeof(rlm_stats_thread_t),
		.config			= module_config,
		.instantiate		= mod_instantiate,
		.detach			= mod_detach,
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach
	},
	.method_names = (module_method_name_t[]){
		{ .name1 = CF_IDENT_ANY,	.name2 = CF_IDENT_ANY,		.method = mod_stats },
		MODULE_NAME_TERMINATOR
	}
};
