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
 * @copyright 2017 Network RADIUS SARL <license@networkradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modules.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/server/rad_assert.h>

/*
 *	@todo - also get the statistics from the network side for
 *		that, though, we need a way to find other network
 *		sockets (i.e. not this one), and then query them for
 *		statistics.
 */

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#define PTHREAD_MUTEX_LOCK   pthread_mutex_lock
#define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock

#else
#define PTHREAD_MUTEX_LOCK
#define PTHREAD_MUTEX_UNLOCK
#endif

typedef struct rlm_stats_t {
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;
#endif

	fr_dict_attr_t const	*type_da;			//!< FreeRADIUS-Stats4-Type
	fr_dict_attr_t const	*ipv4_da;			//!< FreeRADIUS-Stats4-IPv4-Address
	fr_dict_attr_t const	*ipv6_da;			//!< FreeRADIUS-Stats4-IPv6-Address
	fr_dlist_head_t		list;				//!< for threads to know about each other

	uint64_t		stats[FR_MAX_PACKET_CODE];
} rlm_stats_t;

typedef struct rlm_stats_data_t {
	fr_ipaddr_t		ipaddr;				//!< IP address of this thing
	fr_time_t		created;			//!< when it was created
	fr_time_t		last_packet;			//!< when we last saw a packet
	uint64_t		stats[FR_MAX_PACKET_CODE];	//!< actual statistic
} rlm_stats_data_t;

typedef struct rlm_stats_thread_t {
	rlm_stats_t		*inst;

	fr_time_t		last_global_update;
	fr_dlist_t		entry;				//!< for threads to know about each other

	fr_time_t		last_manage;			//!< when we deleted old things

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		src_mutex;
#endif
	rbtree_t		*src;				//!< stats by source

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		dst_mutex;
#endif
	rbtree_t		*dst;				//!< stats by destination

	uint64_t		stats[FR_MAX_PACKET_CODE];
} rlm_stats_thread_t;

static const CONF_PARSER module_config[] = {
	CONF_PARSER_TERMINATOR
};

static fr_dict_t *dict_radius;

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
	{ .out = &attr_freeradius_stats4_ipv4_address, .name = "FreeRADIUS-Stats4-IPv4-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
	{ .out = &attr_freeradius_stats4_ipv6_address, .name = "FreeRADIUS-Stats4-IPv6-Address", .type = FR_TYPE_IPV6_ADDR, .dict = &dict_radius },
	{ .out = &attr_freeradius_stats4_type, .name = "FreeRADIUS-Stats4-Type", .type = FR_TYPE_UINT32, .dict = &dict_radius },
	{ NULL }
};

static void coalesce(uint64_t final_stats[FR_MAX_PACKET_CODE], rlm_stats_thread_t *t,
		     size_t mutex_offset, size_t tree_offset,
		     rlm_stats_data_t *mydata)
{
	rlm_stats_data_t *stats;
	rlm_stats_thread_t *other;
#ifdef HAVE_PTHREAD_H
	pthread_mutex_t *mutex;
#endif
	rbtree_t **tree;
	uint64_t local_stats[FR_MAX_PACKET_CODE];

	tree = (rbtree_t **) (((uint8_t *) t) + tree_offset);

	/*
	 *	Bootstrap with my statistics, where we don't need a
	 *	lock.
	 */
	stats = rbtree_finddata(*tree, mydata);
	if (!stats) {
		memset(final_stats, 0, sizeof(uint64_t) * FR_MAX_PACKET_CODE);
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

		tree = (rbtree_t **) (((uint8_t *) other) + tree_offset);
#ifdef HAVE_PTHREAD_H
		mutex = (pthread_mutex_t *) (((uint8_t *) other) + mutex_offset);
#endif
		PTHREAD_MUTEX_LOCK(mutex);
		stats = rbtree_finddata(*tree, mydata);
		if (!stats) {
			PTHREAD_MUTEX_UNLOCK(mutex);
			continue;
		}
		memcpy(&local_stats, stats->stats, sizeof(stats->stats));
		PTHREAD_MUTEX_UNLOCK(mutex);

		for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
			final_stats[i] += local_stats[i];
		}
	}
}


/*
 *	Do the statistics
 */
static rlm_rcode_t CC_HINT(nonnull) mod_stats(void *instance, void *thread, REQUEST *request)
{
	int i;
	uint32_t stats_type;
	rlm_stats_thread_t *t = thread;
	rlm_stats_t *inst = instance;
	VALUE_PAIR *vp;
	rlm_stats_data_t mydata, *stats;
	fr_cursor_t cursor;
	char buffer[64];
	uint64_t local_stats[sizeof(inst->stats) / sizeof(inst->stats[0])];

	/*
	 *	Increment counters only in "send foo" sections.
	 *
	 *	i.e. only when we have a reply to send.
	 */
	if (request->request_state == REQUEST_SEND) {
		int src_code, dst_code;

		src_code = request->packet->code;
		if (src_code >= FR_MAX_PACKET_CODE) src_code = 0;

		dst_code = request->reply->code;
		if (dst_code >= FR_MAX_PACKET_CODE) dst_code = 0;

		t->stats[src_code]++;
		t->stats[dst_code]++;

		/*
		 *	Update source statistics
		 */
		mydata.ipaddr = request->packet->src_ipaddr;
		stats = rbtree_finddata(t->src, &mydata);
		if (!stats) {
			MEM(stats = talloc_zero(t, rlm_stats_data_t));

			stats->ipaddr = request->packet->src_ipaddr;
			stats->created = request->async->recv_time;

			PTHREAD_MUTEX_LOCK(&t->src_mutex);
			(void) rbtree_insert(t->src, stats);
			PTHREAD_MUTEX_UNLOCK(&t->src_mutex);
		}

		stats->last_packet = request->async->recv_time;
		stats->stats[src_code]++;
		stats->stats[dst_code]++;

		/*
		 *	Update destination statistics
		 */
		mydata.ipaddr = request->packet->dst_ipaddr;
		stats = rbtree_finddata(t->dst, &mydata);
		if (!stats) {
			MEM(stats = talloc_zero(t, rlm_stats_data_t));

			stats->ipaddr = request->packet->dst_ipaddr;
			stats->created = request->async->recv_time;

			PTHREAD_MUTEX_LOCK(&t->dst_mutex);
			(void) rbtree_insert(t->dst, stats);
			PTHREAD_MUTEX_UNLOCK(&t->dst_mutex);
		}

		stats->last_packet = request->async->recv_time;
		stats->stats[src_code]++;
		stats->stats[dst_code]++;

		/*
		 *	@todo - periodically clean up old entries.
		 */

		if ((t->last_global_update + NANOSEC) > request->async->recv_time) {
			return RLM_MODULE_UPDATED;
		}

		t->last_global_update = request->async->recv_time;

		PTHREAD_MUTEX_LOCK(&inst->mutex);
		for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
			inst->stats[i] += t->stats[i];
			t->stats[i] = 0;
		}
		PTHREAD_MUTEX_UNLOCK(&inst->mutex);

		return RLM_MODULE_UPDATED;
	}

	/*
	 *	Ignore "authenticate" and anything other than Status-Server
	 */
	if ((request->request_state != REQUEST_RECV) ||
	    (request->packet->code != FR_CODE_STATUS_SERVER)) {
		return RLM_MODULE_NOOP;
	}

	vp = fr_pair_find_by_da(request->packet->vps, attr_freeradius_stats4_type, TAG_ANY);
	if (!vp) {
		stats_type = FR_FREERADIUS_STATS4_TYPE_VALUE_GLOBAL;
	} else {
		stats_type = vp->vp_uint32;
	}

	/*
	 *	Create attributes based on the statistics.
	 */
	fr_cursor_init(&cursor, &request->reply->vps);

	MEM(pair_update_reply(&vp, attr_freeradius_stats4_type) >= 0);
	vp->vp_uint32 = stats_type;

	switch (stats_type) {
	case FR_FREERADIUS_STATS4_TYPE_VALUE_GLOBAL:			/* global */
		/*
		 *	Merge our stats with the global stats, and then copy
		 *	the global stats to a thread-local variable.
		 *
		 *	The copy helps minimize mutex contention.
		 */
		PTHREAD_MUTEX_LOCK(&inst->mutex);
		for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
			inst->stats[i] += t->stats[i];
			t->stats[i] = 0;
		}
		memcpy(&local_stats, inst->stats, sizeof(inst->stats));
		PTHREAD_MUTEX_UNLOCK(&inst->mutex);
		vp = NULL;
		break;

	case FR_FREERADIUS_STATS4_TYPE_VALUE_CLIENT:			/* src */
		vp = fr_pair_find_by_da(request->packet->vps, attr_freeradius_stats4_ipv4_address, TAG_ANY);
		if (!vp) vp = fr_pair_find_by_da(request->packet->vps, attr_freeradius_stats4_ipv6_address, TAG_ANY);
		if (!vp) return RLM_MODULE_NOOP;

		mydata.ipaddr = vp->vp_ip;
		coalesce(local_stats, t,
			 offsetof(rlm_stats_thread_t, src_mutex), offsetof(rlm_stats_thread_t, src),
			 &mydata);
		break;

	case FR_FREERADIUS_STATS4_TYPE_VALUE_LISTENER:			/* dst */
		vp = fr_pair_find_by_da(request->packet->vps, attr_freeradius_stats4_ipv4_address, TAG_ANY);
		if (!vp) vp = fr_pair_find_by_da(request->packet->vps, attr_freeradius_stats4_ipv6_address, TAG_ANY);
		if (!vp) return RLM_MODULE_NOOP;

		mydata.ipaddr = vp->vp_ip;
		coalesce(local_stats, t,
			 offsetof(rlm_stats_thread_t, dst_mutex), offsetof(rlm_stats_thread_t, dst),
			 &mydata);
		break;

	default:
		REDEBUG("Invalid value '%d' for FreeRADIUS-Stats4-type", stats_type);
		return RLM_MODULE_FAIL;
	}

	if (vp ) {
		vp = fr_pair_copy(request->reply, vp);
		if (vp) {
			fr_cursor_append(&cursor, vp);
			(void) fr_cursor_tail(&cursor);
		}
	}

	strcpy(buffer, "FreeRADIUS-Stats4-");

	for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
		fr_dict_attr_t const *da;

		if (!local_stats[i]) continue;

		strlcpy(buffer + 18, fr_packet_codes[i], sizeof(buffer) - 18);
		da = fr_dict_attr_by_name(dict_radius, buffer);
		if (!da) continue;

		vp = fr_pair_afrom_da(request->reply, da);
		if (!vp) return RLM_MODULE_FAIL;

		vp->vp_uint64 = local_stats[i];

		fr_cursor_append(&cursor, vp);
		(void) fr_cursor_tail(&cursor);
	}

	return RLM_MODULE_OK;
}


static int data_cmp(const void *one, const void *two)
{
	rlm_stats_data_t const *a = one;
	rlm_stats_data_t const *b = two;

	return fr_ipaddr_cmp(&a->ipaddr, &b->ipaddr);
}

/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, UNUSED fr_event_list_t *el, void *thread)
{
	rlm_stats_t *inst = talloc_get_type_abort(instance, rlm_stats_t);
	rlm_stats_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_stats_thread_t);

	t->inst = inst;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&t->src_mutex, NULL);
	pthread_mutex_init(&t->dst_mutex, NULL);
#endif
	t->src = rbtree_talloc_create(t, data_cmp, rlm_stats_data_t, NULL, RBTREE_FLAG_NONE);
	t->dst = rbtree_talloc_create(t, data_cmp, rlm_stats_data_t, NULL, RBTREE_FLAG_NONE);

	PTHREAD_MUTEX_LOCK(&inst->mutex);
	fr_dlist_insert_head(&inst->list, t);
	PTHREAD_MUTEX_UNLOCK(&inst->mutex);

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(UNUSED fr_event_list_t *el, void *thread)
{
	rlm_stats_thread_t *t = talloc_get_type_abort(thread, rlm_stats_thread_t);
	rlm_stats_t *inst = t->inst;
	int i;

	PTHREAD_MUTEX_LOCK(&inst->mutex);
	for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
		inst->stats[i] += t->stats[i];
	}
	fr_dlist_remove(&inst->list, t);
	PTHREAD_MUTEX_UNLOCK(&inst->mutex);

	return 0;
}

static int mod_instantiate(void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_stats_t	*inst = instance;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&inst->mutex, NULL);
#endif

	fr_dlist_init(&inst->list, rlm_stats_thread_t, entry);

	return 0;
}

/*
 *	Only free memory we allocated.  The strings allocated via
 *	cf_section_parse() do not need to be freed.
 */
static int mod_detach(void *instance)
{
	rlm_stats_t *inst = talloc_get_type_abort(instance, rlm_stats_t);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&inst->mutex);
#endif

	/* free things here */
	return 0;
}

/*
 *	The module name should be the only globally exported symbol.
 *	That is, everything else should be 'static'.
 *
 *	If the module needs to temporarily modify it's instantiation
 *	data, the type should be changed to RLM_TYPE_THREAD_UNSAFE.
 *	The server will then take care of ensuring that the module
 *	is single-threaded.
 */
extern rad_module_t rlm_stats;

rad_module_t rlm_stats = {
	.magic			= RLM_MODULE_INIT,
	.name			= "stats",
	.inst_size		= sizeof(rlm_stats_t),
	.thread_inst_size	= sizeof(rlm_stats_thread_t),
	.config			= module_config,
	.instantiate		= mod_instantiate,
	.detach			= mod_detach,
	.thread_instantiate	= mod_thread_instantiate,
	.thread_detach		= mod_thread_detach,
	.methods = {
		[MOD_AUTHORIZE]		= mod_stats, /* @mod_stats_query */
		[MOD_POST_AUTH]		= mod_stats,
		[MOD_ACCOUNTING]	= mod_stats,
		[MOD_SEND_COA]		= mod_stats,
	},
};
