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

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/io/listen.h>
#include <freeradius-devel/rad_assert.h>

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
	pthread_mutex_t	mutex;
#endif

	uint64_t		stats[FR_MAX_PACKET_CODE];
} rlm_stats_t;

typedef struct rlm_stats_thread_t {
	rlm_stats_t		*inst;

	fr_time_t		last_update;

	uint64_t		stats[FR_MAX_PACKET_CODE];
} rlm_stats_thread_t;

static const CONF_PARSER module_config[] = {
	CONF_PARSER_TERMINATOR
};


/*
 *	Do the statistics
 */
static rlm_rcode_t CC_HINT(nonnull) mod_stats(void *instance, void *thread, REQUEST *request)
{
	int i, code;
	rlm_stats_thread_t *t = thread;
	rlm_stats_t *inst = instance;
	VALUE_PAIR *vp;
	vp_cursor_t cursor;
	char buffer[64];
	uint64_t stats[sizeof(inst->stats) / sizeof(inst->stats[0])];

	/*
	 *	Increment counters only in "send foo" sections.
	 *
	 *	i.e. only when we have a reply to send.
	 */
	if (request->request_state == REQUEST_SEND) {
		code = request->packet->code;
		if ((code > 0) && (code < FR_MAX_PACKET_CODE)) t->stats[code]++;

		code = request->reply->code;
		if ((code > 0) && (code < FR_MAX_PACKET_CODE)) t->stats[code]++;

		if ((t->last_update + NANOSEC) > request->async->recv_time) {
			return RLM_MODULE_UPDATED;
		}

		t->last_update = request->async->recv_time;

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
	memcpy(&stats, inst->stats, sizeof(inst->stats));
	PTHREAD_MUTEX_UNLOCK(&inst->mutex);

	/*
	 *	Create attributes based on the statistics.
	 */
	fr_pair_cursor_init(&cursor, &request->reply->vps);
	vp = pair_make_reply("FreeRADIUS-Stats4-Name", "global", T_OP_EQ);
	if (!vp) return RLM_MODULE_FAIL;

	strcpy(buffer, "FreeRADIUS-Stats4-");

	for (i = 0; i < FR_MAX_PACKET_CODE; i++) {
		fr_dict_attr_t const *da;

		if (!stats[i]) continue;

		strcpy(buffer + 18, fr_packet_codes[i]);
		da = fr_dict_attr_by_name(NULL, buffer);
		if (!da) continue;

		vp = fr_pair_afrom_da(request->reply, da);
		if (!vp) return RLM_MODULE_FAIL;

		vp->vp_uint64 = stats[i];

		fr_pair_cursor_append(&cursor, vp);
		(void) fr_pair_cursor_last(&cursor);
	}

	return RLM_MODULE_OK;
}


/** Instantiate thread data for the submodule.
 *
 */
static int mod_thread_instantiate(UNUSED CONF_SECTION const *cs, void *instance, UNUSED fr_event_list_t *el, void *thread)
{
	rlm_stats_t *inst = talloc_get_type_abort(instance, rlm_stats_t);
	rlm_stats_thread_t *t = thread;

	(void) talloc_set_type(t, rlm_radius_thread_t);

	t->inst = inst;

	return 0;
}


/** Destroy thread data for the submodule.
 *
 */
static int mod_thread_detach(void *thread)
{
	rlm_stats_thread_t *t = talloc_get_type_abort(thread, rlm_stats_thread_t);
	rlm_stats_t *inst = t->inst;


	PTHREAD_MUTEX_LOCK(&inst->mutex);
	// @todo - merge all of the stats in
	PTHREAD_MUTEX_UNLOCK(&inst->mutex);

	return 0;
}


static int mod_instantiate(UNUSED void *instance, UNUSED CONF_SECTION *conf)
{
	rlm_stats_t	*inst = instance;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&inst->mutex, NULL);
#endif

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
