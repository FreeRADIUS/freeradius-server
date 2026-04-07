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
 * @file cluster_async.c
 * @brief conf functions for interacting asynchronously with Redis cluster via Hiredis.
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 *
 * @copyright 2026 Network RADIUS (legal@networkradius.com)
 *
 */

#include <freeradius-devel/util/debug.h>

#include "base.h"
#include "cluster_async.h"

/** Thread local state for a cluster
 *
 */
struct fr_redis_cluster_thread_s {
	fr_event_list_t			*el;
	trunk_conf_t	const		*tconf;		//!< Configuration for all trunks in the cluster.
	bool				delay_start;	//!< Prevent connections from spawning immediately.
};

/** Allocate per-thread, per-cluster instance
 *
 * This structure represents all the connections for a given thread for a given cluster.
 * The structures holds the trunk connections to talk to each cluster member.
 *
 */
fr_redis_cluster_thread_t *fr_redis_cluster_thread_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, trunk_conf_t const *tconf)
{
	fr_redis_cluster_thread_t *cluster_thread;
	trunk_conf_t *our_tconf;

	MEM(cluster_thread = talloc_zero(ctx, fr_redis_cluster_thread_t));
	MEM(our_tconf = talloc_memdup(cluster_thread, tconf, sizeof(*tconf)));
	our_tconf->always_writable = true;

	cluster_thread->el = el;
	cluster_thread->tconf = our_tconf;

	return cluster_thread;
}

fr_event_list_t *fr_redis_cluster_thread_el(fr_redis_cluster_thread_t *thread)
{
	return thread->el;
}

trunk_conf_t const *fr_redis_cluster_thread_trunk_conf(fr_redis_cluster_thread_t *thread)
{
	return thread->tconf;
}
