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

#include "cluster_async.h"
#include "crc16.h"

#define MAX_REPLICAS		5			//!< Maximum number of replicas associated
							//!< with a keyslot.
struct fr_redis_ct_key_slot_s {
	uint8_t		replica[MAX_REPLICAS];		//!< Array of ids of replica nodes
	uint8_t		num_replicas;			//!< Number of replica nodes
	uint8_t		master;				//!< id of the master node.
};


/** Thread local state for a cluster
 *
 */
struct fr_redis_cluster_thread_s {
	uint16_t			cluster_id;	//!< Number assigned to the cluster by coordinator.
	fr_event_list_t			*el;
	trunk_conf_t	const		*tconf;		//!< Configuration for all trunks in the cluster.
	bool				delay_start;	//!< Prevent connections from spawning immediately.
	fr_redis_ct_node_t		*node;		//!< Array of nodes in this cluster.
	fr_fifo_t			*free_nodes;	//!< Nodes not currently active.
	fr_rb_tree_t			*used_nodes;	//!< Active nodes.

	fr_redis_ct_key_slot_t		key_slot[KEY_SLOTS];

};

struct fr_redis_ct_node_s {
	fr_rb_node_t			rbnode;		//!< Entry in the tree of used nodes
	char				name[INET6_ADDRSTRLEN];
	uint8_t				id;		//!< Array offset in the array of available nodes.

	bool				is_active;	//!< Is this node currently active.
	bool				is_master;	//!< Is this node currently a master.

	fr_socket_t			addr;		//!< IP address and port

	fr_redis_cluster_thread_t	*rtcluster;	//!< Cluster this node belongs to
	fr_redis_io_conf_t		ioconf;		//!< Connection config for this node.
	fr_redis_trunk_t		*trunk;		//!< Trunk connection to this node.
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
