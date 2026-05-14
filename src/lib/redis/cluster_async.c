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

typedef enum {
	CLUSTER_INIT = 0,				//!< Cluster has been initialised.
	CLUSTER_MAP_FETCHING,				//!< The cluster map is currently being fetched.
	CLUSTER_READY					//!< The cluster is available to handle requests.
} fr_redis_ct_state_t;

/** Thread local state for a cluster
 *
 */
struct fr_redis_cluster_thread_s {
	uint16_t			cluster_id;	//!< Number assigned to the cluster by coordinator.
	fr_event_list_t			*el;
	trunk_conf_t	const		*tconf;		//!< Configuration for all trunks in the cluster.
	bool				delay_start;	//!< Prevent connections from spawning immediately.
	fr_redis_conf_t const		*conf;		//!< Redis configuration for the cluster.

	fr_redis_ct_node_t		*node;		//!< Array of nodes in this cluster.
	fr_fifo_t			*free_nodes;	//!< Nodes not currently active.
	fr_rb_tree_t			*used_nodes;	//!< Active nodes.

	fr_redis_ct_key_slot_t		key_slot[KEY_SLOTS];

	fr_redis_ct_state_t		state;		//!< State of the cluster.
	fr_dlist_head_t			pending;	//!< Commands awaiting cluster map.
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

/** Structure for holding the state of an async redis command set.
 *
 */
struct fr_redis_async_cmd_s {
	request_t			*request;	//!< Request this command set relates to.
	fr_redis_cluster_thread_t	*rtcluster;	//!< Cluster this command set is running on.
	fr_redis_command_set_t		*cmds;		//!< Command set to run.
	uint8_t const			*key;		//!< Key used to identify key slot.
	size_t				key_len;	//!< Length of key.
	fr_redis_ct_key_slot_t const	*key_slot;	//!< Key slot identified from the command key.
	bool				read_only;	//!< Should this command be run read only.
	uint8_t				replica_no;	//!< Current replica number being used.
	fr_dlist_t			entry;		//!< Entry in the list of commands waiting for a cluster remap.
};

/** Resolve key to key slot index
 *
 * Identical to the example implementation, except it uses memchr which will
 * be faster, and isn't so needlessly complex.
 *
 * @param[in] key to resolve.
 * @param[in] key_len length of key.
 * @return key slot index for the key.
 */
static uint16_t cluster_key_hash(uint8_t const *key, size_t key_len)
{
	uint8_t *p, *q;

	p = memchr(key, '{', key_len);
	if (!p) {
	all:
		return fr_crc16_xmodem(key, key_len) & (KEY_SLOTS - 1);
	}

	q = memchr(p, '}', key_len - (p - key)); /* look for } after { */
	if (!q || (q == p + 1)) goto all; /* no } or {}, hash everything */

	p++;	/* skip '{' */

    	return fr_crc16_xmodem(p, q - p) & (KEY_SLOTS - 1);	/* hash stuff between { and } */
}

/** Resolve key to key slot
 *
 * @param[in] rtcluster	to resolve the key slot in.
 * @param[in] request Current request (for debugging).
 * @param[in] key to resolve.
 * @param[in] key_len length of key.
 * @return key slot for the key.
 */
fr_redis_ct_key_slot_t const *fr_redis_ct_slot_by_key(fr_redis_cluster_thread_t *rtcluster, request_t *request,
						      uint8_t const *key, size_t key_len)
{
	fr_redis_ct_key_slot_t *key_slot;

	if (!key || (key_len == 0)) {
		key_slot = &rtcluster->key_slot[(uint16_t)(fr_rand() & (KEY_SLOTS - 1))];
		ROPTIONAL(RDEBUG2, DEBUG2, "Key rand() -> slot %zu", key_slot - rtcluster->key_slot);

		return key_slot;
	}

	/*
	 *	Avoid CRC16 if we're operating with one cluster node or
	 *	without clustering.
	 */
	if (fr_rb_num_elements(rtcluster->used_nodes) > 1) {
		key_slot = &rtcluster->key_slot[cluster_key_hash(key, key_len)];
		ROPTIONAL(RDEBUG2, DEBUG2, "Key \"%pV\" -> slot %zu",
			  fr_box_strvalue_len((char const *)key, key_len), key_slot - rtcluster->key_slot);

		return key_slot;
	}
	ROPTIONAL(RDEBUG3, DEBUG3, "Single node available, skipping key selection");

	return &rtcluster->key_slot[0];
}

/** Compare two redis nodes to check equality
 *
 * @param[in] one first node.
 * @param[in] two second node.
 * @return CMP(one, two)
 */
static int8_t _cluster_thread_node_cmp(void const *one, void const *two)
{
	fr_redis_ct_node_t const *a = one;
	fr_redis_ct_node_t const *b = two;
	int ret;

	ret = fr_ipaddr_cmp(&a->addr.inet.dst_ipaddr, &b->addr.inet.dst_ipaddr);
	if (ret != 0) return ret;

	return CMP(a->addr.inet.dst_port, b->addr.inet.dst_port);
}

/** Allocate per-thread, per-cluster instance
 *
 * This structure represents all the connections for a given thread for a given cluster.
 * The structures holds the trunk connections to talk to each cluster member.
 *
 */
fr_redis_cluster_thread_t *fr_redis_cluster_thread_alloc(TALLOC_CTX *ctx, fr_event_list_t *el, fr_redis_conf_t *conf)
{
	fr_redis_cluster_thread_t	*rtcluster;
	trunk_conf_t			*our_tconf;
	uint8_t				i;

	MEM(rtcluster = talloc_zero(ctx, fr_redis_cluster_thread_t));
	MEM(our_tconf = talloc_memdup(rtcluster, &conf->trunk_conf, sizeof(conf->trunk_conf)));
	our_tconf->always_writable = true;

	rtcluster->el = el;
	rtcluster->tconf = our_tconf;
	rtcluster->conf = conf;
	fr_dlist_talloc_init(&rtcluster->pending, fr_redis_async_cmd_t, entry);

	if (conf->max_nodes == UINT8_MAX) {
		ERROR("%s - Maximum number of connected nodes allowed is %i", conf->log_prefix, UINT8_MAX - 1);
		talloc_free(rtcluster);
		return NULL;
	}

	if (conf->max_nodes == 0) {
		ERROR("%s - Minimum number of nodes allowed is 1", conf->log_prefix);
		talloc_free(rtcluster);
		return NULL;
	}

	MEM(rtcluster->node = talloc_zero_array(rtcluster, fr_redis_ct_node_t, conf->max_nodes + 1));
	MEM(rtcluster->used_nodes = fr_rb_inline_alloc(rtcluster, fr_redis_ct_node_t, rbnode, _cluster_thread_node_cmp, NULL));
	MEM(rtcluster->free_nodes = fr_fifo_create(rtcluster, conf->max_nodes, NULL));

	/*
	 *	Node id 0 is reserved, so we can detect misconfigured
	 *	clusters.
	 */
	for (i = 1; i <= conf->max_nodes; i++) {
		rtcluster->node[i].id = i;
		rtcluster->node[i].rtcluster = rtcluster;

		/* Push them all into the queue */
		fr_fifo_push(rtcluster->free_nodes, &rtcluster->node[i]);
	}

	return rtcluster;
}

fr_event_list_t *fr_redis_cluster_thread_el(fr_redis_cluster_thread_t *rtcluster)
{
	return rtcluster->el;
}

trunk_conf_t const *fr_redis_cluster_thread_trunk_conf(fr_redis_cluster_thread_t *rtcluster)
{
	return rtcluster->tconf;
}
