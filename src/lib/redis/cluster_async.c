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

#include "attrs.h"
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

#define CONFIGURE_NODE(_node, _addr) \
do {  \
char buff [FR_IPADDR_STRLEN]; \
	_node->addr = _addr; \
	_node->ioconf = (fr_redis_io_conf_t) { \
		.port = _node->addr.inet.dst_port, \
		.username = rtcluster->conf->username, \
		.password = rtcluster->conf->password, \
	}; \
	_node->ioconf.log_prefix = talloc_asprintf(rtcluster, "%s %s:%d", rtcluster->conf->log_prefix, \
						   fr_inet_ntop(buff, sizeof(buff), &_node->addr.inet.dst_ipaddr), \
						   _node->ioconf.port); \
	_node->trunk = fr_redis_trunk_alloc(rtcluster, &_node->ioconf, NULL); \
	if (!_node->trunk) goto error; \
} while (0)

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

/** Return the master node that would be used for a particular key slot
 *
 * @param[in] rtcluster		To resolve key slot in.
 * @param[in] key_slot		to resolve to node.
 * @return
 *      - The current master node.
 *	- NULL if no master node is currently assigned to a particular key slot.
 */
fr_redis_ct_node_t const *fr_redis_ct_master(fr_redis_cluster_thread_t *rtcluster,
					     fr_redis_ct_key_slot_t const *key_slot)
{
	return &rtcluster->node[key_slot->master];
}

/** Return the replica node that would be used for a particular key slot
 *
 * @param[in] rtcluster		To resolve key slot in.
 * @param[in] key_slot		To resolve to node.
 * @param[in] replica_num		0..n.
 * @return
 *	- A replica node.
 *	- NULL if no replica node is assigned, or is at the specific key slot.
 *
 */
fr_redis_ct_node_t const *fr_redis_ct_replica(fr_redis_cluster_thread_t *rtcluster,
					      fr_redis_ct_key_slot_t const *key_slot, uint8_t replica_num)
{
	if (replica_num >= key_slot->num_replicas) return NULL;	/* No replica available */

	return &rtcluster->node[key_slot->replica[replica_num]];
}

/** Enqueue a command set on a node identified by the key.
 *
 */
static fr_redis_async_rcode_t fr_redis_async_cmd_enqueue(fr_redis_async_cmd_t *cmd)
{
	fr_redis_cluster_thread_t	*rtcluster = cmd->rtcluster;
	fr_redis_trunk_t		*trunk;
	fr_redis_pipeline_status_t	ret;
	bool				dst_unavail = false;

	cmd->key_slot = fr_redis_ct_slot_by_key(rtcluster, cmd->request, cmd->key, cmd->key_len);

	/*
	 *	Read only commands start on the first replica, if there are any.
	 */
	if (cmd->read_only && cmd->key_slot->num_replicas) {
		trunk = rtcluster->node[cmd->key_slot->replica[0]].trunk;
	} else {
		trunk = rtcluster->node[cmd->key_slot->master].trunk;
	}

again:
	ret = redis_command_set_enqueue(trunk, cmd->cmds);

	switch (ret) {
	case FR_REDIS_PIPELINE_OK:
		return dst_unavail ? REDIS_ASYNC_RCODE_GETMAP : REDIS_ASYNC_RCODE_SUCCESS;

	case FR_REDIS_PIPELINE_DST_UNAVAILABLE:
		dst_unavail = true;
		if (cmd->replica_no < cmd->key_slot->num_replicas) {
			trunk = rtcluster->node[cmd->key_slot->replica[cmd->replica_no]].trunk;
			cmd->replica_no++;
			goto again;
		}
		/*
		 *	Read only commands can also try the master node.
		 *	Non-read only first tried the master.
		 */
		if (cmd->read_only && (trunk != rtcluster->node[cmd->key_slot->master].trunk)) {
			trunk = rtcluster->node[cmd->key_slot->master].trunk;
			goto again;
		}
		return REDIS_ASYNC_RCODE_ERROR;

	default:
		return REDIS_ASYNC_RCODE_ERROR;
	}

}

/** Start running a command set on an async redis cluster
 *
 * @param ctx		to allocate tracking structure.
 * @param request	current request.
 * @param rcode		Where to write the result code.
 * @param rtcluster	to start the command set on
 * @param key		to identify the cluster slot.
 * @param key_len	Length of key.
 * @param cmds		Command set to run.
 * @param read_only	Should the command set be run on read only nodes.
 * @return The async redis command
 */
fr_redis_async_cmd_t *fr_redis_async_cmd_start(TALLOC_CTX *ctx, request_t *request, fr_redis_async_rcode_t *rcode,
					       fr_redis_cluster_thread_t *rtcluster, uint8_t const *key, size_t key_len,
					       fr_redis_command_set_t *cmds, bool read_only)
{
	fr_redis_async_cmd_t		*cmd;

	MEM(cmd = talloc(ctx, fr_redis_async_cmd_t));

	*cmd = (fr_redis_async_cmd_t) {
		.request = request,
		.rtcluster = rtcluster,
		.cmds = cmds,
		.read_only = read_only,
		.key = key,
		.key_len = key_len,
	};

	switch (rtcluster->state) {
	case CLUSTER_INIT:
		/*
		 *	If the cluster has not bootstrapped, that must be done first.
		 */
		fr_dlist_insert_tail(&rtcluster->pending, cmd);
		*rcode = REDIS_ASYNC_RCODE_BOOTSTRAP;
		break;

	case CLUSTER_MAP_FETCHING:
		fr_dlist_insert_tail(&rtcluster->pending, cmd);
		*rcode = REDIS_ASYNC_RCODE_SUCCESS;
		break;

	default:
		*rcode = fr_redis_async_cmd_enqueue(cmd);
		break;
	}

	return cmd;
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

/** Update a Redis cluster map from a pair list returned from a coordinator
 *
 * @param rtcluster	Cluster to update
 * @param list		pairs sent by a coordinator
 * @return
 *	- 0 om success
 *	- -1 on error
 */
int fr_redis_cluster_thread_map_update(fr_redis_cluster_thread_t *rtcluster, fr_pair_list_t const *list)
{
	fr_pair_t	*vp, *shard = NULL, *slot, *start, *end, *node, *role, *node_ip, *node_port;
	uint16_t	i;
	uint8_t		r = 0;
	uint8_t		rollback[UINT8_MAX];		// Set of nodes to re-add to the queue on failure.
	bool		active[UINT8_MAX];		// Set of nodes active in the new cluster map.
	bool		master[UINT8_MAX];		// Master nodes.

	fr_redis_ct_node_t	find, *cluster_node;
	fr_redis_ct_key_slot_t	tmp_slot;
	fr_redis_ct_key_slot_t	key_slot_pending[KEY_SLOTS];
	fr_redis_async_cmd_t	*cmd;

#define SET_INACTIVE(_node) \
do { \
	(_node)->is_active = false; \
	(_node)->is_master = false; \
	talloc_const_free((_node)->ioconf.log_prefix); \
	(_node)->ioconf.log_prefix = NULL; \
	TALLOC_FREE((_node)->trunk); \
	fr_rb_delete(rtcluster->used_nodes, _node); \
	fr_fifo_push(rtcluster->free_nodes, _node); \
} while (0)

#define SET_ACTIVE(_node) \
do { \
	fr_rb_insert(rtcluster->used_nodes, _node); \
	fr_fifo_pop(rtcluster->free_nodes); \
	(_node)->is_active = true; \
	active[(_node)->id] = true; \
	rollback[r++] = (_node)->id; \
} while (0)

	vp = fr_pair_find_by_da(list, NULL, attr_redis_cluster_id);
	if (unlikely(!vp)) {
		ERROR("Missing cluster ID");
		return -1;
	}
	if (rtcluster->cluster_id == 0) rtcluster->cluster_id = vp->vp_uint16;

	if (rtcluster->cluster_id != vp->vp_uint16) {
		ERROR("Got map for cluster ID %d, expected ID %d", vp->vp_uint16, rtcluster->cluster_id);
		return -1;
	}

	DEBUG3("Updating cluster %d", rtcluster->cluster_id);

	memset(&key_slot_pending, 0, sizeof(key_slot_pending));
	memset(active, 0, sizeof(active));
	memset(master, 0, sizeof(master));

	while ((shard = fr_pair_find_by_da(list, shard, attr_redis_shard))) {
		cluster_node = NULL;
		memset(&tmp_slot, 0, sizeof(fr_redis_ct_key_slot_t));
		node = NULL;
		while ((node = fr_pair_find_by_da(&shard->vp_group, node, attr_redis_node))) {
			role = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_role);
			if (unlikely(!role)) continue;
			if (role->vp_uint8 == 1) {
				DEBUG3("Master node %pP", node);

				node_ip = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_endpoint);
				if (unlikely(!node_ip)) continue;
				fr_inet_pton(&find.addr.inet.dst_ipaddr, node_ip->vp_strvalue, node_ip->vp_length, AF_UNSPEC, true, true);
				node_port = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_port);
				if (unlikely(!node_port)) continue;
				find.addr.inet.dst_port = node_port->vp_uint16;

				cluster_node = fr_rb_find(rtcluster->used_nodes, &find);
				break;
			}
		}

		if (!node) {
			ERROR("Missing master node");
		error:
			for (i = 0; i < r; i++) SET_INACTIVE(&rtcluster->node[rollback[i]]);
			return -1;
		}

		if (!cluster_node) {
			cluster_node = fr_fifo_peek(rtcluster->free_nodes);
			if (!cluster_node) {
			out_of_nodes:
				fr_strerror_const("Reached maximum connected nodes");
				goto error;
			}
			CONFIGURE_NODE(cluster_node, find.addr);
			SET_ACTIVE(cluster_node);
		} else {
			active[cluster_node->id] = true;
		}
		master[cluster_node->id] = true;
		tmp_slot.master = cluster_node->id;

		node = NULL;
		while ((node = fr_pair_find_by_da(&shard->vp_group, node, attr_redis_node))) {
			role = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_role);
			if (tmp_slot.num_replicas >= MAX_REPLICAS) break;
			if (role->vp_uint8 != 2) continue;

			DEBUG3("Replica node %pP", node);
			node_ip = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_endpoint);
			fr_inet_pton(&find.addr.inet.dst_ipaddr, node_ip->vp_strvalue, node_ip->vp_length, AF_UNSPEC, true, true);
			node_port = fr_pair_find_by_da(&node->vp_group, NULL, attr_redis_node_port);
			find.addr.inet.dst_port = node_port->vp_uint16;

			cluster_node = fr_rb_find(rtcluster->used_nodes, &find);

			if (cluster_node) {
				tmp_slot.replica[tmp_slot.num_replicas++] = cluster_node->id;
				active[cluster_node->id] = true;
				continue;
			}

			cluster_node = fr_fifo_peek(rtcluster->free_nodes);
			if (!cluster_node) goto out_of_nodes;

			CONFIGURE_NODE(cluster_node, find.addr);
			tmp_slot.replica[tmp_slot.num_replicas++] = cluster_node->id;
			SET_ACTIVE(cluster_node);
		}

		slot = NULL;
		while ((slot = fr_pair_find_by_da(&shard->vp_group, slot, attr_redis_slot))) {
			start = fr_pair_find_by_da(&slot->vp_group, NULL, attr_redis_slot_start);
			if (unlikely(!start)) {
				ERROR("Missing slot start");
				goto error;
			}
			if (unlikely(start->vp_uint16 >= KEY_SLOTS)) {
				ERROR("Value of %d for slot start greater than expected maximum %d",
				      start->vp_uint16, KEY_SLOTS);
				goto error;
			}
			end = fr_pair_find_by_da(&slot->vp_group, NULL, attr_redis_slot_end);
			if (unlikely(!end)) {
				ERROR("Missing slot end");
				goto error;
			}
			if (unlikely(end->vp_uint16 >= KEY_SLOTS)) {
				ERROR("Value of %d for slot end greater than expected maximum %d",
				      end->vp_uint16, KEY_SLOTS);
				goto error;
			}
			if (unlikely(end->vp_uint16 < start->vp_uint16)) {
				ERROR("Value of %d for slot end less than value of %d for slot start",
				      end->vp_uint16, start->vp_uint16);
				goto error;
			}
			DEBUG4("Setting nodes for slots %d to %d", start->vp_uint16, end->vp_uint16);
			for (i = start->vp_uint16; i <= end->vp_uint16; i++) {
				memcpy(&key_slot_pending[i], &tmp_slot, sizeof(*key_slot_pending));
			}
		}
	}

	/*
	 *	Check for holes in the pending_addr key_slot array
	 *
	 *	The cluster specification says that upon
	 *	detecting a 'NULL' key_slot we should
	 *	check again to see if the cluster error has
	 *	been resolved, but seeing as we're in the
	 *	middle of updating the cluster from very
	 *	recent output of 'cluster slots' it's best to
	 *	error out.
	 */
	for (i = 0; i < KEY_SLOTS; i++) {
		if (key_slot_pending[i].master == 0) {
			fr_strerror_printf("Cluster is misconfigured, no node assigned for key %d", i);
			goto error;
		}
	}

	memcpy(&rtcluster->key_slot, &key_slot_pending, sizeof(rtcluster->key_slot));

	/*
	 *	Anything not in the active set of nodes gets
	 *	added back into the queue, to be re-used.
	 *
	 *	We start at 1, as node 0 is reserved.
	 */
	for (i = 1; i <= rtcluster->conf->max_nodes; i++) {
#ifndef NDEBUG
		fr_redis_ct_node_t *found;

		if (rtcluster->node[i].is_active) {
			/* Sanity check for duplicates that are active */
			found = fr_rb_find(rtcluster->used_nodes, &rtcluster->node[i]);
			fr_assert(found);
			fr_assert(found->is_active);
			fr_assert(found->id == i);
		}
#endif

		if (!active[i] && rtcluster->node[i].is_active) {
			SET_INACTIVE(&rtcluster->node[i]);

		/*
		 *	Only change the masters once we've successfully
		 *	remapped the cluster.
		 */
		} else if (master[i]) {
			rtcluster->node[i].is_master = true;
		} else {
			rtcluster->node[i].is_master = false;
		}
	}

	rtcluster->state = CLUSTER_READY;

	/*
	 *	Enqueue any commands which were waiting for the cluster remap.
	 */
	while ((cmd = fr_dlist_pop_head(&rtcluster->pending))) {
		fr_redis_async_cmd_enqueue(cmd);
	}

	return 0;
}

/** Initiate bootstrapping of the cluster map
 *
 * To be used when a module first wants to fetch a cluster map
 *
 * @param rtcluster		Cluster to fetch map for
 * @param cw			Coord worker to launch request
 * @param coord_pair_reg	Coord pair registration
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_redis_cluster_thread_map_bootstrap(fr_redis_cluster_thread_t *rtcluster, fr_coord_worker_t *cw,
					  fr_coord_pair_reg_t *coord_pair_reg)
{
	fr_redis_conf_t const	*conf = rtcluster->conf;
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	TALLOC_CTX		*local = talloc_new(NULL);
	int			ret;
	size_t			i;

	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_redis_packet_type, (uint32_t)FR_REDIS_CLUSTER_MAP_BOOTSTRAP, false);
	if (!vp) {
	error:
		talloc_free(local);
		return -1;
	}

	if (fr_pair_append_by_da(local, &vp, &list, attr_redis_log_prefix) < 0) goto error;
	if (fr_value_box_strdup(vp, &vp->data, NULL, conf->log_prefix, false) < 0) goto error;

	fr_pair_list_append_by_da(local, vp, &list, attr_redis_max_nodes, conf->max_nodes, false);
	if (!vp) goto error;

	for (i = 0; i < talloc_array_length(conf->hostname); i++) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_redis_bootstrap_node) < 0) goto error;
		if (fr_value_box_strdup(vp, &vp->data, NULL, conf->hostname[i], false) < 0) goto error;
	}

	fr_pair_list_append_by_da(local, vp, &list, attr_redis_bootstrap_port, conf->port, false);
	if (!vp) goto error;

	if (conf->password) {
		if (fr_pair_append_by_da(local, &vp, &list, attr_redis_password) < 0) goto error;
		if (fr_value_box_strdup(vp, &vp->data, NULL, conf->password, false) < 0) goto error;
		if (conf->username) {
			if (fr_pair_append_by_da(local, &vp, &list, attr_redis_username) < 0) goto error;
			if (fr_value_box_strdup(vp, &vp->data, NULL, conf->username, false) < 0) goto error;
		}
	}

	ret = fr_worker_to_coord_pair_send(cw, coord_pair_reg, &list);
	talloc_free(local);

	if (ret < 0) return -1;
	rtcluster->state = CLUSTER_MAP_FETCHING;

	return 0;
}

/** Initiate updating of the cluster map
 *
 * To be used when a command returns MOVED
 */
fr_redis_async_rcode_t fr_redis_cluster_thread_map_get(fr_redis_cluster_thread_t *rtcluster, fr_coord_worker_t *cw,
						       fr_coord_pair_reg_t *coord_pair_reg)
{
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	TALLOC_CTX		*local;
	int			ret;

	if (rtcluster->cluster_id == 0) return REDIS_ASYNC_RCODE_BOOTSTRAP;

	local = talloc_new(NULL);
	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_redis_packet_type, (uint32_t)FR_REDIS_CLUSTER_MAP_GET, false);
	if (!vp) {
	error:
		talloc_free(local);
		return REDIS_ASYNC_RCODE_ERROR;
	}

	fr_pair_list_append_by_da(local, vp, &list, attr_redis_cluster_id, rtcluster->cluster_id, false);
	if (!vp) goto error;

	ret = fr_worker_to_coord_pair_send(cw, coord_pair_reg, &list);
	talloc_free(local);

	if (ret < 0) return REDIS_ASYNC_RCODE_ERROR;
	rtcluster->state = CLUSTER_MAP_FETCHING;

	return REDIS_ASYNC_RCODE_SUCCESS;
}

fr_redis_ct_node_t *fr_redis_cluster_thread_node_by_addr(fr_redis_cluster_thread_t *rtcluster, fr_socket_t *addr)
{
	fr_redis_ct_node_t find;
	find.addr = *addr;
	return fr_rb_find(rtcluster->used_nodes, &find);
}
