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

/**
 * $Id$
 * @file src/process/redis/base.c
 * @brief State machine for Redis cluster coordinator thread
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/redis/attrs.h>
#include <freeradius-devel/redis/base.h>
#include <freeradius-devel/redis/cluster_async.h>
#include <freeradius-devel/io/coord_pair.h>
#include <freeradius-devel/server/main_config.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/debug.h>

/* Unique number for each cluster.  Starts at 1, so 0 missing data */
static uint16_t cluster_id = 1;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t process_redis_dict[];
fr_dict_autoload_t process_redis_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_packet_type;
static fr_dict_attr_t const *attr_worker_id;

extern fr_dict_attr_autoload_t process_redis_dict_attr[];
fr_dict_attr_autoload_t process_redis_dict_attr[] = {
	{ .out = &attr_worker_id, .name = "Worker-Id", .type = FR_TYPE_INT32, .dict = &dict_freeradius },

	DICT_AUTOLOAD_TERMINATOR
};

typedef struct {
	uint64_t	nothing;
	CONF_SECTION	*cluster_map_get;
} process_redis_sections_t;

/** Individual cluster node
 */
typedef struct {
	fr_dlist_t			entry;			//!< Entry in the list of cluster nodes.
	fr_redis_io_conf_t		io_conf;		//!< Connection config for this node.
	fr_redis_trunk_t		*trunk;			//!< Trunk connection for this node.
	bool				in_cluster;		//!< Has the node been found in the latest cluster map.
} process_redis_node_t;

/** Coordinator representation of a Redis cluster
 */
typedef struct {
	fr_redis_conf_t			*conf;			//!< Redis config for this cluster.
	uint16_t			cluster_id;		//!< Numeric ID assigned by the coordinator
	fr_ipaddr_t			addr;			//!< IP address of the first bootstrap server
	uint16_t			port;			//!< Port of the first bootstrap server
	fr_dlist_head_t			nodes;			//!< List of current nodes in the cluster
	fr_rb_node_t			cluster_by_server;	//!< Entry in the tree of clusters by bootstrap server.
	fr_rb_node_t			cluster_by_id;		//!< Entry in the tree of clusters by ID.
	fr_redis_cluster_thread_t	*rtcluster;		//!< Cluster used to allocate redis trunk connections
	fr_pair_list_t			cluster_pairs;		//!< Pairs built from the last fetch.
	bool				fetching;		//!< The map is being fetched.
	fr_time_t			last_update;		//!< When was the map last updated.
	fr_rb_tree_t			pending;		//!< Requests waiting for custer map update.
} process_redis_cluster_t;

typedef struct {
	request_t			*request;
	fr_rb_node_t			node;
} process_redis_pending_t;

static int8_t cluster_server_cmp(void const *a, void const *b)
{
	process_redis_cluster_t const	*cluster_a = (process_redis_cluster_t const *)a;
	process_redis_cluster_t const	*cluster_b = (process_redis_cluster_t const *)b;
	int8_t	ret;

	ret = fr_ipaddr_cmp(&cluster_a->addr, &cluster_b->addr);
	if (ret != 0) return ret;

	return CMP(cluster_a->port, cluster_b->port);
}

static int8_t cluster_id_cmp(void const*a, void const *b)
{
	process_redis_cluster_t const	*cluster_a = (process_redis_cluster_t const *)a;
	process_redis_cluster_t const	*cluster_b = (process_redis_cluster_t const *)b;

	return CMP(cluster_a->cluster_id, cluster_b->cluster_id);
}

static int8_t process_redis_pending_cmp(void const *a, void const *b)
{
	process_redis_pending_t	const *pending_a = (process_redis_pending_t const *)a;
	process_redis_pending_t	const *pending_b = (process_redis_pending_t const *)b;

	return CMP(pending_a->request, pending_b->request);
}

typedef struct {
	process_redis_sections_t	sections;
	module_method_t const		*method;
	trunk_conf_t			trunk_conf;
} process_redis_t;

typedef struct {
	fr_event_list_t			*el;
	fr_rb_tree_t			cluster_by_server;	//!< Tree of clusters by primary bootstrap server.
	fr_rb_tree_t			cluster_by_id;		//!< Tree of clusters by ID.
} process_redis_thread_t;

static const conf_parser_t config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, process_redis_t, trunk_conf, trunk_config) },
	CONF_PARSER_TERMINATOR
};

/** Resume context for Redis requests */
typedef struct {
	unlang_result_t		result;			//!< Where results are written to
	int32_t			worker_id;		//!< The worker which sent the data leading to this request.
	fr_redis_command_set_t	*cmds;			//!< Command set for fetching cluster map.
	process_redis_cluster_t	*cluster;		//!< Cluster which is being updated.
	process_redis_node_t	*current_node;		//!< Node currently being queried.
	fr_pair_list_t		list;			//!< To populate with parsed reply data.
} process_redis_rctx_t;

#define FR_REDIS_PACKET_CODE_VALID(_code) (((_code) > 0) && ((_code) < FR_REDIS_CODE_MAX))
#define FR_REDIS_PROCESS_CODE_VALID(_code) (FR_REDIS_PACKET_CODE_VALID(_code) || (_code == FR_REDIS_DO_NOT_RESPOND))

#define PROCESS_PACKET_TYPE		fr_redis_packet_code_t
#define PROCESS_CODE_MAX		FR_REDIS_CODE_MAX
#define PROCESS_CODE_DO_NOT_RESPOND	FR_REDIS_DO_NOT_RESPOND
#define PROCESS_PACKET_CODE_VALID	FR_REDIS_PROCESS_CODE_VALID
#define PROCESS_INST			process_redis_t
#define PROCESS_RCTX			process_redis_rctx_t

#include <freeradius-devel/server/process.h>

/** Convert the reply to CLUSER SLOTS into pairs
 *
 * The CLUSTER SLOTS reply structure
 @verbatim
   [0] -> key slot range 0
       [0] -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master 0 ip (string)
           [1] -> master 0 port (number)
       [3..n] -> replica_node(s)
   [1] -> key slot range 1)
       [0]  -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master 1 ip (string)
           [1] -> master 1 port (number)
       [3..n] -> replica_node(s)
   [n] -> key slot range n
       [0] -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master n ip (string)
           [1] -> master n port (number)
       [3..n] -> replica_node(s)
 @endverbatim
 *
 * @param[in] ctx	to allocate pairs in.
 * @param[in,out] list	to populate with pairs.
 * @param[in] reply	from CLUSTER SLOTS
 */
static int fr_redis_cluster_slots_to_pairs(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *list, redisReply *reply)
{
	size_t		i;
	fr_pair_t	*shard_vp, *slot_vp, *node_vp, *vp;

	if(reply->type != REDIS_REPLY_ARRAY) return -1;

	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);

	/*
	 *	A map consists of an array with the following indexes:
	 *	  [0]    -> key_slot_start
	 *	  [1]    -> key_slot_end
	 *	  [2]    -> master_node
	 *	  [3..n] -> replica_node(s)
	 */
	for (i = 0; i < reply->elements; i++) {
		size_t		j;
		redisReply	*map = reply->element[i];
		redisReply	*node;

		MEM(shard_vp = fr_pair_afrom_da(ctx, attr_redis_shard));

		MEM(slot_vp = fr_pair_afrom_da(shard_vp, attr_redis_slot));
		fr_pair_append(&shard_vp->vp_group, slot_vp);

		MEM(vp = fr_pair_afrom_da(slot_vp, attr_redis_slot_start));
		if (map->element[0]->type != REDIS_REPLY_INTEGER) {
		error:
			talloc_free(shard_vp);
			fr_pair_list_free(list);
			return -1;
		}
		vp->vp_uint16 = (uint16_t) map->element[0]->integer;
		fr_pair_append(&slot_vp->vp_group, vp);

		MEM(vp = fr_pair_afrom_da(slot_vp, attr_redis_slot_end));
		if (map->element[1]->type != REDIS_REPLY_INTEGER) goto error;
		vp->vp_uint16 = (uint16_t) map->element[1]->integer;
		fr_pair_append(&slot_vp->vp_group, vp);

		for (j = 2; j < map->elements; j++) {
			node = map->element[j];
			MEM(node_vp = fr_pair_afrom_da(shard_vp, attr_redis_node));
			fr_pair_append(&shard_vp->vp_group, node_vp);

			MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_endpoint));
			if (node->element[0]->type != REDIS_REPLY_STRING) goto error;
			fr_pair_value_bstrndup(vp, node->element[0]->str, node->element[0]->len, true);
			fr_pair_append(&node_vp->vp_group, vp);

			MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_port));
			if (node->element[1]->type != REDIS_REPLY_INTEGER) goto error;
			vp->vp_uint16 = (uint16_t) node->element[1]->integer;
			fr_pair_append(&node_vp->vp_group, vp);

			MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_role));
			vp->vp_uint8 = (j == 2) ? 1 : 2;
			fr_pair_append(&node_vp->vp_group, vp);
		}

		fr_pair_append(list, shard_vp);
	}

	return 0;
}

static int process_redis_cluster_node_add(TALLOC_CTX *ctx, process_redis_cluster_t *cluster, fr_redis_conf_t *conf,
					     fr_pair_t *host_vp, fr_pair_t *port_vp)
{
	process_redis_node_t	*node;
	char buff[FR_IPADDR_STRLEN];

	MEM(node = talloc_zero(ctx, process_redis_node_t));
	node->io_conf = (fr_redis_io_conf_t) {
		.password = conf->password,
		.username = conf->username,
	};
	if (fr_inet_pton_port(&node->io_conf.ipaddr, &node->io_conf.port, host_vp->vp_strvalue,
			      host_vp->vp_length, AF_UNSPEC, true, true) < 0){
	error:
		talloc_free(node);
		return -1;
	}
	node->io_conf.hostname = talloc_strdup(node, fr_inet_ntop(buff, sizeof(buff), &node->io_conf.ipaddr));
	if (node->io_conf.port == 0) {
		if (!port_vp) goto error;
		node->io_conf.port = port_vp->vp_uint16;
	}
	node->io_conf.log_prefix = talloc_asprintf(node, "Coord %s %s:%d", conf->log_prefix,
						   fr_inet_ntop(buff, sizeof(buff), &node->io_conf.ipaddr),
						   node->io_conf.port);
	node->in_cluster = true;
	fr_dlist_insert_tail(&cluster->nodes, node);
	return 0;
}

static void redis_cluster_slots_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	process_redis_rctx_t	*prctx = talloc_get_type_abort(rctx, process_redis_rctx_t);
	int			ret;

	ret = fr_redis_cluster_slots_to_pairs(prctx, request, &prctx->list, reply);
	if (RDEBUG_ENABLED2 && (ret == 0)){
		RDEBUG2("Cluster map fetched:");
		RINDENT();
		fr_pair_list_foreach(&prctx->list, vp) {
			RDEBUG2("%pP", vp);
		}
		REXDENT();
	}
}

static unlang_action_t redis_cluster_map_get(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(uctx, process_redis_rctx_t);
	process_redis_cluster_t	*cluster = rctx->cluster;

	cluster->fetching = true;
	fr_pair_list_init(&rctx->list);

	MEM(rctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, NULL, false));

	fr_redis_command_preformatted_add(rctx->cmds, "CLUSTER SLOTS", redis_cluster_slots_results, rctx);

	while ((rctx->current_node = fr_dlist_next(&cluster->nodes, rctx->current_node))) {
		RDEBUG2("Fetching cluster map %d from %pV:%d", cluster->cluster_id,
			fr_box_ipaddr(rctx->current_node->io_conf.ipaddr), rctx->current_node->io_conf.port);
		if (!rctx->current_node->trunk) {
			rctx->current_node->trunk = fr_redis_trunk_alloc(cluster->rtcluster,
									 &rctx->current_node->io_conf,
									 NULL, NULL, NULL, false);
		}

		if (redis_command_set_enqueue(rctx->current_node->trunk, rctx->cmds) == FR_REDIS_PIPELINE_OK) return UNLANG_ACTION_YIELD;
		RWARN("Unable to enqueue request");
	}

	RERROR("Unable to query any cluster node");
	return UNLANG_ACTION_FAIL;
}

static unlang_action_t redis_cluster_map_get_resume(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(uctx, process_redis_rctx_t);
	process_redis_cluster_t	*cluster = rctx->cluster;
	fr_pair_t		*vp;
	process_redis_pending_t	*pending;
	fr_rb_iter_inorder_t	iter;

	/*
	 *	If no cluster data was returned, try the next node.
	 */
	if (fr_pair_list_num_elements(&rctx->list) == 0) {
		rctx->current_node = fr_dlist_next(&cluster->nodes, rctx->current_node);
		if (!rctx->current_node) RETURN_UNLANG_FAIL;
		return unlang_function_push_with_result(p_result, request, redis_cluster_map_get,
							redis_cluster_map_get_resume, NULL, 0, UNLANG_SUB_FRAME, rctx);
	}

	/*
	 *	Verify the list of nodes, checking the cluster map matches
	 */
	fr_dlist_foreach(&cluster->nodes, process_redis_node_t, node) {
		node->in_cluster = false;
	}
	fr_pair_list_foreach(&rctx->list, shard) {
		vp = NULL;
		while ((vp = fr_pair_find_by_da(&shard->vp_group, vp, attr_redis_node))) {
			fr_pair_t		*endpoint, *port;
			bool			found = false;

			endpoint = fr_pair_find_by_da(&vp->vp_group, NULL, attr_redis_node_endpoint);
			port = fr_pair_find_by_da(&vp->vp_group, NULL, attr_redis_node_port);

			fr_dlist_foreach(&cluster->nodes, process_redis_node_t, node) {
				if ((strcmp(node->io_conf.hostname, endpoint->vp_strvalue) == 0) &&
				    (node->io_conf.port == port->vp_uint16)) {
					node->in_cluster = true;
					found = true;
					break;
				}
			}

			if (found) continue;

			if (process_redis_cluster_node_add(cluster, cluster, cluster->conf, endpoint, port) < 0) {
				RERROR("Failed adding new node to cluster");
			}
		}
	}

	/*
	 *	Remove any nodes not in the returned cluster map.
	 */
	fr_dlist_foreach(&cluster->nodes, process_redis_node_t, node) {
		if (node->in_cluster) continue;
		fr_dlist_remove(&cluster->nodes, node);
		if (node->trunk) talloc_free(node->trunk);
		talloc_free(node);
	}

	/*
	 *	Update the stored cluster definition
	 */
	fr_pair_list_free(&cluster->cluster_pairs);
	fr_pair_list_copy(cluster, &cluster->cluster_pairs, &rctx->list);

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_cluster_id);
	vp->vp_uint16 = cluster->cluster_id;
	cluster->fetching = false;
	cluster->last_update = fr_time();

	fr_pair_list_copy(request->reply_ctx, &request->reply_pairs, &rctx->list);

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_packet_type);
	vp->vp_uint32 = FR_REDIS_CLUSTER_MAP_UPDATE;

	fr_coord_to_worker_reply_broadcast(request);

	if (fr_rb_num_elements(&cluster->pending) == 0) return UNLANG_ACTION_CALCULATE_RESULT;

	for (pending = fr_rb_iter_init_inorder(&cluster->pending, &iter);
	     pending;
	     pending = fr_rb_iter_next_inorder(&cluster->pending, &iter)) {
		fr_rb_iter_delete_inorder(&cluster->pending, &iter);
		unlang_interpret_mark_runnable(pending->request);
		talloc_free(pending);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}

static void redis_cluster_map_get_cancel(request_t *request, UNUSED fr_signal_t action, void *uctx)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(uctx, process_redis_rctx_t);

	if (!rctx->cmds) return;

	RWARN("Forcibly cancelling CLUSTER SLOTS request");
	fr_redis_command_set_cancel(rctx->cmds);
}

static int _process_redis_cluster_free(process_redis_cluster_t *cluster)
{
	process_redis_node_t	*node = NULL;

	while ((node = fr_dlist_next(&cluster->nodes, node))) {
		if (!node->trunk) continue;
		talloc_free(node->trunk);
	}
	return 0;
}

static void process_redis_pending_cancel(module_ctx_t const *mctx, request_t *request, UNUSED fr_signal_t action)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);
	process_redis_pending_t	find, *pending;

	find.request = request;
	pending = fr_rb_find(&rctx->cluster->pending, &find);
	if (!pending) return;

	fr_rb_remove(&rctx->cluster->pending, pending);
	talloc_free(pending);
}

static unlang_action_t process_redis_return_existing(request_t *request, process_redis_cluster_t *cluster,
						     uint32_t worker_id)
{
	fr_pair_t	*vp;

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_cluster_id);
	vp->vp_uint16 = cluster->cluster_id;

	fr_pair_list_copy(request->reply_ctx, &request->reply_pairs, &cluster->cluster_pairs);

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_packet_type);
	vp->vp_uint32 = FR_REDIS_CLUSTER_MAP_UPDATE;

	fr_coord_to_worker_reply_send(request, worker_id);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

RECV(cluster_map_bootstrap)
{
	process_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, process_redis_t);
	process_redis_thread_t	*thread = talloc_get_type_abort(mctx->thread, process_redis_thread_t);
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_worker_id);
	fr_pair_t		*port_vp;
	process_redis_cluster_t	find, *cluster;
	fr_redis_conf_t		*conf;

	if (!vp) return UNLANG_ACTION_FAIL;
	rctx->worker_id = vp->vp_int32;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_bootstrap_node);
	if (!vp) return UNLANG_ACTION_FAIL;

	port_vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_bootstrap_port);

	if (fr_inet_pton_port(&find.addr, &find.port, vp->vp_strvalue, vp->vp_length,
			      AF_UNSPEC, true, true) < 0) return UNLANG_ACTION_FAIL;

	if (find.port == 0) {
		if (!port_vp) return UNLANG_ACTION_FAIL;
		find.port = port_vp->vp_uint16;
	}

	cluster = fr_rb_find(&thread->cluster_by_server, &find);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_max_nodes);
	if (!vp) return UNLANG_ACTION_FAIL;

	if (cluster) {
		/*
		 *	If this is a bootstrap call using nodes matching an existing
		 *	cluster, check the max_nodes match or array sizes will get messy.
		 */
		if (vp->vp_uint8 != cluster->conf->max_nodes) return UNLANG_ACTION_FAIL;

		/*
		 *	We already have data for this cluster, just return it.
		 */
		if (fr_time_gt(cluster->last_update, fr_time_wrap(0))) {
			return process_redis_return_existing(request, cluster, rctx->worker_id);
		}

		/*
		 *	If the cluster map is already being fetched, yield until
		 *	the result is in.
		 *	More than one module instance may be using the same
		 *	so we need to process the request rather than relying
		 *	on the broadcast to workers, as that will only update
		 *	a single module instance.
		 */
		if (cluster->fetching) {
			process_redis_pending_t	*pending;

			RDEBUG2("Cluster map already being fetched");
			rctx->cluster = cluster;
			if (unlang_module_yield(request, recv_cluster_map_bootstrap, process_redis_pending_cancel,
						~FR_SIGNAL_CANCEL, mctx->rctx) != UNLANG_ACTION_YIELD) RETURN_UNLANG_FAIL;

			MEM(pending = talloc(cluster, process_redis_pending_t));
			*pending = (process_redis_pending_t) {.request = request};
			fr_rb_insert(&cluster->pending, pending);

			return UNLANG_ACTION_YIELD;
		}
	}

	MEM(cluster = talloc_zero(thread, process_redis_cluster_t));
	MEM(conf = talloc_zero(cluster, fr_redis_conf_t));
	conf->trunk_conf = inst->trunk_conf;

	cluster->cluster_id = cluster_id++;
	cluster->conf = conf;
	cluster->addr = find.addr;
	cluster->port = find.port;
	fr_rb_inline_init(&cluster->pending, process_redis_pending_t, node, process_redis_pending_cmp, NULL);

	fr_dlist_talloc_init(&cluster->nodes, process_redis_node_t, entry);
	fr_pair_list_init(&cluster->cluster_pairs);

	conf->max_nodes = vp->vp_uint8;

	fr_pair_list_foreach(&request->request_pairs, conf_vp) {
		if (conf_vp->da == attr_redis_username) {
			conf->username = talloc_strdup(conf, conf_vp->vp_strvalue);
		} else if (conf_vp->da == attr_redis_password) {
			conf->password = talloc_strdup(conf, conf_vp->vp_strvalue);
		} else if (conf_vp->da == attr_redis_log_prefix) {
			conf->log_prefix = talloc_strdup(conf, conf_vp->vp_strvalue);
		}
	}

	MEM(cluster->rtcluster = fr_redis_cluster_thread_alloc(cluster, thread->el, conf, NULL, NULL, false));

	/*
	 *	Add all the bootstrap nodes to the cluster.
	 */
	vp = NULL;
	while ((vp = fr_pair_find_by_da(&request->request_pairs, vp, attr_redis_bootstrap_node))) {
		if (process_redis_cluster_node_add(cluster, cluster, conf, vp, port_vp) < 0) {
			talloc_free(cluster);
			return UNLANG_ACTION_FAIL;
		}
	}
	fr_rb_insert(&thread->cluster_by_server, cluster);
	fr_rb_insert(&thread->cluster_by_id, cluster);
	talloc_set_destructor(cluster, _process_redis_cluster_free);

	rctx->cluster = cluster;
	return unlang_function_push_with_result(p_result, request, redis_cluster_map_get, redis_cluster_map_get_resume,
						redis_cluster_map_get_cancel, ~FR_SIGNAL_CANCEL, UNLANG_SUB_FRAME, rctx);
}

RECV(cluster_map_get)
{
	process_redis_thread_t	*thread = talloc_get_type_abort(mctx->thread, process_redis_thread_t);
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_worker_id);
	process_redis_cluster_t	find;

	if (!vp) return UNLANG_ACTION_FAIL;
	rctx->worker_id = vp->vp_int32;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_cluster_id);
	if (!vp) return UNLANG_ACTION_FAIL;

	find.cluster_id = vp->vp_uint16;
	rctx->cluster = fr_rb_find(&thread->cluster_by_id, &find);
	if (!rctx->cluster) {
		return UNLANG_ACTION_FAIL;
	}

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_force_update);
	if ((fr_time_to_sec(fr_time()) == fr_time_to_sec(rctx->cluster->last_update)) && (!vp || !vp->vp_bool)) {
		RWARN("Cluster was updated less than a second ago, returning last response");
		return process_redis_return_existing(request, rctx->cluster, rctx->worker_id);
	}

	return unlang_function_push_with_result(p_result, request, redis_cluster_map_get, redis_cluster_map_get_resume,
						NULL, 0, UNLANG_SUB_FRAME, rctx);
}

static unlang_action_t mod_process(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	fr_process_state_t const *state;

	PROCESS_TRACE;

	(void)talloc_get_type_abort_const(mctx->mi->data, process_redis_t);
	fr_assert(FR_REDIS_PACKET_CODE_VALID(request->packet->code));

	request->component = "redis";
	request->module = NULL;
	fr_assert(request->proto_dict == dict_redis);

	UPDATE_STATE(packet);

	if (!state->recv) {
		REDEBUG("Invalid packet type (%u)", request->packet->code);
		RETURN_UNLANG_FAIL;
	}

	return state->recv(p_result, mctx, request);
}

static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	process_redis_thread_t	*t = talloc_get_type_abort(mctx->thread, process_redis_thread_t);

	t->el = mctx->el;
	fr_rb_inline_init(&t->cluster_by_server, process_redis_cluster_t, cluster_by_server, cluster_server_cmp, NULL);
	fr_rb_inline_init(&t->cluster_by_id, process_redis_cluster_t, cluster_by_id, cluster_id_cmp, NULL);
	return 0;
}

static int mod_load(void)
{
	return redis_dict_init();
	attr_packet_type = attr_redis_packet_type;
}

static fr_process_state_t const process_state[] = {
	[ FR_REDIS_CLUSTER_MAP_BOOTSTRAP ] = {
		.default_reply = FR_REDIS_CLUSTER_MAP_UPDATE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_cluster_map_bootstrap,
	},
	[ FR_REDIS_CLUSTER_MAP_GET ] = {
		.default_reply = FR_REDIS_CLUSTER_MAP_UPDATE,
		.default_rcode = RLM_MODULE_NOOP,
		.recv = recv_cluster_map_get,
	}
};

extern fr_process_module_t process_redis;
fr_process_module_t process_redis = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.name			= "redis",
		.config			= config,
		.onload			= mod_load,
		MODULE_INST(process_redis_t),
		MODULE_RCTX(process_redis_rctx_t),
		MODULE_THREAD_INST(process_redis_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
	},
	.process	= mod_process,
	.dict		= &dict_redis,
	.packet_type	= &attr_redis_packet_type
};
