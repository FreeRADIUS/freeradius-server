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

static const uint32_t redis_shards_version = REDIS_VERSION(7, 0, 0);

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
	uint32_t			version;		//!< Redis version on this node.
	uint64_t			current_epoch;		//!< Redis cluster epoch as reported by this node.
	fr_pair_list_t			trigger_args;		//!< Pair list to pass to trigger.
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
	fr_redis_ct_t			*rtcluster;		//!< Cluster used to allocate redis trunk connections
	fr_pair_list_t			cluster_pairs;		//!< Pairs built from the last fetch.
	bool				fetching;		//!< The map is being fetched.
	fr_time_t			last_update;		//!< When was the map last updated.
	fr_rb_tree_t			pending;		//!< Requests waiting for custer map update.
	fr_coord_pair_t			*coord_pair;		//!< The coord_pair which requested this cluster map.
	bool				failed;			//!< Has the cluster failed.
	fr_timer_t			*ev;			//!< Timer event for retry / refresh.
} process_redis_cluster_t;

typedef struct {
	request_t			*request;
	fr_rb_node_t			node;
} process_redis_pending_t;

static fr_cmp_ret_t cluster_server_cmp(void const *a, void const *b)
{
	process_redis_cluster_t const	*cluster_a = (process_redis_cluster_t const *)a;
	process_redis_cluster_t const	*cluster_b = (process_redis_cluster_t const *)b;
	fr_cmp_ret_t	ret;

	ret = fr_ipaddr_cmp(&cluster_a->addr, &cluster_b->addr);
	if (ret != 0) return ret;

	return CMP(cluster_a->port, cluster_b->port);
}

static fr_cmp_ret_t cluster_id_cmp(void const*a, void const *b)
{
	process_redis_cluster_t const	*cluster_a = (process_redis_cluster_t const *)a;
	process_redis_cluster_t const	*cluster_b = (process_redis_cluster_t const *)b;

	return CMP(cluster_a->cluster_id, cluster_b->cluster_id);
}

static fr_cmp_ret_t process_redis_pending_cmp(void const *a, void const *b)
{
	process_redis_pending_t	const *pending_a = (process_redis_pending_t const *)a;
	process_redis_pending_t	const *pending_b = (process_redis_pending_t const *)b;

	return CMP(pending_a->request, pending_b->request);
}

typedef struct {
	process_redis_sections_t	sections;
	module_method_t const		*method;
	trunk_conf_t			trunk_conf;
	fr_time_delta_t			timeout;
	fr_time_delta_t			retry_interval;
	fr_time_delta_t			refresh_interval;
	char const			*inst_name;
} process_redis_t;

typedef struct {
	fr_event_list_t			*el;
	fr_rb_tree_t			cluster_by_server;	//!< Tree of clusters by primary bootstrap server.
	fr_rb_tree_t			cluster_by_id;		//!< Tree of clusters by ID.
} process_redis_thread_t;

static const conf_parser_t config[] = {
	{ FR_CONF_OFFSET_SUBSECTION("pool", 0, process_redis_t, trunk_conf, trunk_config) },
	{ FR_CONF_OFFSET("timeout", process_redis_t, timeout), .dflt = "5s" },
	{ FR_CONF_OFFSET("retry_interval", process_redis_t, retry_interval), .dflt = "30s" },
	{ FR_CONF_OFFSET("refresh_interval", process_redis_t, refresh_interval) },
	CONF_PARSER_TERMINATOR
};

/** State of cluster map fetching from each node.
 */
typedef enum {
	CLUSTER_MAP_GET_INFO = 0,
	CLUSTER_MAP_GOT_INFO,
	CLUSTER_MAP_GET_MAP,
	CLUSTER_MAP_GOT_MAP,
	CLUSTER_MAP_GET_FAILED,
	CLUSTER_MAP_GET_TIMEOUT,
} map_get_status_t;

/** Resume context for node specific calls
 */
typedef struct {
	process_redis_node_t	*node;			//!< Node being queried.
	fr_dlist_t		entry;			//!< In list of resume contexts.
	map_get_status_t	status;			//!< Status of the node calls.
	bool			cluster_ok;		//!< Does CLUSTER INFO say the cluster is OK.
	fr_pair_list_t		list;			//!< To populate with parsed reply data.
	fr_redis_command_set_t	*cmds;			//!< Command set for fetching cluster map.
	fr_timer_t		*ev;			//!< Timeout event for this node.
} process_redis_node_rctx_t;

/** Resume context for Redis requests */
typedef struct {
	process_redis_t const	*inst;			//!< Module instance.
	process_redis_thread_t	*thread;		//!< Thread instance.
	unlang_result_t		result;			//!< Where results are written to
	int32_t			worker_id;		//!< The worker which sent the data leading to this request.
	process_redis_cluster_t	*cluster;		//!< Cluster which is being updated.
	process_redis_node_t	*current_node;		//!< Node currently being queried.
	fr_dlist_head_t		rctx_list;		//!< List of per-node resume contexts.
	uint64_t		cluster_epoch;		//!< Largest epoch value returned by any node.
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

/** Convert the "slots" array in CLUSTER SHARDS replies into pairs
 *
 * @param reply		Redis reply containing the "slots" array.
 * @param shard_vp	Pair representing shard to build slots pairs under.
 * @param slots_covered	Array recording which slots have been covered.
 * @return
 *	- number of slot ranges found
 *	- -1 on error
 */
static int fr_redis_cluster_shards_slots_to_pairs(redisReply *reply, fr_pair_t *shard_vp, bool slots_covered[KEY_SLOTS])
{
	fr_pair_t	*slot_vp, *vp;
	size_t		i;
	uint16_t	s;

	/*
	 *	The "slots" value must be an array with an even number
	 *	of entries and all integers.
	 */
	if (reply->type != REDIS_REPLY_ARRAY) return -1;
	if (reply->elements == 0) return 0;
	if ((reply->elements % 2) != 0) return -1;
	for (i = 0; i < reply->elements; i++) if (reply->element[i]->type != REDIS_REPLY_INTEGER) return -1;

	for (i = 0; i < (reply->elements - 1); i += 2) {
		MEM(slot_vp = fr_pair_afrom_da(shard_vp, attr_redis_slot));
		fr_pair_append(&shard_vp->vp_group, slot_vp);

		MEM(vp = fr_pair_afrom_da(slot_vp, attr_redis_slot_start));
		if (reply->element[i]->type != REDIS_REPLY_INTEGER) return -1;
		if (reply->element[i]->integer >= KEY_SLOTS) return -1;
		vp->vp_uint16 = (uint16_t) reply->element[i]->integer;
		fr_pair_append(&slot_vp->vp_group, vp);

		MEM(vp = fr_pair_afrom_da(slot_vp, attr_redis_slot_end));
		if (reply->element[i + 1]->type != REDIS_REPLY_INTEGER) return -1;
		vp->vp_uint16 = (uint16_t) reply->element[i + 1]->integer;
		if (reply->element[i + 1]->integer >= KEY_SLOTS) return -1;
		fr_pair_append(&slot_vp->vp_group, vp);

		for(s = reply->element[i]->integer; s <= reply->element[i + 1]->integer; s++) slots_covered[s] = true;
	}

	return i / 2;
}

/** Convert the "nodes" array in CLUSTER SHARDS replies into pairs
 *
 * @param reply		Redis reply containing the "nodes" array.
 * @param shard_vp	Pair representing shard to build ndoes pairs under.
 * @return
 *	- number of nodes found
 *	- -1 on error
 */
static int fr_redis_cluster_shards_nodes_to_pairs(redisReply *reply, fr_pair_t *shard_vp)
{
	fr_pair_t	*node_vp, *vp;
	size_t		i, j;
	redisReply	*node, *field, *value;

	/*
	 *	The "nodes" value must be an array of arrays.
	 */
	if (reply->type != REDIS_REPLY_ARRAY) return -1;
	for (i = 0; i < reply->elements; i++) if (reply->element[i]->type != REDIS_REPLY_ARRAY) return -1;

	for (i = 0; i < reply->elements; i++) {
		node = reply->element[i];

		/*
		 *	Every other entry must be a string - the field name.
		 */
		for (j = 0; j < node->elements; j += 2) if (node->element[j]->type != REDIS_REPLY_STRING) return -1;

		MEM(node_vp = fr_pair_afrom_da(shard_vp, attr_redis_node));

		for (j = 0; j < (node->elements - 1); j +=2) {
			field = node->element[j];
			value = node->element[j + 1];
			if (strcmp(field->str, "endpoint") == 0) {
				if (value->type != REDIS_REPLY_STRING) return -1;
				MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_endpoint));
				fr_pair_value_bstrndup(vp, value->str, value->len, true);

			} else if (strcmp(field->str, "port") == 0) {
				if (value->type != REDIS_REPLY_INTEGER) return -1;
				MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_port));
				vp->vp_uint16 = (uint16_t) value->integer;

			} else if (strcmp(field->str, "role") == 0) {
				if (value->type != REDIS_REPLY_STRING) return -1;
				MEM(vp = fr_pair_afrom_da(node_vp, attr_redis_node_role));
				vp->vp_uint8 = (strcmp(value->str, "master") == 0) ? 1 : 2;

			} else if (strcmp(field->str, "health") == 0) {
				if (value->type != REDIS_REPLY_STRING) return -1;
				if (strcmp(value->str, "failed") == 0) {
					TALLOC_FREE(node_vp);
					break;
				}
				continue;

			} else {
				continue;
			}

			fr_pair_append(&node_vp->vp_group, vp);
		}

		if (!node_vp) continue;

		fr_pair_append(&shard_vp->vp_group, node_vp);
	}

	return i;
}

/** Convert the reply to CLUSTER SHARDS into pairs
 *
 * The CLUSTER SHARDS reply is designed as an extensible
 * structure using arrays containing named fields.
 * i.e. an element which is the field name, followed by
 * the value in the next element.
 *
 * The fields for node entries are specifically described as
 * being extensible.
 *
 * The CLUSTER SHARDS reply structure
 @verbatim
   [0] -> Shard 0
       [0] -> "slots"
       [1] -> Array of slot entries in pairs of start / end values.
           [0] -> key_slot0_start
           [1] -> key_slot0_end
	   [2] -> key_slot1_start
	   [3] -> key_slot1_end
	   [4 .. n] -> key_slot2_start .. key_slotm_end
       [2] -> "nodes"
       [3] -> Array of nodes which cover the slots in the "slots" array.
           [0] -> Node 0
	       [0]  -> "id"
               [1]  -> Node ID
               [2]  -> "port"
               [3]  -> (integer) port number
               [4]  -> "ip"
               [5]  -> IP address of node
               [6]  -> "endpoint"
               [7]  -> Preferred endpoint to connect to node
               [8]  -> "role"
               [9]  -> ("master"|"replica")
               [10] -> "replication-offset"
               [11] -> (integer) replication offset
               [12] -> "health"
               [13] -> ("online"|"failed"|"loading")
           [1] -> Node 1
               [0 .. n] -> Entries for Node 1
   [1] -> Shard 1
       [...]
 @endverbatim
 */
 static int fr_redis_cluster_shards_to_pairs(TALLOC_CTX *ctx, request_t *request, fr_pair_list_t *list, redisReply *reply)
{
	size_t		i;
	fr_pair_t	*shard_vp;
	int		ret;
	bool		slots_covered[KEY_SLOTS];
	uint16_t	s;

	if(reply->type != REDIS_REPLY_ARRAY) return -1;

	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);

	memset(slots_covered, 0, sizeof(slots_covered));

	for (i = 0; i < reply->elements; i++) {
		size_t		j;
		redisReply	*shard = reply->element[i];

		if (shard->type != REDIS_REPLY_ARRAY) {
		error:
			fr_pair_list_free(list);
			return -1;
		}
		if (shard->elements < 4 || (shard->elements % 2 != 0)) goto error;

		MEM(shard_vp = fr_pair_afrom_da(ctx, attr_redis_shard));
		fr_pair_append(list, shard_vp);

		for (j = 0; j < (shard->elements - 1); j += 2) {
			redisReply *field = shard->element[j];
			if (strcmp(field->str, "slots") == 0) {
				ret = fr_redis_cluster_shards_slots_to_pairs(shard->element[j + 1], shard_vp,
									     slots_covered);
				if (ret < 0) goto error;

				/*
				 *	Failed nodes can be reported with zero slots entries.
				 *	Remove this shard from the list.
				 */
				if (ret == 0) {
				clean_up:
					fr_pair_remove(list, shard_vp);
					talloc_free(shard_vp);
					break;
				}

			} else if (strcmp(field->str, "nodes") == 0) {
				ret = fr_redis_cluster_shards_nodes_to_pairs(shard->element[j + 1], shard_vp);
				if (ret < 0) goto error;
				if (ret == 0) goto clean_up;

			} else {
				continue;
			}
		}
	}

	for (s = 0; s < KEY_SLOTS; s++) if (!slots_covered[s]) goto error;

	return 0;
}

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
	bool		slots_covered[KEY_SLOTS];
	uint16_t	s;

	if(reply->type != REDIS_REPLY_ARRAY) return -1;

	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);

	memset(slots_covered, 0, sizeof(slots_covered));

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
		list_free:
			fr_pair_list_free(list);
			return -1;
		}
		if (map->element[0]->integer >= KEY_SLOTS) goto error;
		vp->vp_uint16 = (uint16_t) map->element[0]->integer;
		fr_pair_append(&slot_vp->vp_group, vp);

		MEM(vp = fr_pair_afrom_da(slot_vp, attr_redis_slot_end));
		if (map->element[1]->type != REDIS_REPLY_INTEGER) goto error;
		if (map->element[0]->integer >= KEY_SLOTS) goto error;
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

		for (s = map->element[0]->integer; s <= map->element[1]->integer; s++) slots_covered[s] = true;

		fr_pair_append(list, shard_vp);
	}

	for (s = 0; s < KEY_SLOTS; s++) if (!slots_covered[s]) goto list_free;

	return 0;
}

static int process_redis_cluster_node_add(TALLOC_CTX *ctx, process_redis_cluster_t *cluster, process_redis_t const *inst,
					  fr_redis_conf_t *conf, fr_pair_t *host_vp, fr_pair_t *port_vp)
{
	process_redis_node_t	*node;
	fr_ipaddr_t		ipaddr;
	char buff[FR_IPADDR_STRLEN];

	MEM(node = talloc_zero(ctx, process_redis_node_t));
	node->io_conf = (fr_redis_io_conf_t) {
		.password = conf->password,
		.username = conf->username,
		.use_tls = conf->use_tls,
	};
	if (fr_inet_pton_port(&ipaddr, &node->io_conf.port, host_vp->vp_strvalue,
			      host_vp->vp_length, AF_UNSPEC, true, true) < 0){
	error:
		talloc_free(node);
		return -1;
	}
	node->io_conf.hostname = talloc_strdup(node, fr_inet_ntop(buff, sizeof(buff), &ipaddr));
	if (node->io_conf.port == 0) {
		if (!port_vp) goto error;
		node->io_conf.port = port_vp->vp_uint16;
	}
	node->io_conf.log_prefix = talloc_asprintf(node, "Coord %s %s:%d", conf->log_prefix,
						   fr_inet_ntop(buff, sizeof(buff), &ipaddr),
						   node->io_conf.port);
	node->in_cluster = true;
	fr_pair_list_init(&node->trigger_args);
	if (conf->trunk_conf.conn_triggers) {
		module_trigger_args_build(node, &node->trigger_args, NULL,
					&(module_trigger_args_t) {
						.module = "process_redis",
						.name = inst->inst_name, \
						.server = buff, \
						.port = node->io_conf.port \
					}); \
	}
	fr_dlist_insert_tail(&cluster->nodes, node);
	return 0;
}

static void redis_cluster_info_server_results(request_t *request, UNUSED fr_redis_command_t *cmd,
					      redisReply *reply, void *rctx)
{
	process_redis_node_t	*node = talloc_get_type_abort(rctx, process_redis_node_t);
	char			buffer[20];

	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);
	if (fr_redis_parse_version(buffer, sizeof(buffer), reply) != REDIS_RCODE_SUCCESS) return;
	node->version = fr_redis_version_num(buffer);
	RDEBUG3("Cluster node %s:%d is running Redis version %s", node->io_conf.hostname, node->io_conf.port, buffer);
}

static void redis_cluster_info_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	process_redis_node_rctx_t	*nrctx = talloc_get_type_abort(rctx, process_redis_node_rctx_t);
	fr_sbuff_t			sbuff;

	fr_redis_reply_print(L_DBG_LVL_3, reply, request, 0, REDIS_RCODE_SUCCESS);

	if (reply->type != REDIS_REPLY_STRING) {
		RERROR("Bad value type, expected string, got %s",
			fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
	error:
		nrctx->status = CLUSTER_MAP_GET_FAILED;
		return;
	}

	fr_sbuff_init_in(&sbuff, reply->str, reply->len);
	if (!fr_sbuff_adv_to_str_literal(&sbuff, SIZE_MAX, "cluster_state:")) {
		RERROR("Response did not contain cluster_state");
		goto error;
	}
	fr_sbuff_advance(&sbuff, sizeof("cluster_state:") - 1);

	if (fr_sbuff_adv_past_str_literal(&sbuff, "ok\r\n")) {
		nrctx->cluster_ok = true;
		RDEBUG2("Node %s:%d reports Cluster OK", nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
	} else {
		RERROR("Node %s:%d reports Cluster Failed", nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
	}

	/*
	 *	The sequence of entries in the CLUSTER INFO results is not guaranteed,
	 *	so we start the search from the beginning again.
	 */
	fr_sbuff_set_to_start(&sbuff);

	if (!fr_sbuff_adv_to_str_literal(&sbuff, SIZE_MAX, "cluster_current_epoch:")) {
		RERROR("Response did not contain cluster_current_epoch");
		goto error;
	}
	fr_sbuff_advance(&sbuff, sizeof("cluster_current_epoch:") -1);

	if (fr_sbuff_out_uint64(NULL, &nrctx->node->current_epoch, &sbuff, false) < 0) {
		RERROR("Failed parsing current_cluster_epoch");
		goto error;
	}

	RDEBUG3("Node %s:%d reported epoch %"PRIu64, nrctx->node->io_conf.hostname,
		nrctx->node->io_conf.port, nrctx->node->current_epoch);
	nrctx->status = CLUSTER_MAP_GOT_INFO;
	return;
}

static void redis_cluster_slots_results(request_t *request, UNUSED fr_redis_command_t *cmd, redisReply *reply, void *rctx)
{
	process_redis_node_rctx_t	*nrctx = talloc_get_type_abort(rctx, process_redis_node_rctx_t);
	int				ret;

	if (nrctx->node->version > redis_shards_version) {
		ret = fr_redis_cluster_shards_to_pairs(nrctx, request, &nrctx->list, reply);
	} else {
		ret = fr_redis_cluster_slots_to_pairs(nrctx, request, &nrctx->list, reply);
	}
	if (RDEBUG_ENABLED2 && (ret == 0)){
		RDEBUG2("Cluster map fetched:");
		RINDENT();
		fr_pair_list_foreach(&nrctx->list, vp) {
			RDEBUG2("%pP", vp);
		}
		REXDENT();
	}
	nrctx->status = CLUSTER_MAP_GOT_MAP;
}

static void redis_cluster_map_get_timeout(UNUSED fr_timer_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	process_redis_node_rctx_t	*nrctx = talloc_get_type_abort(uctx, process_redis_node_rctx_t);

	ERROR("Fetching map from %s:%d failed", nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
	nrctx->status = CLUSTER_MAP_GET_TIMEOUT;
	fr_redis_command_set_cancel(nrctx->cmds);
}

static void redis_cluster_map_get_refetch(UNUSED fr_timer_list_t *tl, fr_time_t now, void *uctx)
{
	process_redis_cluster_t	*cluster = talloc_get_type_abort(uctx, process_redis_cluster_t);
	fr_pair_list_t		list;
	fr_pair_t		*vp;
	TALLOC_CTX		*local = talloc_new(NULL);

	if (cluster->failed) {
		DEBUG2("Retrying fetch of cluster map");
	} else {
		DEBUG2("Refreshing cluster map");
	}

	fr_pair_list_init(&list);
	fr_pair_list_append_by_da(local, vp, &list, attr_redis_packet_type, (uint32_t)FR_REDIS_CLUSTER_MAP_GET, false);
	if (!vp) goto free;

	fr_pair_list_append_by_da(local, vp, &list, attr_redis_cluster_id, cluster->cluster_id, false);
	if (!vp) goto free;

	fr_coord_pair_coord_request_start(cluster->coord_pair, &list, now);

free:
	talloc_free(local);
}

/** Send a Cluster-Failed message to a worker
 */
static unlang_action_t process_redis_return_failed(request_t *request, process_redis_cluster_t *cluster,
						   uint32_t worker_id)
{
	fr_pair_t	*vp;

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_cluster_id);
	vp->vp_uint16 = cluster->cluster_id;

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_packet_type);
	vp->vp_uint32 = FR_REDIS_CLUSTER_MAP_FAIL;

	fr_coord_to_worker_reply_send(request, worker_id);
	return UNLANG_ACTION_CALCULATE_RESULT;
}

static unlang_action_t redis_cluster_map_get(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(uctx, process_redis_rctx_t);
	process_redis_cluster_t	*cluster = rctx->cluster;
	process_redis_node_rctx_t	*nrctx;

	cluster->fetching = true;
	fr_dlist_talloc_init(&rctx->rctx_list, process_redis_node_rctx_t, entry);

	fr_dlist_foreach(&cluster->nodes, process_redis_node_t, node) {
		MEM(nrctx = talloc_zero(rctx, process_redis_node_rctx_t));
		nrctx->node = node;
		fr_pair_list_init(&nrctx->list);

		MEM(nrctx->cmds = fr_redis_command_set_alloc(rctx, request, NULL, NULL, nrctx, false));

		RDEBUG2("Fetching cluster map %d from %s:%d", cluster->cluster_id, node->io_conf.hostname,
			node->io_conf.port);
		if (!node->trunk) {
			node->trunk = fr_redis_trunk_alloc(cluster->rtcluster, &node->io_conf, &node->trigger_args,
							   NULL, NULL, false);
			if (fr_redis_command_literal_add(nrctx->cmds, "INFO SERVER", redis_cluster_info_server_results,
							 node) != FR_REDIS_PIPELINE_OK) {
			fail:
				fr_fatal_assert_fail("Failed adding command to Redis command set");
			}
		}

		if (fr_redis_command_literal_add(nrctx->cmds, "CLUSTER INFO", redis_cluster_info_results,
						 nrctx) != FR_REDIS_PIPELINE_OK) goto fail;

		if (redis_command_set_enqueue(node->trunk, nrctx->cmds) != FR_REDIS_PIPELINE_OK) {
			RERROR("Unable to enqueue request on node %s:%d", node->io_conf.hostname,
			       node->io_conf.port);
			talloc_free(nrctx);
			continue;
		}

		fr_timer_in(nrctx, rctx->thread->el->tl, &nrctx->ev, rctx->inst->timeout, true,
			    redis_cluster_map_get_timeout, nrctx);
		fr_dlist_insert_tail(&rctx->rctx_list, nrctx);
	}

	if (fr_dlist_num_elements(&rctx->rctx_list) > 0) return UNLANG_ACTION_YIELD;

	RERROR("Unable to query any cluster node");

	cluster->failed = true;
	if (fr_timer_in(cluster, rctx->thread->el->tl, &cluster->ev, rctx->inst->retry_interval,
			false, redis_cluster_map_get_refetch, cluster) < 0) {
		RERROR("Failed setting up retry event");
	};
	return process_redis_return_failed(request, cluster, rctx->worker_id);
}

static unlang_action_t redis_cluster_map_get_resume(UNUSED unlang_result_t *p_result, request_t *request, void *uctx)
{
	process_redis_rctx_t	*rctx = talloc_get_type_abort(uctx, process_redis_rctx_t);
	process_redis_cluster_t	*cluster = rctx->cluster;
	fr_pair_t		*vp;
	process_redis_pending_t	*pending;
	fr_rb_iter_inorder_t	iter;
	size_t			completed = 0;
	fr_pair_list_t		*list = NULL;

	/*
	 *	The request processing will resume when one or more nodes has
	 *	replied.
	 *	Check the current state of the rctx for each node.
	 */
	fr_dlist_foreach(&rctx->rctx_list, process_redis_node_rctx_t, nrctx) {
		switch (nrctx->status) {
		case CLUSTER_MAP_GET_INFO:
		case CLUSTER_MAP_GET_MAP:
			break;

		case CLUSTER_MAP_GET_FAILED:
		case CLUSTER_MAP_GET_TIMEOUT:
		clean_up:
			fr_dlist_remove(&rctx->rctx_list, nrctx);
			talloc_free(nrctx);
			break;

		case CLUSTER_MAP_GOT_INFO:
			/*
			 *	Check epoch returned by node.  Anything lower than
			 *	the highest value seen so far can be disregarded.
			 */
			if (nrctx->node->current_epoch < rctx->cluster_epoch) {
				RWARN("Node %s:%d returned lower epoch than other nodes - ignoring",
				      nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
				goto clean_up;
			}

			rctx->cluster_epoch = nrctx->node->current_epoch;

			fr_redis_command_set_clear(nrctx->cmds);
			if (nrctx->node->version > redis_shards_version) {
				if (fr_redis_command_literal_add(nrctx->cmds, "CLUSTER SHARDS",
								 redis_cluster_slots_results,
								 nrctx) != FR_REDIS_PIPELINE_OK) goto clean_up;
			} else {
				if (fr_redis_command_literal_add(nrctx->cmds, "CLUSTER SLOTS",
								 redis_cluster_slots_results,
								 nrctx) != FR_REDIS_PIPELINE_OK) goto clean_up;
			}
			nrctx->status = CLUSTER_MAP_GET_MAP;
			if (redis_command_set_enqueue(nrctx->node->trunk, nrctx->cmds) != FR_REDIS_PIPELINE_OK) {
				RERROR("Unable to enqueue request on node %s:%d",
				       nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
				goto clean_up;
			}
			break;

		case CLUSTER_MAP_GOT_MAP:
			if (fr_pair_list_num_elements(&nrctx->list) == 0) {
				RWARN("Node %s:%d didn't return a cluster", nrctx->node->io_conf.hostname,
				      nrctx->node->io_conf.port);
				goto clean_up;
			}
			completed++;
			break;
		}
	}

	/*
	 *	If there are still nodes with outstanding rctx then yield.
	 */
	if (completed < fr_dlist_num_elements(&rctx->rctx_list)) {
		if (unlang_function_repeat_set(request, redis_cluster_map_get_resume) < 0) goto fail;
		return UNLANG_ACTION_YIELD;
	}

	if (fr_dlist_num_elements(&rctx->rctx_list) < 1) {
		RERROR("No node returned a valid cluster map");
	fail:
		cluster->failed = true;
		if (fr_timer_in(cluster, rctx->thread->el->tl, &cluster->ev, rctx->inst->retry_interval,
				false, redis_cluster_map_get_refetch, cluster) < 0) {
			RERROR("Failed setting up retry event");
		};
		return process_redis_return_failed(request, cluster, rctx->worker_id);
	}

	/*
	 *	Find the first node's rctx where the node epoch matches the
	 *	highest seen value.
	 */
	fr_dlist_foreach(&rctx->rctx_list, process_redis_node_rctx_t, nrctx) {
		if (nrctx->node->current_epoch == rctx->cluster_epoch) {
			list = &nrctx->list;
			break;
		}
	}
	if (unlikely(!list)) goto fail;

	/*
	 *	Verify the list of nodes, checking the cluster map matches
	 */
	fr_dlist_foreach(&cluster->nodes, process_redis_node_t, node) {
		node->in_cluster = false;
	}
	fr_pair_list_foreach(list, shard) {
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

			if (process_redis_cluster_node_add(cluster, cluster, rctx->inst, cluster->conf, endpoint, port) < 0) {
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
	fr_pair_list_copy(cluster, &cluster->cluster_pairs, list);

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_cluster_id);
	vp->vp_uint16 = cluster->cluster_id;
	cluster->fetching = false;
	cluster->failed = false;
	cluster->last_update = fr_time();

	fr_pair_list_copy(request->reply_ctx, &request->reply_pairs, list);

	fr_pair_prepend_by_da(request->reply_ctx, &vp, &request->reply_pairs, attr_redis_packet_type);
	vp->vp_uint32 = FR_REDIS_CLUSTER_MAP_UPDATE;

	fr_coord_to_worker_reply_broadcast(request);

	if ((fr_time_delta_ispos(rctx->inst->refresh_interval)) &&
	    (fr_timer_in(cluster, rctx->thread->el->tl, &cluster->ev, rctx->inst->refresh_interval,
			false, redis_cluster_map_get_refetch, cluster) < 0)) {
		RERROR("Failed setting up refresh event");
	}

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

	fr_dlist_foreach(&rctx->rctx_list, process_redis_node_rctx_t, nrctx) {
		if (!nrctx->cmds) continue;
		RWARN("Forcibly cancelling cluster map request on %s:%d",
		      nrctx->node->io_conf.hostname, nrctx->node->io_conf.port);
		fr_redis_command_set_cancel(nrctx->cmds);
	}
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
	fr_rb_find((void **)&pending, &rctx->cluster->pending, &find);
	if (!pending) return;

	fr_rb_remove(NULL, &rctx->cluster->pending, pending);
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
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);
	process_redis_t const	*inst = rctx->inst;
	process_redis_thread_t	*thread = rctx->thread;
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_worker_id);
	fr_pair_t		*port_vp;
	process_redis_cluster_t	find, *cluster;
	fr_redis_conf_t		*conf;
	CONF_SECTION		*tls_conf = NULL;

	rctx->worker_id = vp ? vp->vp_int32 : 0;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_bootstrap_node);
	fr_fatal_assert_msg(vp, "Missing %s", attr_redis_bootstrap_node->name);

	port_vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_bootstrap_port);

	if (fr_inet_pton_port(&find.addr, &find.port, vp->vp_strvalue, vp->vp_length,
			      AF_UNSPEC, true, true) < 0) {
		fr_fatal_assert_fail("Unable to parse bootstrap node");
	}

	if (find.port == 0) {
		fr_fatal_assert_msg(port_vp, "Missing %s", attr_redis_bootstrap_port->name);
		find.port = port_vp->vp_uint16;
	}

	fr_rb_find((void **)&cluster, &thread->cluster_by_server, &find);

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_max_nodes);
	fr_fatal_assert_msg(vp, "Missing %s", attr_redis_max_nodes->name);

	if (cluster) {
		/*
		 *	If this is a bootstrap call using nodes matching an existing
		 *	cluster, check the max_nodes match or array sizes will get messy.
		 */
		fr_fatal_assert_msg(vp->vp_uint8 == cluster->conf->max_nodes,
				    "Max nodes (%d) mis-match with existing cluster configured with %d",
				    vp->vp_uint8, cluster->conf->max_nodes);

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

		/*
		 *	Cluster map fetching failed, and the retry timer is armed.
		 *	Tell the caller that the map has failed.
		 */
		if (cluster->failed) {
			return process_redis_return_failed(request, cluster, rctx->worker_id);
		}
	}

	MEM(cluster = talloc_zero(thread, process_redis_cluster_t));
	MEM(conf = talloc_zero(cluster, fr_redis_conf_t));
	conf->trunk_conf = inst->trunk_conf;

	cluster->cluster_id = cluster_id++;
	cluster->conf = conf;
	cluster->addr = find.addr;
	cluster->port = find.port;
	cluster->coord_pair = fr_coord_pair_request_coord_pair(request);
	fr_rb_inline_init(&cluster->pending, process_redis_pending_t, node, process_redis_pending_cmp, NULL);

	fr_dlist_talloc_init(&cluster->nodes, process_redis_node_t, entry);
	fr_pair_list_init(&cluster->cluster_pairs);

	conf->max_nodes = vp->vp_uint8;
	conf->use_cluster_map = true;

	fr_pair_list_foreach(&request->request_pairs, conf_vp) {
		if (conf_vp->da == attr_redis_username) {
			conf->username = talloc_strdup(conf, conf_vp->vp_strvalue);
		} else if (conf_vp->da == attr_redis_password) {
			conf->password = talloc_strdup(conf, conf_vp->vp_strvalue);
		} else if (conf_vp->da == attr_redis_log_prefix) {
			conf->log_prefix = talloc_strdup(conf, conf_vp->vp_strvalue);
		}
	}

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_use_tls);
	if (vp) {
		vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_tls_conf);
		fr_fatal_assert_msg(vp, "Missing %s when TLS is enabled", attr_redis_tls_conf->name);
		conf->use_tls = true;
		tls_conf = (CONF_SECTION *)(uintptr_t)vp->vp_uint64;
	}

	MEM(cluster->rtcluster = fr_redis_ct_alloc(cluster, tls_conf, thread->el, conf, NULL, NULL, false));

	/*
	 *	Add all the bootstrap nodes to the cluster.
	 */
	vp = NULL;
	while ((vp = fr_pair_find_by_da(&request->request_pairs, vp, attr_redis_bootstrap_node))) {
		if (process_redis_cluster_node_add(cluster, cluster, inst, conf, vp, port_vp) < 0) {
			talloc_free(cluster);
			fr_fatal_assert_fail("Failed adding cluster node to list");
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
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);
	fr_pair_t		*vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_worker_id);
	process_redis_cluster_t	find;

	rctx->worker_id = vp ? vp->vp_int32 : 0;

	vp = fr_pair_find_by_da(&request->request_pairs, NULL, attr_redis_cluster_id);
	fr_fatal_assert_msg(vp, "Missing %s", attr_redis_cluster_id->name);

	find.cluster_id = vp->vp_uint16;
	fr_rb_find((void **)&rctx->cluster, &rctx->thread->cluster_by_id, &find);
	fr_fatal_assert_msg(rctx->cluster, "Update requested for cluster %d which has not been bootstrapped",
			    vp->vp_uint16);

	/*
	 *	Cluster map fetching failed, and the retry timer is armed.
	 *	Tell the caller that the map has failed.
	 */
	if (fr_timer_armed(rctx->cluster->ev)) {
		return process_redis_return_failed(request, rctx->cluster, rctx->worker_id);
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
	process_redis_t		*inst = talloc_get_type_abort(mctx->mi->data, process_redis_t);
	process_redis_thread_t	*thread = talloc_get_type_abort(mctx->thread, process_redis_thread_t);
	process_redis_rctx_t	*rctx = talloc_get_type_abort(mctx->rctx, process_redis_rctx_t);

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

	rctx->inst = inst;
	rctx->thread = thread;

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

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
	process_redis_t *inst = talloc_get_type_abort(mctx->mi->data, process_redis_t);

	inst->inst_name = mctx->mi->name;
	return (0);
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
		.instantiate		= mod_instantiate,
		MODULE_INST(process_redis_t),
		MODULE_RCTX(process_redis_rctx_t),
		MODULE_THREAD_INST(process_redis_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
	},
	.process	= mod_process,
	.dict		= &dict_redis,
	.packet_type	= &attr_redis_packet_type
};
