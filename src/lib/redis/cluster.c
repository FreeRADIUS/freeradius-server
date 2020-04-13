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
 * @file redis.c
 * @brief conf functions for interacting with Redis cluster via Hiredis.
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Network RADIUS (legal@networkradius.com)
 * @copyright 2015 The FreeRADIUS server project
 *
 * Overview
 * ========
 *
 * Read and understand this http://redis.io/topics/cluster-spec first, else the text below
 * will not be useful.
 *
 * Using the cluster's public API
 * ------------------------------
 *
 * The two functions used at runtime to issue commands are #fr_redis_cluster_state_init
 * and #fr_redis_cluster_state_next.
 *
 * #fr_redis_cluster_state_init initialises the structure we use to track which node
 * we're communicating with, and uses a key (string) to determine which node we should
 * try and contact first.
 *
 * #fr_redis_cluster_state_next examines the result of the last command, and either
 * gets a new connection, or errors out.
 *
 * In both cases the connection should not be released by the caller, only by
 * #fr_redis_cluster_state_next.
 *
 * Below is the sequence of calls required to use the cluster:
 *
 *     1. During initialization allocate a cluster configuration structure with
 *	  #fr_redis_cluster_alloc.  This holds the cluster configuration and state.
 *     2. Declare a #fr_redis_cluster_state_t in the function that needs to issue
 *        commands against the cluster.
 *     3. Call #fr_redis_cluster_state_init with relevant arguments including a pointer
 *        to the #fr_redis_cluster_state_t struct, and a key/key_len used for initial
 *        lookup.  For most commands the key is the value of the second argument.
 *        #fr_redis_cluster_state_init will then and reserve/pass back a connection for
 *        the pool associated with the node associated with the key.
 *     4. Use the connection that was passed back, to issue a Redis command against.
 *     5. Use #fr_redis_command_status to translate the result of the command into
 *        a #fr_redis_rcode_t value.
 *     6. Call #fr_redis_cluster_state_next with relevant arguments including a pointer
 *        to the #fr_redis_cluster_state_t struct and the #fr_redis_rcode_t value for the
 *        last command.
 *     7. If #fr_redis_cluster_state_next returns 0, repeat steps 4-7.  Otherwise
 *        stop and analyse the return value.
 *
 * See #fr_redis_cluster_state_init for example code.
 *
 * Structures
 * ----------
 *
 *   This code maintains a series structures for efficient lookup and lockless operations.
 *
 *   The important ones are:
 *     - An array of #fr_redis_cluster_node_t.  These are pre-allocated on startup and are
 *       never added to, or removed from.
 *     - An #fr_fifo_t.  This contains the queue of nodes that may be re-used.
 *     - An #rbtree_t.  This contains a tree of nodes which are active.  The tree is built on IP
 *       address and port.
 *
 *   Each #fr_redis_cluster_node_t contains a master ID, and an array of slave IDs.  The IDs are array
 *   indexes in the fr_redis_cluster_t.node array.  We use 8bit unsigned integers instead of
 *   pointers to save space.  Using pointers, the node[] array would need 784K, using IDs
 *   it uses 112K.  Still not light on memory, but a bit more acceptable.
 *   Currently the key_slot array is shadowed by key_slot_pending, used to stage new key_slot
 *   mappings.  This doubles the memory used.  We may want to consider allocating key_slot_pending
 *   only during remappings and freeing it after.
 *
 * Mapping/Remapping the cluster
 * -----------------------------
 *
 *   On startup, and during cluster operation, a remap may be performed.  A remap involves
 *   the following steps:
 *
 *     1. Executing the Redis 'cluster slots' command.
 *     2. Validating the result of this command.  We need to do extensive validation to
 *        avoid SEGV on invalid data, due to the way libhiredis presents the result.
 *     3. Determining the intersection between nodes described in the result, and those already
 *        in our #rbtree_t.
 *     4. Connecting to nodes that were in the result, but not in the tree.
 *        Note: If we can't connect to any of the masters, we count the map as invalid, roll
 *        back any newly connected nodes, and error out. Slave failure is OK.
 *     5. Mapping keyslot ranges to nodes in the key_slot_pending array.
 *     6. Verifying there are no holes in the ranges (if there are, we roll back and error out).
 *     7. Applying the new keyslot ranges.
 *     8. Removing nodes no longer used by the key slots, and adding them back to the free
 *        nodes queue.
 *
 *   #cluster_map_get and #cluster_map_apply, perform the operations described
 *   above. The get function, issues the 'cluster slots' command and performs validation, the
 *   apply function processes and applys the map.
 *
 *   Failing to apply a map is not a fatal error at runtime, and is only fatal on startup if
 *   pool.start > 0.
 *
 *   The cluster client can continue to operate, albeit inefficiently, with a stale cluster map
 *   by following '-ASK' and '-MOVE' redirects.
 *
 *   Remaps are limited to one per second.  If any operation sets the remap_needed flag, or
 *   attempts a remap directly, the remap may be skipped if one occurred recently.
 *
 *
 * Processing '-ASK' and '-MOVE' redirects
 * ---------------------------------------
 *
 *   The code treats '-ASK' (temporary redirect) and '-MOVE' (permanent redirect) responses
 *   similarly.  If the node is known, then a connection is reserved from its pool, if the node
 *   is not known, a new pool is established, and a connection reserved.
 *
 *   The difference between '-ASK' and '-MOVE' is that '-MOVE' attempts a cluster remap before
 *   following the redirect.
 *
 *   The data from '-MOVE' responses, is not used to alter the cluster map.  That is only done
 *   on successful remap.
 *
 *
 * Processing '-TRYAGAIN'
 * ----------------------
 *
 *   If the cluster is in a state of flux, a node may return '-TRYAGAIN' to indicated that we
 *   should attempt the operation again.  The cluster spec says we should attempt the operation
 *   after some time.  This time is configurable.
 *
 */

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/cf_parse.h>

#include <freeradius-devel/util/fifo.h>
#include <freeradius-devel/util/misc.h>
#include <freeradius-devel/util/rand.h>

#include "base.h"
#include "cluster.h"
#include "crc16.h"

#define KEY_SLOTS		16384			//!< Maximum number of keyslots (should not change).

#define MAX_SLAVES		5			//!< Maximum number of slaves associated
							//!< with a keyslot.

/*
 *	Periods and weights for live node selection
 */
#define CLOSED_PERIOD		10000			//!< How recently must the closed have
							//!< occurred for us to care.

#define CLOSED_WEIGHT		1			//!< What weight to give to nodes that
							//!< had a connection closed recently.

#define FAILED_PERIOD		10000			//!< How recently must the spawn failure
							//!< occurred for us to care.

#define FAILED_WEIGHT		1			//!< What weight to give to nodes that
							//!< had a spawn failure recently.

#define RELEASED_PERIOD		10000			//!< Period after which we don't care
							//!< about when the last connection was
							//!< released.

#define RELEASED_MIN_WEIGHT	1000			//!< Minimum weight to assign to node.

/** Live nodes data, used to perform weighted random selection of alternative nodes
 */
typedef struct {
	struct {
		uint8_t					id;		//!< Node ID.
		fr_pool_state_t const	*pool_state;	//!< Connection pool stats.
		unsigned int				cumulative;	//!< Cumulative weight.
	} node[UINT8_MAX - 1];				//!< Array of live node IDs (and weights).
	uint8_t next;					//!< Next index in live.
	uint8_t skip;
} cluster_nodes_live_t;

/** A Redis cluster node
 *
 * Passed as opaque data to pools which open connection to nodes.
 */
struct fr_redis_cluster_node_s {
	char			name[INET6_ADDRSTRLEN];	//!< Buffer to hold IP string.
							//!< text for debug messages.
	uint8_t			id;			//!< Node ID (index in node array).

	fr_socket_addr_t	addr;			//!< Current node address.
	fr_socket_addr_t	pending_addr;		//!< New node address to be applied when the pool
							//!< is reconnected.

	fr_redis_cluster_t	*cluster;		//!< Commmon configuration (database number,
							//!< password, etc..).
	fr_pool_t		*pool;			//!< Pool associated with this node.
	CONF_SECTION		*pool_cs;		//!< Pool configuration section associated with node.

	bool			is_active;		//!< Whether this node is in the active node set.
	bool			is_master;		//!< Whether this node is a master.
							//!< This is needed for commands like 'KEYS', which
							//!< we need to issue to every master in the cluster.
};

/** Indexes in the fr_redis_cluster_node_t array for a single key slot
 *
 * When dealing with 16K entries, space is a concern. It's significantly
 * more memory efficient to use 8bit indexes than 64bit pointers for each
 * of the key slot to node mappings.
 */
struct fr_redis_cluster_key_slot_s {
	uint8_t			slave[MAX_SLAVES];	//!< R/O node (slave) for this key slot.
	uint8_t			slave_num;		//!< Number of slaves associated with this key slot.
	uint8_t			master;			//!< R/W node (master) for this key slot.
};

/** A redis cluster
 *
 * Holds all the structures and collections of nodes, to represent a Redis cluster.
 */
struct fr_redis_cluster {
	char const		*log_prefix;		//!< What to prepend to log messages.
	char const		*trigger_prefix;	//!< Trigger path.
	VALUE_PAIR		*trigger_args;		//!< Arguments to pass to triggers.
	bool			triggers_enabled;	//!< Whether triggers are enabled.

	bool			remapping;		//!< True when cluster is being remapped.
	bool			remap_needed;		//!< Set true if at least one cluster node is definitely
							//!< unreachable. Set false on successful remap.
	time_t			last_updated;		//!< Last time the cluster mappings were updated.
	CONF_SECTION		*module;		//!< Module configuration.

	fr_redis_conf_t		*conf;			//!< Base configuration data such as the database number
							//!< and passwords.

	fr_redis_cluster_node_t		*node;			//!< Structure containing a node id, its address and
							//!< a pool of its connections.

	fr_fifo_t		*free_nodes;		//!< Queue of free nodes (or nodes waiting to be reused).
	rbtree_t		*used_nodes;		//!< Tree of used nodes.

	fr_redis_cluster_key_slot_t	key_slot[KEY_SLOTS];		//!< Lookup table of slots to pools.
	fr_redis_cluster_key_slot_t	key_slot_pending[KEY_SLOTS];	//!< Pending key slot table.

	pthread_mutex_t		mutex;			//!< Mutex to synchronise cluster operations.
};

fr_table_num_sorted_t const fr_redis_cluster_rcodes_table[] = {
	{ "bad-input",		FR_REDIS_CLUSTER_RCODE_BAD_INPUT	},
	{ "failed",		FR_REDIS_CLUSTER_RCODE_FAILED		},
	{ "ignored",		FR_REDIS_CLUSTER_RCODE_IGNORED		},
	{ "no-connection",	FR_REDIS_CLUSTER_RCODE_NO_CONNECTION	},
	{ "success",		FR_REDIS_CLUSTER_RCODE_SUCCESS		}
};
size_t fr_redis_cluster_rcodes_table_len = NUM_ELEMENTS(fr_redis_cluster_rcodes_table);

/** Resolve key to key slot
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

/** Compare two redis nodes to check equality
 *
 * @param[in] a first node.
 * @param[in] b second node.
 * @return
 *	- 0 if nodes are equal.
 *	- +1 if nodes are unequal.
 *	- -1 if nodes are unequal.
 */
static int _cluster_node_cmp(void const *a, void const *b)
{
	fr_redis_cluster_node_t const *my_a = a, *my_b = b;
	int ret;

	ret = fr_ipaddr_cmp(&my_a->addr.ipaddr, &my_b->addr.ipaddr);
	if (ret != 0) return ret;

	return my_a->addr.port - my_b->addr.port;
}

/** Reconnect callback to apply new pool config
 *
 * @param[in] pool to apply new configuration to.
 * @param[in] opaque data passed to the connection pool.
 */
static void _cluster_node_conf_apply(fr_pool_t *pool, void *opaque)
{
	VALUE_PAIR	*args;
	fr_redis_cluster_node_t	*node = opaque;

	node->addr = node->pending_addr;

	if (node->cluster->triggers_enabled) {
		args = trigger_args_afrom_server(pool, node->name, node->addr.port);
		if (!args) return;

		if (node->cluster->trigger_args) MEM(fr_pair_list_copy(node->cluster, &args,
								      node->cluster->trigger_args) >= 0);

		fr_pool_enable_triggers(pool, node->cluster->trigger_prefix, args);

		fr_pair_list_free(&args);
	}
}

/** Establish a connection to a cluster node
 *
 * @note Must be called with the cluster mutex locked.
 * @note Configuration to use for the connection must be set in node->pending_addr, not node->cluster->conf.
 *
 * @param[in] cluster to search in.
 * @param[in] node config.
 * @return
 *	 - FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	 - FR_REDIS_CLUSTER_RCODE_FAILED if the operation failed.
 */
static fr_redis_cluster_rcode_t cluster_node_connect(fr_redis_cluster_t *cluster, fr_redis_cluster_node_t *node)
{
	char const *p;

	fr_assert(node->pending_addr.ipaddr.af);

	/*
	 *	Write out the IP address and Port in string form
	 */
	p = inet_ntop(node->pending_addr.ipaddr.af, &node->pending_addr.ipaddr.addr,
		      node->name, sizeof(node->name));
	if (!fr_cond_assert(p)) return FR_REDIS_CLUSTER_RCODE_FAILED;

	/*
	 *	Node has never been used before, needs a pool allocated for it.
	 */
	if (!node->pool) {
		char		buffer[256];
		VALUE_PAIR	*args;
		CONF_SECTION	*pool;

		snprintf(buffer, sizeof(buffer), "%s [%i]", cluster->log_prefix, node->id);

		pool = cf_section_find(cluster->module, "pool", NULL);
		/*
		 *	Dup so we can re-parse, and have unique CONF_DATA
		 */
		node->pool_cs = cf_section_dup(cluster, NULL, pool, "pool", NULL, true);
		node->addr = node->pending_addr;
		node->pool = fr_pool_init(cluster, node->pool_cs, node,
					  fr_redis_cluster_conn_create, NULL, buffer);
		if (!node->pool) {
		error:
			TALLOC_FREE(node->pool_cs);
			TALLOC_FREE(node->pool);
			return FR_REDIS_CLUSTER_RCODE_FAILED;
		}
		fr_pool_reconnect_func(node->pool, _cluster_node_conf_apply);

		if (trigger_enabled() && cluster->triggers_enabled) {
			args = trigger_args_afrom_server(node->pool, node->name, node->addr.port);
			if (!args) goto error;

			if (cluster->trigger_args) MEM(fr_pair_list_copy(cluster, &args, cluster->trigger_args) >= 0);

			fr_pool_enable_triggers(node->pool, node->cluster->trigger_prefix, args);

			fr_pair_list_free(&args);
		}

		if (fr_pool_start(node->pool) < 0) goto error;

		return FR_REDIS_CLUSTER_RCODE_SUCCESS;
	}

	/*
	 *	Apply the new config to the possibly live pool
	 */
	if (fr_pool_reconnect(node->pool, NULL) < 0) goto error;

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Parse a -MOVED or -ASK redirect
 *
 * Converts the body of the -MOVED or -ASK error into an IPv4/6 address and port.
 *
 * @param[out] key_slot value extracted from redirect string (may be NULL).
 * @param[out] node_addr Redis node ipaddr and port extracted from redirect string.
 * @param[in] redirect to process.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT if the server returned an invalid redirect.
 */
static fr_redis_cluster_rcode_t cluster_node_conf_from_redirect(uint16_t *key_slot, fr_socket_addr_t *node_addr,
						       redisReply *redirect)
{
	char		*p, *q;
	unsigned long	key;
	uint16_t	port;
	fr_ipaddr_t	ipaddr;

	if (!redirect || (redirect->type != REDIS_REPLY_ERROR)) {
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	p = redirect->str;
	if (strncmp(REDIS_ERROR_MOVED_STR, redirect->str, sizeof(REDIS_ERROR_MOVED_STR) - 1) == 0) {
		q = p + sizeof(REDIS_ERROR_MOVED_STR);	/* not a typo, skip space too */
	} else if (strncmp(REDIS_ERROR_ASK_STR, redirect->str, sizeof(REDIS_ERROR_ASK_STR) - 1) == 0) {
		q = p + sizeof(REDIS_ERROR_ASK_STR);	/* not a typo, skip space too */
	} else {
		fr_strerror_printf("No '-MOVED' or '-ASK' log_prefix");
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}
	if ((size_t)(q - p) >= (size_t)redirect->len) {
		fr_strerror_printf("Truncated");
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}
	p = q;
	key = strtoul(p, &q, 10);
	if (key > KEY_SLOTS) {
		fr_strerror_printf("Key %lu outside of redis slot range", key);
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}
	p = q;

	if (*p != ' ') {
		fr_strerror_printf("Missing key/host separator");
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}
	p++;			/* Skip the ' ' */

	if (fr_inet_pton_port(&ipaddr, &port, p, redirect->len - (p - redirect->str), AF_UNSPEC, false, true) < 0) {
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}
	fr_assert(ipaddr.af);

	if (key_slot) *key_slot = key;
	if (node_addr) {
		node_addr->ipaddr = ipaddr;
		node_addr->port = port;
	}

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Apply a cluster map received from a cluster node
 *
 * @note Errors may be retrieved with fr_strerror().
 * @note Must be called with the cluster mutex held.
 *
 * Key slot range structure
 @verbatim
   [0] -> key slot range 0
       [0] -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master 0 ip (string)
           [1] -> master 0 port (number)
       [3..n] -> slave_node(s)
   [1] -> key slot range 1)
       [0]  -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master 1 ip (string)
           [1] -> master 1 port (number)
       [3..n] -> slave_node(s)
   [n] -> key slot range n
       [0] -> key_slot_start
       [1] -> key_slot_end
       [2] -> master_node
           [0] -> master n ip (string)
           [1] -> master n port (number)
       [3..n] -> slave_node(s)
 @endverbatim
 *
 * @param[in,out] cluster to apply map to.
 * @param[in] reply from #cluster_map_get.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_FAILED on failure.
  *	- FR_REDIS_CLUSTER_RCODE_NO_CONNECTION connection failure.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT if the map didn't provide nodes for all keyslots.
 */
static fr_redis_cluster_rcode_t cluster_map_apply(fr_redis_cluster_t *cluster, redisReply *reply)
{
	size_t		i;
	uint8_t		r = 0;

	fr_redis_cluster_rcode_t	rcode;

	uint8_t		rollback[UINT8_MAX];		// Set of nodes to re-add to the queue on failure.
	bool		active[UINT8_MAX];		// Set of nodes active in the new cluster map.
	bool		master[UINT8_MAX];		// Master nodes.
#ifndef NDEBUG
#  define SET_ADDR(_addr, _map) \
do { \
	int _ret; \
	_ret = fr_inet_pton(&_addr.ipaddr, _map->element[0]->str, _map->element[0]->len, AF_UNSPEC, false, true);\
	fr_assert(_ret == 0);\
	_addr.port = _map->element[1]->integer; \
} while (0)
#else
#  define SET_ADDR(_addr, _map) \
do { \
	fr_inet_pton(&_addr.ipaddr, _map->element[0]->str, _map->element[0]->len, AF_UNSPEC, false, true);\
	_addr.port = _map->element[1]->integer; \
} while (0)
#endif

#define SET_INACTIVE(_node) \
do { \
	(_node)->is_active = false; \
	(_node)->is_master = false; \
	rbtree_deletebydata(cluster->used_nodes, _node); \
	fr_fifo_push(cluster->free_nodes, _node); \
} while (0)

#define SET_ACTIVE(_node) \
do { \
	(_node)->is_active = true; \
	rbtree_insert(cluster->used_nodes, _node); \
	fr_fifo_pop(cluster->free_nodes); \
	active[(_node)->id] = true; \
	rollback[r++] = (_node)->id; \
} while (0)

	fr_assert(reply->type == REDIS_REPLY_ARRAY);

	memset(&rollback, 0, sizeof(rollback));
	memset(active, 0, sizeof(active));
	memset(master, 0, sizeof(master));

	cluster->remapping = true;

	/*
	 *	Must be cleared with the mutex held
	 */
	memset(&cluster->key_slot_pending, 0, sizeof(cluster->key_slot_pending));

	/*
	 *	Insert new nodes and markup the keyslot indexes
	 *	in our temporary keyslot_array.
	 *
	 *	A map consists of an array with the following indexes:
	 *	  [0]    -> key_slot_start
	 *	  [1]    -> key_slot_end
	 *	  [2]    -> master_node
	 *	  [3..n] -> slave_node(s)
	 */
	for (i = 0; i < reply->elements; i++) {
		size_t			j;
		long long int		k;
		int			slaves = 0;
		fr_redis_cluster_node_t		*found, *spare;
		fr_redis_cluster_node_t		find;
		fr_redis_cluster_key_slot_t	tmpl_slot;
		redisReply		*map = reply->element[i];

		memset(&tmpl_slot, 0, sizeof(tmpl_slot));

		SET_ADDR(find.addr, map->element[2]);
		found = rbtree_finddata(cluster->used_nodes, &find);
		if (found) {
			active[found->id] = true;
			goto reuse_master_node;
		}

		/*
		 *	Process the master
		 *
		 *      A master node consists of any array with the following indexes:
		 *	  [0] -> node ip (as string)
		 *	  [1] -> node port
		 */
		spare = fr_fifo_peek(cluster->free_nodes);
		if (!spare) {
		out_of_nodes:
			fr_strerror_printf("Reached maximum connected nodes");
			rcode = FR_REDIS_CLUSTER_RCODE_FAILED;
		error:
			cluster->remapping = false;
			cluster->last_updated = time(NULL);
			/* Re-insert new nodes back into the free_nodes queue */
			for (i = 0; i < r; i++) SET_INACTIVE(&cluster->node[rollback[i]]);
			return rcode;
		}

		spare->pending_addr = find.addr;
		rcode = cluster_node_connect(cluster, spare);
		if (rcode < 0) goto error;

		/*
		 *	Check to see if the node we just configured
		 *	already exists in the tree.  If it does we
		 *	use that, else we add it to the array of
		 *	nodes to rollback on failure.
		 */
		SET_ACTIVE(spare);
		found = spare;

	reuse_master_node:
		tmpl_slot.master = found->id;
		master[found->id] = true;	/* Mark this node as a master */

		/*
		 *	Process the slaves
		 *
		 *      A slave node consists of any array with the following indexes:
		 *	  [0] -> node ip (as string)
		 *	  [1] -> node port
		 */
		for (j = 3; (j < map->elements); j++) {
			SET_ADDR(find.addr, map->element[j]);
			found = rbtree_finddata(cluster->used_nodes, &find);
			if (found) {
				active[found->id] = true;
				goto next;
			}

			spare = fr_fifo_peek(cluster->free_nodes);
			if (!spare) goto out_of_nodes;

			spare->pending_addr = find.addr;
			if (cluster_node_connect(cluster, spare) < 0) continue;	/* Slave failure is non-fatal */

			SET_ACTIVE(spare);
			found = spare;

		next:
			tmpl_slot.slave[slaves++] = found->id;

			/* Hit the maximum number of slaves we allow */
			if (slaves >= MAX_SLAVES) break;
		}
		tmpl_slot.slave_num = slaves;

		/*
		 *	Copy our tmpl key slot to each of the key slots
		 *	specified by the range for this map.
		 */
		for (k = map->element[0]->integer; k <= map->element[1]->integer; k++) {
			memcpy(&cluster->key_slot_pending[k], &tmpl_slot,
			       sizeof(*(cluster->key_slot_pending)));
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
		if (cluster->key_slot_pending[i].master == 0) {
			fr_strerror_printf("Cluster is misconfigured, no node assigned for key %zu", i);
			rcode = FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
			goto error;
		}
	}

	/*
	 *	We have connections/pools for all the nodes in
	 *	the new map, apply it to the live cluster.
	 *
	 *	Other workers may be using the key slot table,
	 *	but that's ok. Nodes and pools are never freed,
	 *	so the worst that will happen, is they'll hit
	 *	the wrong node for the key, and get redirected.
	 */
	memcpy(&cluster->key_slot, &cluster->key_slot_pending, sizeof(cluster->key_slot));

	/*
	 *	Anything not in the active set of nodes gets
	 *	added back into the queue, to be re-used.
	 *
	 *	We start at 1, as node 0 is reserved.
	 */
	for (i = 1; i < cluster->conf->max_nodes; i++) {
#ifndef NDEBUG
		fr_redis_cluster_node_t *found;

		if (cluster->node[i].is_active) {
			/* Sanity check for duplicates that are active */
			found = rbtree_finddata(cluster->used_nodes, &cluster->node[i]);
			fr_assert(found);
			fr_assert(found->is_active);
			fr_assert(found->id == i);
		}
#endif

		if (!active[i] && cluster->node[i].is_active) {
			SET_INACTIVE(&cluster->node[i]);	/* Sets is_master = false */

		/*
		 *	Only change the masters once we've successfully
		 *	remapped the cluster.
		 */
		} else if (master[i]) {
			cluster->node[i].is_master = true;
		}
	}

	cluster->remapping = false;
	cluster->last_updated = time(NULL);

	/*
	 *	Sanity checks
	 */
	fr_assert(((talloc_array_length(cluster->node) - 1) - rbtree_num_elements(cluster->used_nodes)) ==
		   fr_fifo_num_elements(cluster->free_nodes));

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Validate a cluster map node entry
 *
 * @note Errors may be retrieved with fr_strerror().
 * @note In a separate function, as it's called for both master and slave nodes.
 *
 * @param[in] node we're validating.
 * @param[in] map_idx we're processing.
 * @param[in] node_idx we're processing.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static int cluster_map_node_validate(redisReply *node, int map_idx, int node_idx)
{
	fr_ipaddr_t ipaddr;

	if (node->type != REDIS_REPLY_ARRAY) {
		fr_strerror_printf("Cluster map %i node %i is wrong type, expected array got %s",
				   map_idx, node_idx,
				   fr_table_str_by_value(redis_reply_types, node->element[1]->type, "<UNKNOWN>"));
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	/*
	 *  As per the redis docs: https://redis.io/commands/cluster-slots
	 *
	 *  Newer versions of Redis Cluster will output, for each Redis instance,
	 *  not just the IP and port, but also the node ID as third element of the
	 *  array. In future versions there could be more elements describing the
	 *  node better. In general a client implementation should just rely on
	 *  the fact that certain parameters are at fixed positions as specified,
	 *  but more parameters may follow and should be ignored.
	 *  Similarly a client library should try if possible to cope with the fact
	 *  that older versions may just have the IP and port parameter.
	 */
	if (node->elements < 2) {
		fr_strerror_printf("Cluster map %i node %i has incorrect number of elements, expected at least "
				   "2 got %zu", map_idx, node_idx, node->elements);
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	if (node->element[0]->type != REDIS_REPLY_STRING) {
		fr_strerror_printf("Cluster map %i node %i ip address is wrong type, expected string got %s",
				   map_idx, node_idx,
				   fr_table_str_by_value(redis_reply_types, node->element[0]->type, "<UNKNOWN>"));
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	if (fr_inet_pton(&ipaddr, node->element[0]->str, node->element[0]->len, AF_UNSPEC, false, true) < 0) {
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	if (node->element[1]->type != REDIS_REPLY_INTEGER) {
		fr_strerror_printf("Cluster map %i node %i port is wrong type, expected integer got %s",
				   map_idx, node_idx,
				   fr_table_str_by_value(redis_reply_types, node->element[1]->type, "<UNKNOWN>"));
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	if (node->element[1]->integer < 0) {
		fr_strerror_printf("Cluster map %i node %i port is too low, expected >= 0 got %lli",
				   map_idx, node_idx, node->element[1]->integer);
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	if (node->element[1]->integer > UINT16_MAX) {
		fr_strerror_printf("Cluster map %i node %i port is too high, expected <= " STRINGIFY(UINT16_MAX)" "
				   "got %lli", map_idx, node_idx, node->element[1]->integer);
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Learn a new cluster layout by querying the node that issued the -MOVE
 *
 * Also validates the response from the Redis cluster, so we can be sure that
 * it's well formed, before doing more expensive operations.
 *
 * @note Errors may be retrieved with fr_strerror().
 *
 * @param[out] out Where to write cluster map.
 * @param[in] conn to use for learning the new cluster map.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_IGNORED if 'cluster slots' returned an error (indicating clustering not supported).
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_FAILED if issuing the command resulted in an error.
 *	- FR_REDIS_CLUSTER_RCODE_NO_CONNECTION connection failure.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static fr_redis_cluster_rcode_t cluster_map_get(redisReply **out, fr_redis_conn_t *conn)
{
	redisReply	*reply;
	size_t		i = 0;

	*out = NULL;

	reply = redisCommand(conn->handle, "cluster slots");
	switch (fr_redis_command_status(conn, reply)) {
	case REDIS_RCODE_RECONNECT:
		fr_redis_reply_free(&reply);
		fr_strerror_printf("No connections available");
		return FR_REDIS_CLUSTER_RCODE_NO_CONNECTION;

	case REDIS_RCODE_ERROR:
	default:
		if (reply && reply->type == REDIS_REPLY_ERROR) {
			fr_strerror_printf("%.*s", (int)reply->len, reply->str);
			fr_redis_reply_free(&reply);
			return FR_REDIS_CLUSTER_RCODE_IGNORED;
		}
		fr_strerror_printf("Unknown client error");
		return FR_REDIS_CLUSTER_RCODE_FAILED;

	case REDIS_RCODE_SUCCESS:
		break;
	}

	if (reply->type != REDIS_REPLY_ARRAY) {
		fr_strerror_printf("Bad response to \"cluster slots\" command, expected array got %s",
				   fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	/*
	 *	Clustering configured but no slots set
	 */
	if (reply->elements == 0) {
		fr_strerror_printf("Empty response to \"cluster slots\" command (zero length array)");
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	/*
	 *	Validate the complete map set before returning.
	 */
	for (i = 0; i < reply->elements; i++) {
		size_t		j;
		redisReply	*map;

		map = reply->element[i];
		if (map->type != REDIS_REPLY_ARRAY) {
			fr_strerror_printf("Cluster map %zu is wrong type, expected array got %s",
				   	   i, fr_table_str_by_value(redis_reply_types, map->type, "<UNKNOWN>"));
		error:
			fr_redis_reply_free(&reply);
			return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
		}

		if (map->elements < 3) {
			fr_strerror_printf("Cluster map %zu has too few elements, expected at least 3, got %zu",
					   i, map->elements);
			goto error;
		}

		/*
		 *	Key slot start
		 */
		if (map->element[0]->type != REDIS_REPLY_INTEGER) {
			fr_strerror_printf("Cluster map %zu key slot start is wrong type, expected integer got %s",
					   i, fr_table_str_by_value(redis_reply_types, map->element[0]->type, "<UNKNOWN>"));
			goto error;
		}

		if (map->element[0]->integer < 0) {
			fr_strerror_printf("Cluster map %zu key slot start is too low, expected >= 0 got %lli",
					   i, map->element[0]->integer);
			goto error;
		}

		if (map->element[0]->integer > KEY_SLOTS) {
			fr_strerror_printf("Cluster map %zu key slot start is too high, expected <= "
					   STRINGIFY(KEY_SLOTS) " got %lli", i, map->element[0]->integer);
			goto error;
		}

		/*
		 *	Key slot end
		 */
		if (map->element[1]->type != REDIS_REPLY_INTEGER) {
			fr_strerror_printf("Cluster map %zu key slot end is wrong type, expected integer got %s",
					   i, fr_table_str_by_value(redis_reply_types, map->element[1]->type, "<UNKNOWN>"));
			goto error;
		}

		if (map->element[1]->integer < 0) {
			fr_strerror_printf("Cluster map %zu key slot end is too low, expected >= 0 got %lli",
					   i, map->element[1]->integer);
			goto error;
		}

		if (map->element[1]->integer > KEY_SLOTS) {
			fr_strerror_printf("Cluster map %zu key slot end is too high, expected <= "
					   STRINGIFY(KEY_SLOTS) " got %lli", i, map->element[1]->integer);
			goto error;
		}

		if (map->element[1]->integer < map->element[0]->integer) {
			fr_strerror_printf("Cluster map %zu key slot start/end out of order.  "
					   "Start was %lli, end was %lli", i, map->element[0]->integer,
					   map->element[1]->integer);
			goto error;
		}

		/*
		 *	Master node
		 */
		if (cluster_map_node_validate(map->element[2], i, 0) < 0) goto error;

		/*
		 *	Slave nodes
		 */
		for (j = 3; j < map->elements; j++) {
			if (cluster_map_node_validate(map->element[j], i, j - 2) < 0) goto error;
		}
	}
	*out = reply;

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Perform a runtime remap of the cluster
 *
 * @note Errors may be retrieved with fr_strerror().
 * @note Must be called with the cluster mutex free.
 *
 * @param[in] request The current request.
 * @param[in,out] cluster to remap.
 * @param[in] conn to use to query the cluster.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_IGNORED if 'cluster slots' returned an error (indicating clustering not supported).
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_FAILED if issuing the 'cluster slots' command resulted in a protocol error.
 *	- FR_REDIS_CLUSTER_RCODE_NO_CONNECTION connection failure.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT on validation failure (bad data returned from Redis).
 */
fr_redis_cluster_rcode_t fr_redis_cluster_remap(REQUEST *request, fr_redis_cluster_t *cluster, fr_redis_conn_t *conn)
{
	time_t		now;
	redisReply	*map;
	fr_redis_cluster_rcode_t	ret;
	size_t		i, j;

	/*
	 *	If the cluster was remapped very recently, or is being
	 *	remapped it's unlikely that it needs remapping again.
	 */
	if (cluster->remapping) {
	in_progress:
		RDEBUG2("Cluster remapping in progress, ignoring remap request");
		return FR_REDIS_CLUSTER_RCODE_IGNORED;
	}

	now = time(NULL);
	if (now == cluster->last_updated) {
	too_soon:
		RWARN("Cluster was updated less than a second ago, ignoring remap request");
		return FR_REDIS_CLUSTER_RCODE_IGNORED;
	}

	RINFO("Initiating cluster remap");

	/*
	 *	Get new cluster information
	 */
	ret = cluster_map_get(&map, conn);
	switch (ret) {
	case FR_REDIS_CLUSTER_RCODE_BAD_INPUT:		/* Validation error */
	case FR_REDIS_CLUSTER_RCODE_NO_CONNECTION:		/* Connection error */
	case FR_REDIS_CLUSTER_RCODE_FAILED:			/* Error issuing command */
		return ret;

	case FR_REDIS_CLUSTER_RCODE_IGNORED:		/* Clustering not enabled, or not supported */
		cluster->remap_needed = false;
		return FR_REDIS_CLUSTER_RCODE_IGNORED;

	case FR_REDIS_CLUSTER_RCODE_SUCCESS:		/* Success */
		break;
	}

	/*
	 *	Print the mapping we received
	 */
	RINFO("Cluster map consists of %zu key ranges", map->elements);
	for (i = 0; i < map->elements; i++) {
		redisReply *map_node = map->element[i];

		RINFO("%zu - keys %lli-%lli", i,
		      map_node->element[0]->integer,
		      map_node->element[1]->integer);

		RINDENT();
		RINFO("master: %s:%lli",
		      map_node->element[2]->element[0]->str,
		      map_node->element[2]->element[1]->integer);
		for (j = 3; j < map_node->elements; j++) {
			RINFO("slave%zu: %s:%lli", j - 3,
			      map_node->element[j]->element[0]->str,
			      map_node->element[j]->element[1]->integer);
		}
		REXDENT();
	}

	/*
	 *	Check again that the cluster isn't being
	 *	remapped, or was remapped too recently,
	 *	now we hold the mutex and the state of
	 *	those variables is synchronized.
	 */
	pthread_mutex_lock(&cluster->mutex);
	if (cluster->remapping) {
		pthread_mutex_unlock(&cluster->mutex);
		fr_redis_reply_free(&map);	/* Free the map */
		goto in_progress;
	}
	if (now == cluster->last_updated) {
		pthread_mutex_unlock(&cluster->mutex);
		fr_redis_reply_free(&map);	/* Free the map */
		goto too_soon;
	}
	ret = cluster_map_apply(cluster, map);
	if (ret == FR_REDIS_CLUSTER_RCODE_SUCCESS) cluster->remap_needed = false;	/* Change on successful remap */
	pthread_mutex_unlock(&cluster->mutex);

	fr_redis_reply_free(&map);	/* Free the map */
	if (ret < 0) return FR_REDIS_CLUSTER_RCODE_FAILED;

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Retrieve or associate a node with the server indicated in the redirect
 *
 * @note Errors may be retrieved with fr_strerror().
 *
 * @param[out] out Where to write the node representing the redirect server.
 * @param[in] cluster to draw node from.
 * @param[in] reply Redis reply containing the redirect information.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_FAILED no more nodes available.
 *	- FR_REDIS_CLUSTER_RCODE_NO_CONNECTION connection failure.
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static fr_redis_cluster_rcode_t cluster_redirect(fr_redis_cluster_node_t **out, fr_redis_cluster_t *cluster, redisReply *reply)
{
	fr_redis_cluster_node_t		find, *found, *spare;
	fr_redis_conn_t		*rconn;

	uint16_t		key;

	memset(&find, 0, sizeof(find));

	*out = NULL;

	if (cluster_node_conf_from_redirect(&key, &find.addr, reply) < 0) return FR_REDIS_CLUSTER_RCODE_FAILED;

	pthread_mutex_lock(&cluster->mutex);
	/*
	 *	If we have already have a pool for the
	 *	host we were redirected to, use that.
	 */
	found = rbtree_finddata(cluster->used_nodes, &find);
	if (found) {
		/* We have the new pool, don't need to hold the lock */
		pthread_mutex_unlock(&cluster->mutex);
		*out = found;
		return FR_REDIS_CLUSTER_RCODE_SUCCESS;
	}

	/*
	 *	Otherwise grab a free node and try and connect
	 *	it to the server we were redirected to.
	 */
	spare = fr_fifo_peek(cluster->free_nodes);
	if (!spare) {
		fr_strerror_printf("Reached maximum connected nodes");
		pthread_mutex_unlock(&cluster->mutex);
		return FR_REDIS_CLUSTER_RCODE_FAILED;
	}
	spare->pending_addr = find.addr;	/* Set the config to be applied */
	if (cluster_node_connect(cluster, spare) < 0) {
		pthread_mutex_unlock(&cluster->mutex);
		return FR_REDIS_CLUSTER_RCODE_NO_CONNECTION;
	}
	rbtree_insert(cluster->used_nodes, spare);
	fr_fifo_pop(cluster->free_nodes);
	found = spare;

	/* We have the new pool, don't need to hold the lock */
	pthread_mutex_unlock(&cluster->mutex);

	/*
	 *	Determine if we can establish a connection to
	 *	the new pool, to check if it's viable.
	 */
	rconn = fr_pool_connection_get(found->pool, NULL);
	if (!rconn) {
		/*
		 *	To prevent repeated misconfigurations
		 *	using all free nodes, add the node
		 *	back to the spare queue if this
		 *	was the first connection attempt and
		 *	it failed.
		 */
		pthread_mutex_lock(&cluster->mutex);
		fr_fifo_push(cluster->free_nodes, spare);
		pthread_mutex_unlock(&cluster->mutex);

		fr_strerror_printf("No connections available");
		return FR_REDIS_CLUSTER_RCODE_NO_CONNECTION;
	}
	fr_pool_connection_release(found->pool, NULL, rconn);
	*out = found;

	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Walk all used pools adding them to the live node list
 *
 * @param[in] uctx	Where to write the node we found.
 * @param[in] data	node to check.
 * @return
 *	- 0 continue walking.
 *	- -1 found suitable node.
 */
static int _cluster_pool_walk(void *data, void *uctx)
{
	cluster_nodes_live_t	*live = uctx;
	fr_redis_cluster_node_t	*node = data;

	fr_assert(node->pool);

	if (live->skip == node->id) return 0;	/* Skip the dead node */

	live->node[live->next].pool_state = fr_pool_state(node->pool);
	live->node[live->next++].id = node->id;

	return 0;
}

/** Try to determine the health of a cluster node passively by examining its pool state
 *
 * Returns an integer value representing the likelihood that the pool is live.
 * Range is between 1 and 11,000.
 *
 * If a weight of 1 is returned, connections from the pool should be checked
 * (by pinging) before use.
 *
 * @param now The current time.
 * @param state of the connection pool.
 * @return
 *	- 1 the pool is very likely to be bad.
 *	- 2-11000 the pool is likely to be good, with a higher number
 *	  indicating higher probability of liveness.
 */
static int cluster_node_pool_health(fr_time_t now, fr_pool_state_t const *state)
{
	/*
	 *	Failed spawn recently, probably bad
	 */
	if (fr_time_delta_to_msec(now - state->last_failed) < FAILED_PERIOD) return FAILED_WEIGHT;

	/*
	 *	Closed recently, probably bad
	 */
	if (fr_time_delta_to_msec(now - state->last_closed) < CLOSED_PERIOD) return CLOSED_WEIGHT;

	/*
	 *	Released too long ago, don't know
	 */
	if (fr_time_delta_to_msec(now - state->last_released) > RELEASED_PERIOD) return RELEASED_MIN_WEIGHT;

	/*
	 *	Released not long ago, might be ok.
	 */
	return RELEASED_MIN_WEIGHT + (RELEASED_PERIOD - fr_time_delta_to_msec(now - state->last_released));
}

/** Issue a ping request against a cluster node
 *
 * Establishes whether the connection to the node we have is live.
 *
 * @param request The current request.
 * @param node to ping.
 * @param conn the connection to ping on.
 * @return
 *	- FR_REDIS_CLUSTER_RCODE_BAD_INPUT if we got a bad response.
 *	- FR_REDIS_CLUSTER_RCODE_SUCCESS on success.
 *	- FR_REDIS_CLUSTER_RCODE_NO_CONNECTION on connection down.
 */
static fr_redis_cluster_rcode_t cluster_node_ping(REQUEST *request, fr_redis_cluster_node_t *node, fr_redis_conn_t *conn)
{
	redisReply		*reply;
	fr_redis_rcode_t	rcode;

	RDEBUG2("[%i] Executing command: PING", node->id);
	reply = redisCommand(conn->handle, "PING");
	rcode = fr_redis_command_status(conn, reply);
	if (rcode != REDIS_RCODE_SUCCESS) {
		RPERROR("[%i] PING failed to %s:%i", node->id, node->name, node->addr.port);
		fr_redis_reply_free(&reply);
		return FR_REDIS_CLUSTER_RCODE_NO_CONNECTION;
	}

	if (reply->type != REDIS_REPLY_STATUS) {
		RERROR("[%i] Bad PING response from %s:%i, expected status got %s",
		       node->id, node->name, node->addr.port,
		       fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
		fr_redis_reply_free(&reply);
		return FR_REDIS_CLUSTER_RCODE_BAD_INPUT;
	}

	RDEBUG2("[%i] Got response: %s", node->id, reply->str);
	fr_redis_reply_free(&reply);
	return FR_REDIS_CLUSTER_RCODE_SUCCESS;
}

/** Attempt to find a live pool in the cluster
 *
 * The intent here is to find pools/nodes where a connection was released the shortest
 * time ago.  Having a connection be released (vs closed) indicates that the pool is live.
 *
 * We don't want to have all workers try and grab a connection to this node however, as it
 * may still be dead (we don't know).
 *
 * So we use an inverse transform sample, to weight the nodes, based on time between now
 * and when the connection was released.  Connections released closest to the current
 * time are given a higher weighting.
 *
 * Weight range is between 1 - 11,000.
 *
 * - If released > 10.0 seconds ago,information is not valid, weight 500.
 * - If closed < 10.0 seconds ago, it's a bad pool, weight 1.
 * - If spawn failed < 10.0 seconds ago, it's a bad pool, weight 1.
 * - If a connection was released 0.0 seconds ago, weight 11,000.
 * - If a connection was released 10.0 seconds ago, weight 1000.
 *
 * Using the above algorithm we use the experience of other workers using the cluster to
 * inform our alternative node selection.
 *
 * Suggestions on improving live node selection appreciated.
 *
 * Inverse transform sampling based roughly on the solution from this post:
 *    http://stackoverflow.com/questions/17250568/randomly-choosing-from-a-list-with-weighted-probabilities
 *
 * Wikipedia page here:
 *    https://en.wikipedia.org/wiki/Inverse_transform_sampling
 *
 * @note Must be called with the cluster mutex free.
 *
 * @param[out] live_node we found.
 * @param[out] live_conn to that node.
 * @param[in] request The current request (used for logging).
 * @param[in] cluster to search for live pools in.
 * @param[in] skip this node (it's bad).
 * @return 0 (iterates over the whole tree).
 */
static int cluster_node_find_live(fr_redis_cluster_node_t **live_node, fr_redis_conn_t **live_conn,
				  REQUEST *request, fr_redis_cluster_t *cluster, fr_redis_cluster_node_t *skip)
{
	uint32_t		i;

	cluster_nodes_live_t	*live;
	fr_time_t		now;

	RDEBUG2("Searching for live cluster nodes");

	if (rbtree_num_elements(cluster->used_nodes) == 1) {
	no_alts:
		RERROR("No alternative nodes available");
		return -1;
	}

	live = talloc_zero(NULL, cluster_nodes_live_t);	/* Too big for stack */
	live->skip = skip->id;

	pthread_mutex_lock(&cluster->mutex);
	rbtree_walk(cluster->used_nodes, RBTREE_IN_ORDER, _cluster_pool_walk, live);
	pthread_mutex_unlock(&cluster->mutex);

	fr_assert(live->next);			/* There should be at least one */
	if (live->next == 1) goto no_alts;	/* Weird, but conceivable */

	now = fr_time();

	/*
	 *	Weighted random selection
	 */
	for (i = 0; (i < cluster->conf->max_alt) && live->next; i++) {
		fr_redis_conn_t 	*conn;
		fr_redis_cluster_node_t	*node;
		uint8_t			j;
		int			first, last, pivot;	/* Must be signed for BS */
		unsigned int		find, cumulative = 0;

		RDEBUG3("(Re)assigning node weights:");
		RINDENT();
		for (j = 0; j < live->next; j++) {
			int weight;

			weight = cluster_node_pool_health(now, live->node[j].pool_state);
			RDEBUG3("Node %i weight: %i", live->node[j].id, weight);
			live->node[j].cumulative = (cumulative += weight);
		}
		REXDENT();

		/*
		 *	Select a node at random
		 */
		find = (fr_rand() & (cumulative - 1));	/* Between 1 and total */
		first = 0;
		last = live->next - 1;
		pivot = (first + last) / 2;

		while (first <= last) {
			if (live->node[pivot].cumulative < find) {
				first = pivot + 1;
			} else if (live->node[pivot].cumulative == find) {
				break;
			} else {
				last = pivot - 1;
			}
			pivot = (first + last) / 2;
		}
		/*
		 *	Round up...
		 */
		if (first > last) pivot = last + 1;

		/*
		 *	Resolve the index to the actual node.  We use IDs
		 *	to save memory...
		 */
		node = &cluster->node[live->node[pivot].id];
		fr_assert(live->node[pivot].id == node->id);

		RDEBUG2("Selected node %i (using random value %i)", node->id, find);
		conn = fr_pool_connection_get(node->pool, request);
		if (!conn) {
			RERROR("No connections available to node %i %s:%i", node->id,
			       node->name, node->addr.port);
		next:
			/*
			 *	Remove the node we just discovered was bad
			 *	out of the set of nodes we're selecting over.
			 */
			if (pivot == live->next) {
				live->next--;
				continue;
			}
			memcpy(&live->node[pivot], &live->node[live->next - 1], sizeof(live->node[pivot]));
			live->next--;
			continue;
		}

		/*
		 *	PING! PONG?
		 */
		switch (cluster_node_ping(request, node, conn)) {
		case FR_REDIS_CLUSTER_RCODE_SUCCESS:
			break;

		case FR_REDIS_CLUSTER_RCODE_NO_CONNECTION:
			fr_pool_connection_close(node->pool, request, conn);
			goto next;

		default:
			fr_pool_connection_release(node->pool, request, conn);
			goto next;
		}

		*live_node = node;
		*live_conn = conn;
		talloc_free(live);

		return 0;
	}

	RERROR("Hit max alt limit %i, and no live connections found", cluster->conf->max_alt);
	talloc_free(live);

	return -1;
}

/** Callback for freeing a Redis connection
 *
 * @param[in] conn to free.
 * @return 0.
 */
static int _cluster_conn_free(fr_redis_conn_t *conn)
{
	redisFree(conn->handle);

	return 0;
}

/** Create a new connection to a Redis node
 *
 * @param[in] ctx to allocate connection structure in. Will be freed at the same time as the pool.
 * @param[in] instance data of type #fr_redis_cluster_node_t. Holds parameters for establishing new connection.
 * @param[in] timeout The maximum time allowed to complete the connection.
 * @return
 *	- New #fr_redis_conn_t on success.
 *	- NULL on failure.
 */
void *fr_redis_cluster_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout)
{
	fr_redis_cluster_node_t		*node = instance;
	fr_redis_conn_t		*conn = NULL;
	redisContext		*handle;
	redisReply		*reply = NULL;
	char const		*log_prefix = node->cluster->log_prefix;

	DEBUG2("%s - [%i] Connecting to node %s:%i", log_prefix, node->id, node->name, node->addr.port);

	handle = redisConnectWithTimeout(node->name, node->addr.port, fr_time_delta_to_timeval(timeout));
	if ((handle != NULL) && handle->err) {
		ERROR("%s - [%i] Connection failed: %s", log_prefix, node->id, handle->errstr);
		redisFree(handle);
		return NULL;
	} else if (!handle) {
		ERROR("%s - [%i] Connection failed", log_prefix, node->id);
		return NULL;
	}

	if (node->cluster->conf->password) {
		DEBUG3("%s - [%i] Executing: AUTH %s", log_prefix, node->id, node->cluster->conf->password);
		reply = redisCommand(handle, "AUTH %s", node->cluster->conf->password);
		if (!reply) {
			ERROR("%s - [%i] Failed authenticating: %s", log_prefix, node->id, handle->errstr);
		error:
			if (reply) fr_redis_reply_free(&reply);
			redisFree(handle);
			return NULL;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s - [%i] Failed authenticating: %s", log_prefix,
				      node->id, reply->str);
				goto error;
			}
			fr_redis_reply_free(&reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s - [%i] Failed authenticating: %s", log_prefix, node->id, reply->str);
			goto error;

		default:
			ERROR("%s - [%i] Unexpected reply of type %s to AUTH", log_prefix, node->id,
			      fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
			goto error;
		}
	}

	if (node->cluster->conf->database) {
		DEBUG3("%s - [%i] Executing: SELECT %i", log_prefix, node->id, node->cluster->conf->database);
		reply = redisCommand(handle, "SELECT %i", node->cluster->conf->database);
		if (!reply) {
			ERROR("%s - [%i] Failed selecting database %i: %s", log_prefix, node->id,
			      node->cluster->conf->database, handle->errstr);
			goto error;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s - [%i] Failed selecting database %i: %s", log_prefix, node->id,
				      node->cluster->conf->database, reply->str);
				goto error;
			}
			fr_redis_reply_free(&reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s - [%i] Failed selecting database %i: %s", log_prefix, node->id,
			      node->cluster->conf->database, reply->str);
			goto error;

		default:
			ERROR("%s - [%i] Unexpected reply of type %s, to SELECT", log_prefix, node->id,
			      fr_table_str_by_value(redis_reply_types, reply->type, "<UNKNOWN>"));
			goto error;
		}
	}

	conn = talloc_zero(ctx, fr_redis_conn_t);
	conn->handle = handle;
	talloc_set_destructor(conn, _cluster_conn_free);

	return conn;
}

/** Implements the key slot selection scheme used by freeradius
 *
 * Like the scheme in the clustering specification but with some differences
 * if the key is NULL or zero length, then a random keyslot is chosen.
 *
 * If there's only a single node in the cluster, then we avoid the CRC16
 * and just use key slot 0.
 *
 * @param cluster to determine key slot for.
 * @param request The current request.
 * @param key the key to resolve.
 * @param key_len the length of the key.
 * @return pointer to key slot key resolves to.
 */
fr_redis_cluster_key_slot_t const *fr_redis_cluster_slot_by_key(fr_redis_cluster_t *cluster, REQUEST *request,
								uint8_t const *key, size_t key_len)
{
	fr_redis_cluster_key_slot_t *key_slot;

	if (!key || (key_len == 0)) {
		key_slot = &cluster->key_slot[(uint16_t)(fr_rand() & (KEY_SLOTS - 1))];
		RDEBUG2("Key rand() -> slot %zu", key_slot - cluster->key_slot);

		return key_slot;
	}

	/*
	 *	Avoid CRC16 if we're operating with one cluster node or
	 *	without clustering.
	 */
	if (rbtree_num_elements(cluster->used_nodes) > 1) {
		key_slot = &cluster->key_slot[cluster_key_hash(key, key_len)];
		RDEBUG2("Key \"%pV\" -> slot %zu",
			fr_box_strvalue_len((char const *)key, key_len), key_slot - cluster->key_slot);

		return key_slot;
	}
	RDEBUG3("Single node available, skipping key selection");

	return &cluster->key_slot[0];
}

/** Return the master node that would be used for a particular key
 *
 * @param[in] cluster		To resolve key in.
 * @param[in] key_slot		to resolve to node.
 * @return
 *      - The current master node.
 *	- NULL if no master node is currently assigned to a particular key slot.
 */
fr_redis_cluster_node_t const *fr_redis_cluster_master(fr_redis_cluster_t *cluster,
						       fr_redis_cluster_key_slot_t const *key_slot)
{
	return &cluster->node[key_slot->master];
}

/** Return the slave node that would be used for a particular key
 *
 * @param[in] cluster		To resolve key in.
 * @param[in] key_slot		To resolve to node.
 * @param[in] slave_num		0..n.
 * @return
 *	- A slave node.
 *	- NULL if no slave node is assigned, or is at the specific key slot.
 *
 */
fr_redis_cluster_node_t const *fr_redis_cluster_slave(fr_redis_cluster_t *cluster,
						      fr_redis_cluster_key_slot_t const *key_slot,
						      uint8_t slave_num)
{
	if (slave_num >= key_slot->slave_num) return NULL;	/* No slave available */

	return &cluster->node[key_slot->slave[slave_num]];
}

/** Return the ipaddr of a particular node
 *
 * @param[out] out	Ipaddr of the node.
 * @param[in] node	to get ip address from.
 * @return
 *	- 0 on success.
 *	- -1 on failure (node is NULL).
 */
int fr_redis_cluster_ipaddr(fr_ipaddr_t *out, fr_redis_cluster_node_t const *node)
{
	if (!node) return -1;

	memcpy(out, &node->addr.ipaddr, sizeof(*out));

	return 0;
}

/** Return the port of a particular node
 *
 * @param[out] out	Port of the node.
 * @param[in] node	to get ip address from.
 * @return
 *	- 0 on success.
 *	- -1 on failure (node is NULL).
 */
int fr_redis_cluster_port(uint16_t *out, fr_redis_cluster_node_t const *node)
{
	if (!node) return -1;

	*out = node->addr.port;

	return 0;
}

/** Resolve a key to a pool, and reserve a connection in that pool
 *
 * This should be used with #fr_redis_cluster_state_next, and #fr_redis_command_status, to
 * transparently locate the cluster node we need to perform the operation on.
 *
 * Example code below shows how this function is used in conjunction
 * with #fr_redis_cluster_state_next to follow redirects, and reconnect handles.
 *
 @code{.c}
    int                 s_ret;
    redis_conn_state	state;
    fr_redis_conn_t  	*conn;
    redisReply		*reply;
    fr_redis_rcode_t	status;

    for (s_ret = fr_redis_cluster_state_init(&state, &conn, cluster, key, key_len, false);
         s_ret == REDIS_RCODE_TRY_AGAIN,
         s_ret = fr_redis_cluster_state_next(&state, &conn, cluster, request, status, &reply)) {
            reply = redisCommand(conn->handle, "SET foo bar");
            status = fr_redis_command_status(conn, reply);
    }
    // Reply is freed if ret == REDIS_RCODE_TRY_AGAIN, but left in all other cases to allow error
    // processing, or extraction of results.
    fr_redis_reply_free(&reply);
    if (s_ret != REDIS_RCODE_SUCCESS) {
    	// Error
    }
    // Success
 @endcode
 *
 * @param[out] state to track current pool and various counters, will be initialised.
 * @param[out] conn Where to write the reserved connection to.
 * @param[in] cluster of pools.
 * @param[in] request The current request.
 * @param[in] key to resolve to a cluster node/pool. If no key is NULL or key_len is 0 a random
 *	slot will be chosen.
 * @param[in] key_len Length of the key.
 * @param[in] read_only If true, will use random slave pool in preference to the master, falling
 *	back to the master if no slaves are available.
 * @return
 *	- REDIS_RCODE_TRY_AGAIN - try your command with this connection (provided via command).
 *	- REDIS_RCODE_RECONNECT - when no additional connections available.
 */
fr_redis_rcode_t fr_redis_cluster_state_init(fr_redis_cluster_state_t *state, fr_redis_conn_t **conn,
					     fr_redis_cluster_t *cluster, REQUEST *request,
					     uint8_t const *key, size_t key_len, bool read_only)
{
	fr_redis_cluster_node_t			*node;
	fr_redis_cluster_key_slot_t const	*key_slot;
	uint8_t					first, i;
	int					used_nodes;

	fr_assert(cluster);
	fr_assert(state);
	fr_assert(conn);

	memset(state, 0, sizeof(*state));

	used_nodes = rbtree_num_elements(cluster->used_nodes);
	if (used_nodes == 0) {
		REDEBUG("No nodes in cluster");
		return REDIS_RCODE_RECONNECT;
	}

again:
	key_slot = fr_redis_cluster_slot_by_key(cluster, request, key, key_len);

	/*
	 *	1. Try each of the slaves for the key slot
	 *	2. Fall through to trying the master, and a single alternate node.
	 */
	if (read_only) {
		first = fr_rand() & key_slot->slave_num;
		for (i = 0; i < key_slot->slave_num; i++) {
			uint8_t node_id;

			node_id = key_slot->slave[(first + i) % key_slot->slave_num];
			node = &cluster->node[node_id];
			*conn = fr_pool_connection_get(node->pool, request);
			if (!*conn) {
				RDEBUG2("[%i] No connections available (key slot %zu slave %i)",
					node->id, key_slot - cluster->key_slot, (first + i) % key_slot->slave_num);
				cluster->remap_needed = true;
				continue;	/* Continue until we find a live pool */
			}

			goto finish;
		}
		/* Fall through to using key slot master or alternate */
	}

	/*
	 *	1. Try the master for the key slot
	 *	2. If unavailable search for any pools with handles available
	 *	3. If there are no pools, or we can't reserve a handle,
	 *	   give up.
	 */
	node = &cluster->node[key_slot->master];
	*conn = fr_pool_connection_get(node->pool, request);
	if (!*conn) {
		RDEBUG2("[%i] No connections available (key slot %zu master)",
			node->id, key_slot - cluster->key_slot);
		cluster->remap_needed = true;

		if (cluster_node_find_live(&node, conn, request, cluster, node) < 0) return REDIS_RCODE_RECONNECT;
	}

finish:
	/*
	 *	Something set the remap_needed flag, and we have a live connection
	 */
	if (cluster->remap_needed) {
		if (fr_redis_cluster_remap(request, cluster, *conn) == FR_REDIS_CLUSTER_RCODE_SUCCESS) {
			fr_pool_connection_release(node->pool, request, *conn);
			goto again;	/* New map, try again */
		}
		RDEBUG2("%s", fr_strerror());
	}

	state->node = node;
	state->key = key;
	state->key_len = key_len;

	RDEBUG2("[%i] >>> Sending command(s) to %s:%i", state->node->id, state->node->name, state->node->addr.port);

	return REDIS_RCODE_TRY_AGAIN;
}

/** Get the next connection to attempt a command against
 *
 * Will process reconnect and redirect states performing the actions necessary.
 *
 * - May trigger a cluster remap on receiving a #REDIS_RCODE_MOVE status.
 * - May perform a temporary redirect on receiving a #REDIS_RCODE_ASK status.
 * - May reserve a new connection on receiving a #REDIS_RCODE_RECONNECT status.
 *
 * If a remap is in progress, has ocurred within the last second, has recently failed,
 * or fails, the '-MOVE' will be treated as a temporary redirect (-ASK).
 *
 * This allows the server to be more responsive during remaps, as unless the worker has been
 * redirected to a node we don't currently have a pool for, it can grab a connection for the
 * node it was redirected to, and continue.
 *
 * @note Irrespective of return code, the connection passed via conn will be released,
 *	A new connection to attempt command on will be provided via conn.
 *
 * @note reply will be automatically freed and set to NULL if a new connection is provided
 *	in all other cases, the caller is responsible for freeing the reply.
 *
 * @param[in,out] state containing the current pool, and various counters which control
 *	retries, and limit redirects.
 * @param[in,out] conn we received the '-ASK' or '-MOVE' redirect on. Will be replaced with a
 *	connection in the new pool the key points to.
 * @param[in] request The current request.
 * @param[in] cluster of pools.
 * @param[in] status of the last command, must be #REDIS_RCODE_MOVE or #REDIS_RCODE_ASK.
 * @param[in] reply from last command.  Freed if 0 is returned, else caller must free.
 * @return
 *	- REDIS_RCODE_SUCCESS - on success.
 *	- REDIS_RCODE_TRY_AGAIN - try new connection (provided via conn). Will free reply.
 *	- REDIS_RCODE_ERROR - on failure or command error.
 *	- REDIS_RCODE_RECONNECT - when no additional connections available.
 */
fr_redis_rcode_t fr_redis_cluster_state_next(fr_redis_cluster_state_t *state, fr_redis_conn_t **conn,
					     fr_redis_cluster_t *cluster, REQUEST *request,
					     fr_redis_rcode_t status, redisReply **reply)
{
	fr_assert(state && state->node && state->node->pool);
	fr_assert(conn && *conn);

	if (*reply) fr_redis_reply_print(L_DBG_LVL_3, *reply, request, 0);

 	RDEBUG2("[%i] <<< Returned: %s", state->node->id, fr_table_str_by_value(redis_rcodes, status, "<UNKNOWN>"));

	/*
	 *	Caller indicated we should close the connection
	 */
	if (state->close_conn) {
		RDEBUG2("[%i] Connection no longer viable, closing it", state->node->id);
		fr_pool_connection_close(state->node->pool, request, *conn);
		*conn = NULL;
		state->close_conn = false;
	}

	/*
	 *	If we have a proven live connection, and something
	 *	has set the remap_needed flag, do that now before
	 *	releasing the connection.
	 */
	if (cluster->remap_needed && *conn) switch(status) {
	case REDIS_RCODE_MOVE:		/* We're going to remap anyway */
	case REDIS_RCODE_RECONNECT:	/* The connection's dead */
		break;

	default:
		/*
		 *	Remap the cluster. On success, will clear the
		 *	remap_needed flag.
		 */
		if (fr_redis_cluster_remap(request, cluster, *conn) != FR_REDIS_CLUSTER_RCODE_SUCCESS) RDEBUG2("%s", fr_strerror());
	}

	/*
	 *	Check the result of the last redis command, and do
	 *	something appropriate.
	 */
	switch (status) {
	case REDIS_RCODE_SUCCESS:
		fr_pool_connection_release(state->node->pool, request, *conn);
		*conn = NULL;
		return REDIS_RCODE_SUCCESS;

	/*
	 *	Command error, not fixable.
	 */
	case REDIS_RCODE_NO_SCRIPT:
	case REDIS_RCODE_ERROR:
		RPEDEBUG("[%i] Command failed", state->node->id);
		fr_pool_connection_release(state->node->pool, request, *conn);
		*conn = NULL;
		return REDIS_RCODE_ERROR;

	/*
	 *	Cluster's unstable, try again.
	 */
	case REDIS_RCODE_TRY_AGAIN:
		if (state->retries++ >= cluster->conf->max_retries) {
			REDEBUG("[%i] Hit maximum retry attempts", state->node->id);
			fr_pool_connection_release(state->node->pool, request, *conn);
			*conn = NULL;
			return REDIS_RCODE_ERROR;
		}

		if (!*conn) *conn = fr_pool_connection_get(state->node->pool, request);

		if (cluster->conf->retry_delay) nanosleep(&fr_time_delta_to_timespec(cluster->conf->retry_delay), NULL);
		goto try_again;

	/*
	 *	Connection's dead, check to see if we can switch nodes,
	 *	or, failing that, reconnect the connection.
	 */
	case REDIS_RCODE_RECONNECT:
	{
		fr_redis_cluster_key_slot_t const *key_slot;

		RERROR("[%i] Failed communicating with %s:%i: %s", state->node->id, state->node->name,
		       state->node->addr.port, fr_strerror());

		fr_pool_connection_close(state->node->pool, request, *conn);	/* He's dead jim */

		if (state->reconnects++ > state->in_pool) {
			REDEBUG("[%i] Hit maximum reconnect attempts", state->node->id);
			cluster->remap_needed = true;
			return REDIS_RCODE_RECONNECT;
		}

		/*
		 *	Refresh the key slot
		 */
		key_slot = fr_redis_cluster_slot_by_key(cluster, request, state->key, state->key_len);
		state->node = &cluster->node[key_slot->master];

		*conn = fr_pool_connection_get(state->node->pool, request);
		if (!*conn) {
			REDEBUG("[%i] No connections available for %s:%i", state->node->id, state->node->name,
				state->node->addr.port);
			cluster->remap_needed = true;

			if (cluster_node_find_live(&state->node, conn, request,
						   cluster, state->node) < 0) return REDIS_RCODE_RECONNECT;

			return REDIS_RCODE_TRY_AGAIN;
		}

		state->retries = 0;
	}
		goto try_again;

	/*
	 *	-MOVE is treated identically to -ASK, except it may
	 *	trigger a cluster remap.
	 */
	case REDIS_RCODE_MOVE:
		fr_assert(*reply);

		if (*conn && (fr_redis_cluster_remap(request, cluster, *conn) != FR_REDIS_CLUSTER_RCODE_SUCCESS)) {
			RDEBUG2("%s", fr_strerror());
		}
		/* FALL-THROUGH */

	/*
	 *	-ASK process a redirect.
	 */
	case REDIS_RCODE_ASK:
	{
		fr_redis_cluster_node_t *new;

		fr_pool_connection_release(state->node->pool, request, *conn);	/* Always release the old connection */

		if (!fr_cond_assert(*reply)) return REDIS_RCODE_ERROR;

		RDEBUG2("[%i] Processing redirect \"%s\"", state->node->id, (*reply)->str);
		if (state->redirects++ >= cluster->conf->max_redirects) {
			REDEBUG("[%i] Reached max_redirects (%i)", state->node->id, state->redirects);
			return REDIS_RCODE_ERROR;
		}

		switch (cluster_redirect(&new, cluster, *reply)) {
		case FR_REDIS_CLUSTER_RCODE_SUCCESS:
			if (new == state->node) {
				REDEBUG("[%i] %s:%i issued redirect to itself", state->node->id,
					state->node->name, state->node->addr.port);
				return REDIS_RCODE_ERROR;
			}

			RDEBUG2("[%i] Redirected from %s:%i to [%i] %s:%i", state->node->id, state->node->name,
			        state->node->addr.port, new->id, new->name, new->addr.port);
			state->node = new;

			*conn = fr_pool_connection_get(state->node->pool, request);
			if (!*conn) return REDIS_RCODE_RECONNECT;

			/*
			 *	Reset these counters, their scope is
			 *	a single node in the cluster.
			 */
			state->reconnects = 0;
			state->retries = 0;
			state->in_pool = fr_pool_state(state->node->pool)->num;
			goto try_again;

		case FR_REDIS_CLUSTER_RCODE_NO_CONNECTION:
			cluster->remap_needed = true;
			return REDIS_RCODE_RECONNECT;

		default:
			return REDIS_RCODE_ERROR;
		}
	}
	}

try_again:
	RDEBUG2("[%i] >>> Sending command(s) to %s:%i", state->node->id, state->node->name, state->node->addr.port);

	fr_redis_reply_free(&*reply);
	*reply = NULL;

	return REDIS_RCODE_TRY_AGAIN;
}

/** Get the pool associated with a node in the cluster
 *
 * @note This is used for testing only.  It's not ifdef'd out because
 *	tests need to run against production builds too.
 *
 * @param[out] pool associated with the node.
 * @param[in] cluster to search for node in.
 * @param[in] node_addr to retrieve pool for.  Specifies IP and port of node.
 * @param[in] create Establish a connection to the specified node if it
 *	was previously unknown to the cluster client.
 * @return
 *	- 0 on success.
 *	- -1 if no such node exists.
 */
int fr_redis_cluster_pool_by_node_addr(fr_pool_t **pool, fr_redis_cluster_t *cluster,
				       fr_socket_addr_t *node_addr, bool create)
{
	fr_redis_cluster_node_t	find, *found;

	find.addr.ipaddr = node_addr->ipaddr;
	find.addr.port = node_addr->port;

	pthread_mutex_lock(&cluster->mutex);
	found = rbtree_finddata(cluster->used_nodes, &find);
	if (!found) {
		fr_redis_cluster_node_t *spare;
		char buffer[INET6_ADDRSTRLEN];
		char const *hostname;

		if (!create) {
			pthread_mutex_unlock(&cluster->mutex);

			hostname = inet_ntop(node_addr->ipaddr.af, &node_addr->ipaddr.addr, buffer, sizeof(buffer));
			fr_assert(hostname);	/* addr.ipaddr is probably corrupt */;
			fr_strerror_printf("No existing node found with address %s, port %i",
					   hostname, node_addr->port);
			return -1;
		}

		spare = fr_fifo_peek(cluster->free_nodes);
		if (!spare) {
			fr_strerror_printf("Reached maximum connected nodes");
			pthread_mutex_unlock(&cluster->mutex);
			return -1;
		}
		spare->pending_addr = find.addr;	/* Set the config to be applied */
		if (cluster_node_connect(cluster, spare) < 0) {
			pthread_mutex_unlock(&cluster->mutex);
			return -1;
		}
		rbtree_insert(cluster->used_nodes, spare);
		fr_fifo_pop(cluster->free_nodes);
		found = spare;
	}
	/*
	 *	Sanity checks
	 */
	fr_assert(((talloc_array_length(cluster->node) - 1) - rbtree_num_elements(cluster->used_nodes)) ==
		   fr_fifo_num_elements(cluster->free_nodes));
	pthread_mutex_unlock(&cluster->mutex);

	*pool = found->pool;

	return 0;
}

/** Private ctx structure to pass to _cluster_role_walk
 *
 */
typedef struct {
	bool			is_master;
	bool			is_slave;
	uint8_t			count;
	fr_socket_addr_t	*found;
} addr_by_role_ctx_t;

/** Walk all used pools, recording the IP addresses of ones matching the filter
 *
 * @param[in] uctx	Where to write the node we found.
 * @param[in] data	node to check.
 * @return
 *	- 0 continue walking.
 *	- -1 found suitable node.
 */
static int _cluster_role_walk(void *data, void *uctx)
{
	addr_by_role_ctx_t		*ctx = uctx;
	fr_redis_cluster_node_t		*node = data;

	if ((ctx->is_master && node->is_master) || (ctx->is_slave && !node->is_master)) {
		ctx->found[ctx->count++] = node->addr;
	}
	return 0;
}

/** Return an array of IP addresses belonging to masters or slaves
 *
 * @note We return IP addresses as they're safe to use across cluster remaps.
 * @note Result array must be freed (talloc_free()) after use.
 *
 * @param[in] ctx to allocate array of IP addresses in.
 * @param[out] out		Where to write the addresses of the nodes.
 * @param[in] cluster		to search for nodes in.
 * @param[in] is_master		If true, include the addresses of all the master nodes.
 * @param[in] is_slave		If true, include the addresses of all the slaves nodes.
 * @return the number of ip addresses written to out.
 */
ssize_t fr_redis_cluster_node_addr_by_role(TALLOC_CTX *ctx, fr_socket_addr_t *out[],
					   fr_redis_cluster_t *cluster, bool is_master, bool is_slave)
{
	addr_by_role_ctx_t context;
	size_t in_use = rbtree_num_elements(cluster->used_nodes);

	if (in_use == 0) {
		*out = NULL;
		return 0;
	}

	context.is_master = is_master;
	context.is_slave = is_slave;
	context.count = 0;
	context.found = talloc_zero_array(ctx, fr_socket_addr_t, in_use);
	if (!context.found) {
		fr_strerror_printf("Out of memory");
		return -1;
	}

	pthread_mutex_lock(&cluster->mutex);
	rbtree_walk(cluster->used_nodes, RBTREE_IN_ORDER, _cluster_role_walk, &context);
	*out = context.found;
	pthread_mutex_unlock(&cluster->mutex);

	if (context.count == 0) {
		*out = NULL;
		talloc_free(context.found);
		return 0;
	}

	*out = context.found;

	return context.count;
}

/** Destroy mutex associated with cluster slots structure
 *
 * @param cluster being freed.
 * @return 0
 */
static int _fr_redis_cluster_free(fr_redis_cluster_t *cluster)
{
	pthread_mutex_destroy(&cluster->mutex);

	return 0;
}

/** Walk all used pools checking their versions
 *
 * @param[in] uctx	Where to write the node we found.
 * @param[in] data	node to check.
 * @return
 *	- 0 continue walking.
 *	- -1 found suitable node.
 */
static int _cluster_version_walk(void *data, void *uctx)
{
	char const 		*min_version = uctx;
	fr_redis_cluster_node_t	*node = data;
	fr_redis_conn_t		*conn;
	int			ret;
	char			buffer[40];

	conn = fr_pool_connection_get(node->pool, NULL);
	if (!conn) return 0;

	/*
	 *	We don't care if we can't get the version
	 *	as we don't want to prevent the server from
	 *	starting if start == 0.
	 */
	ret = fr_redis_get_version(buffer, sizeof(buffer), conn);
	fr_pool_connection_release(node->pool, NULL, conn);
	if (ret < 0) return 0;

	if (fr_redis_version_num(buffer) < fr_redis_version_num(min_version)) {
		fr_strerror_printf("Redis node %s:%i (currently v%s) needs update to >= v%s",
				   node->name, node->addr.port, buffer, min_version);
		return -1;
	}

	return 0;
}

/** Check if members of the cluster are above a certain version
 *
 * @param cluster to perform check on.
 * @param min_version that must be found on each node for the check to succeed.
 *	Must be in the format @verbatim <major>.<minor>.<release> @endverbatim.
 * @return
 *	- true if all contactable members are above min_version.
 *	- false if at least one member if not above minimum version
 *	  (use #fr_strerror to retrieve node information).
 */
bool fr_redis_cluster_min_version(fr_redis_cluster_t *cluster, char const *min_version)
{
	int ret;
	char *p;

	memcpy(&p, &min_version, sizeof(p));

	pthread_mutex_lock(&cluster->mutex);
	ret = rbtree_walk(cluster->used_nodes, RBTREE_IN_ORDER, _cluster_version_walk, p);
	pthread_mutex_unlock(&cluster->mutex);

	return ret < 0 ? false : true;
}

/** Allocate and initialise a new cluster structure
 *
 * This holds all the data necessary to manage a pool of pools for a specific redis cluster.
 *
 * @note Will not error out unless cs.pool.start > 0.  This is consistent with other pool based
 *	modules/code.
 *
 * @param ctx			to link the lifetime of the cluster structure to.
 * @param module		Configuration section to search for 'server' conf pairs in.
 * @param conf			Base redis server configuration. Cluster nodes share database
 *				number and password.
 * @param triggers_enabled	Whether triggers should be enabled.
 * @param log_prefix		Custom log prefix.  Defaults to @verbatim rlm_<module> (<instance>) @endverbatim.
 * @param trigger_prefix	Custom trigger prefix.  Defaults to @verbatim modules.<module>.pool @endverbatim.
 * @param trigger_args		Argument pairs to pass to the trigger in addition to Connection-Pool-Server,
 *				and Connection-Pool-Port (which are always set by the cluster code).
 * @return
 *	- New #fr_redis_cluster_t on success.
 *	- NULL on error.
 */
fr_redis_cluster_t *fr_redis_cluster_alloc(TALLOC_CTX *ctx,
					   CONF_SECTION *module,
					   fr_redis_conf_t *conf,
					   bool triggers_enabled,
					   char const *log_prefix,
					   char const *trigger_prefix,
					   VALUE_PAIR *trigger_args)
{
	uint8_t			i;
	uint16_t		s;

	char const		*cs_name1, *cs_name2;

	CONF_PAIR		*cp;
	int			af = AF_UNSPEC;		/* AF of first server */

	int			num_nodes;
	fr_redis_cluster_t	*cluster;

	fr_assert(triggers_enabled || !trigger_prefix);
	fr_assert(triggers_enabled || !trigger_args);

	cluster = talloc_zero(NULL, fr_redis_cluster_t);
	if (!cluster) {
		ERROR("%s - Out of memory", log_prefix);
		return NULL;
	}

	cs_name1 = cf_section_name1(module);
	cs_name2 = cf_section_name2(module);

	cluster->triggers_enabled = triggers_enabled;
	if (cluster->triggers_enabled) {
		/*
		 *	Setup trigger prefix
		 */
		if (!trigger_prefix) {
			cluster->trigger_prefix = talloc_typed_asprintf(cluster, "modules.%s.pool", cs_name1);
		} else {
			cluster->trigger_prefix = talloc_strdup(cluster, trigger_prefix);
		}

		/*
		 *	Duplicate the trigger arguments.
		 */
		 if (trigger_args) MEM(fr_pair_list_copy(cluster, &cluster->trigger_args, trigger_args) >= 0);
	}

	/*
	 *	Setup log prefix
	 */
	if (!log_prefix) {
		if (!cs_name2) cs_name2 = cs_name1;
		cluster->log_prefix = talloc_typed_asprintf(conf, "rlm_%s (%s)", cs_name1, cs_name2);
	} else {
		cluster->log_prefix = talloc_strdup(cluster, log_prefix);
	}

	/*
	 *	Ensure we always have a pool section (even if it's empty)
	 */
	if (!cf_section_find(module, "pool", NULL)) {
		(void) cf_section_alloc(module, module, "pool", NULL);
	}

	if (conf->max_nodes == UINT8_MAX) {
		ERROR("%s - Maximum number of connected nodes allowed is %i", cluster->log_prefix, UINT8_MAX - 1);
		talloc_free(cluster);
		return NULL;
	}

	if (conf->max_nodes == 0) {
		ERROR("%s - Minimum number of nodes allowed is 1", cluster->log_prefix);
		talloc_free(cluster);
		return NULL;
	}

	cp = cf_pair_find(module, "server");
	if (!cp) {
		ERROR("%s - No servers configured", cluster->log_prefix);
		talloc_free(cluster);
		return NULL;
	}

	cluster->module = module;

	/*
	 *	Ensure the pool is freed at the same time as its
	 *	parent.
	 *
	 *	We need to break the link between the cluster and
	 *	its parent context, as the two contexts may be
	 *	modified by multiple threads.
	 */
	if (talloc_link_ctx(ctx, cluster) < 0) {
	oom:
		ERROR("%s - Out of memory", cluster->log_prefix);

	error:
		talloc_free(cluster);
		return NULL;
	}

	cluster->node = talloc_zero_array(cluster, fr_redis_cluster_node_t, conf->max_nodes + 1);
	if (!cluster->node) goto oom;

	cluster->used_nodes = rbtree_create(cluster, _cluster_node_cmp, NULL, 0);
	if (!cluster->used_nodes) goto oom;

	cluster->free_nodes = fr_fifo_create(cluster, conf->max_nodes, NULL);
	if (!cluster->free_nodes) goto oom;

	cluster->conf = conf;

	pthread_mutex_init(&cluster->mutex, NULL);
	talloc_set_destructor(cluster, _fr_redis_cluster_free);

	/*
	 *	Node id 0 is reserved, so we can detect misconfigured
	 *	clusters.
	 */
	for (i = 1; i < (cluster->conf->max_nodes + 1); i++) {
		cluster->node[i].id = i;
		cluster->node[i].cluster = cluster;

		/* Push them all into the queue */
		fr_fifo_push(cluster->free_nodes, &cluster->node[i]);
	}

	/*
	 *	Don't connect to cluster nodes if we're just
	 *	checking the config.
	 */
	if (check_config) return cluster;

	/*
	 *	Populate the cluster with the bootstrap servers.
	 *
	 *	If we fail getting a key_slot map here, then the
	 *	bootstrap servers are distributed evenly through
	 *	the key slots.
	 *
	 *	This allows the server to start, and potentially,
	 *	a valid map to be applied, once the server starts
	 *	processing requests.
	 */
	do {
		char const	*server;
		fr_redis_cluster_node_t	*node;
		fr_redis_conn_t	*conn;
		redisReply	*map;
		size_t		j, k;

		node = fr_fifo_peek(cluster->free_nodes);
		if (!node) {
			ERROR("%s - Number of bootstrap servers exceeds 'max_nodes'", cluster->log_prefix);
			goto error;
		}

		server = cf_pair_value(cp);
		if (fr_inet_pton_port(&node->pending_addr.ipaddr, &node->pending_addr.port, server,
				 talloc_array_length(server) - 1, af, true, true) < 0) {
			PERROR("%s - Failed parsing server \"%s\"", cluster->log_prefix, server);
			goto error;
		}
		if (!node->pending_addr.port) node->pending_addr.port = conf->port;

		if (cluster_node_connect(cluster, node) < 0) {
			WARN("%s - Connecting to %s:%i failed", cluster->log_prefix, node->name, node->pending_addr.port);
			continue;
		}

		if (!rbtree_insert(cluster->used_nodes, node)) {
			WARN("%s - Skipping duplicate bootstrap server \"%s\"", cluster->log_prefix, server);
			continue;
		}
		node->is_active = true;
		fr_fifo_pop(cluster->free_nodes);

		/*
		 *	Prefer the same IPaddr family as the first node
		 */
		if (af == AF_UNSPEC) af = node->addr.ipaddr.af;

		/*
		 * 	Only get cluster map config if required
		 */
		if (fr_pool_start_num(node->pool) > 0) {
			/*
			 *	Fine to leave this node configured, if we do find
			 *	a live node, and it's not in the map, it'll be cleared out.
			 */
			conn = fr_pool_connection_get(node->pool, NULL);
			if (!conn) {
				WARN("%s - Can't contact bootstrap server \"%s\"", cluster->log_prefix, server);
				continue;
			}
		} else {
			break;
		}

		switch (cluster_map_get(&map, conn)) {
		/*
		 *	We got a valid map! See if we can apply it...
		 */
		case FR_REDIS_CLUSTER_RCODE_SUCCESS:
			fr_pool_connection_release(node->pool, NULL, conn);

			DEBUG("%s - Cluster map consists of %zu key ranges", cluster->log_prefix, map->elements);
			for (j = 0; j < map->elements; j++) {
				redisReply *map_node = map->element[j];

				DEBUG("%s - %zu - keys %lli-%lli", cluster->log_prefix, j,
				      map_node->element[0]->integer,
				      map_node->element[1]->integer);
				DEBUG("%s -  master: %s:%lli", cluster->log_prefix,
				      map_node->element[2]->element[0]->str,
				      map_node->element[2]->element[1]->integer);
				for (k = 3; k < map_node->elements; k++) {
					DEBUG("%s -  slave%zu: %s:%lli", cluster->log_prefix, k - 3,
					      map_node->element[k]->element[0]->str,
					      map_node->element[k]->element[1]->integer);
				}
			}

			if (cluster_map_apply(cluster, map) < 0) {
				WARN("%s: Applying cluster map failed: %s", cluster->log_prefix, fr_strerror());
				fr_redis_reply_free(&map);
				continue;
			}
			fr_redis_reply_free(&map);

			return cluster;

		/*
		 *	Unusable bootstrap node
		 */
		case FR_REDIS_CLUSTER_RCODE_BAD_INPUT:
			WARN("%s - Bootstrap server \"%s\" returned invalid data: %s",
			     cluster->log_prefix, server, fr_strerror());
			fr_pool_connection_release(node->pool, NULL, conn);
			continue;

		case FR_REDIS_CLUSTER_RCODE_NO_CONNECTION:
			WARN("%s - Can't contact bootstrap server \"%s\": %s",
			     cluster->log_prefix, server, fr_strerror());
			fr_pool_connection_close(node->pool, NULL, conn);
			continue;

		/*
		 *	Clustering not enabled, or not supported,
		 *	by this node, skip it and check the others.
		 */
		case FR_REDIS_CLUSTER_RCODE_FAILED:
		case FR_REDIS_CLUSTER_RCODE_IGNORED:
			DEBUG2("%s - Bootstrap server \"%s\" returned: %s",
			       cluster->log_prefix, server, fr_strerror());
			fr_pool_connection_release(node->pool, NULL, conn);
			break;
		}
	} while ((cp = cf_pair_find_next(module, cp, "server")));

	/*
	 *	Catch pool.start != 0
	 */
	num_nodes = rbtree_num_elements(cluster->used_nodes);
	if (!num_nodes) {
		ERROR("%s - Can't contact any bootstrap servers", cluster->log_prefix);
		goto error;
	}

	/*
	 *	We've failed to apply a valid cluster map.
	 *	Distribute the node(s) throughout the key_slots,
	 *	hopefully we'll get one when we start processing
	 *	requests.
	 */
	for (s = 0; s < KEY_SLOTS; s++) cluster->key_slot[s].master = (s % (uint16_t) num_nodes) + 1;

	return cluster;
}
