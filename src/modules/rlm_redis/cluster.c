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
 * @copyright 2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 Network RADIUS <info@networkradius.com>
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
 *     - An array of #cluster_node_t.  These are pre-allocated on startup and are
 *       never added to, or removed from.
 *     - An #fr_fifo_t.  This contains the queue of nodes that may be re-used.
 *     - An #rbtree_t.  This contains a tree of nodes which are active.  The tree is built on IP
 *       address and port.
 *
 *   Each #cluster_node_t contains a master ID, and an array of slave IDs.  The IDs are array
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
#include "redis.h"
#include "cluster.h"
#include "crc16.h"
#include <freeradius-devel/rad_assert.h>

#ifndef HAVE_PTHREAD_H
/*
 *	This is easier than ifdef's throughout the code.
 */
#  define pthread_mutex_init(_x, _y)
#  define pthread_mutex_destroy(_x)
#  define pthread_mutex_lock(_x)
#  define pthread_mutex_unlock(_x)
#endif

#define KEY_SLOTS		16384		//!< Maximum number of keyslots (should not change).

#define MAX_SLAVES		5		//!< Maximum number of slaves associated
						//!< with a keyslot.

/*
 *	Periods and weights for live node selection
 */
#define CLOSED_PERIOD		10000		//!< How recently must the closed have
						//!< occurred for us to care.

#define CLOSED_WEIGHT		1		//!< What weight to give to nodes that
						//!< had a connection closed recently.

#define FAILED_PERIOD		10000		//!< How recently must the spawn failure
						//!< occurred for us to care.

#define FAILED_WEIGHT		1		//!< What weight to give to nodes that
						//!< had a spawn failure recently.

#define RELEASED_PERIOD		10000		//!< Period after which we don't care
						//!< about when the last connection was
						//!< released.

#define RELEASED_MIN_WEIGHT	1000		//!< Minimum weight to assign to node.

/** Return values for internal functions
 */
typedef enum {
	CLUSTER_OP_IGNORED		= 1,	//!< Operation ignored.
	CLUSTER_OP_SUCCESS		= 0,	//!< Operation completed successfully.
	CLUSTER_OP_FAILED		= -1,	//!< Operation failed.
	CLUSTER_OP_NO_CONNECTION	= -2,	//!< Operation failed because we couldn't find
						//!< a live connection.
	CLUSTER_OP_BAD_INPUT		= -3	//!< Validation error.
} cluster_rcode_t;

/** Live nodes data, used to perform weighted random selection of alternative nodes
 */
typedef struct cluster_nodes_live {
	struct {
		uint8_t					id;		//!< Node ID.
		fr_connection_pool_state_t const	*pool_state;	//!< Connection pool stats.
		unsigned int				cumulative;	//!< Cumulative weight.
	} node[UINT8_MAX - 1];			//!< Array of live node IDs (and weights).
	uint8_t next;				//!< Next index in live.
	uint8_t skip;
} cluster_nodes_live_t;

/** Configuration for a single node
 */
typedef struct cluster_node_conf {
	fr_ipaddr_t		ipaddr;		//!< IP Address of Redis cluster node.
	uint16_t		port;		//!< Port of Redis cluster node.
} cluster_node_addr_t;

/** A Redis cluster node
 *
 * Passed as opaque data to pools which open connection to nodes.
 */
typedef struct fr_redis_cluster_node {
	char			name[INET6_ADDRSTRLEN];	//!< Buffer to hold IP + port
						//!< text for debug messages.
	bool			active;		//!< Whether this node is in the active node set.
	uint8_t			id;		//!< Node ID (index in node array).

	cluster_node_addr_t	addr;		//!< Current node address.
	cluster_node_addr_t	pending_addr;	//!< New node address to be applied when the pool
						//!< is reconnected.

	fr_redis_conf_t		*conf;		//!< Commmon configuration (database number,
						//!< password, etc..).
	fr_connection_pool_t	*pool;		//!< Pool associated with this node.
} cluster_node_t;

/** Indexes in the cluster_node_t array for a single key slot
 *
 * When dealing with 16K entries, space is a concern. It's significantly
 * more memory efficient to use 8bit indexes than 64bit pointers for each
 * of the key slot to node mappings.
 */
typedef struct cluster_key_slot {
	uint8_t			slave[MAX_SLAVES];	//!< R/O node (slave) for this key slot.
	uint8_t			slave_num;	//!< Number of slaves associated with this key slot.
	uint8_t			master;		//!< R/W node (master) for this key slot.
} cluster_key_slot_t;

/** A redis cluster
 *
 * Holds all the structures and collections of nodes, to represent a Redis cluster.
 */
struct fr_redis_cluster {
	bool			remapping;	//!< True when cluster is being remapped.
	bool			remap_needed;	//!< Set true if at least one cluster node is definitely
						//!< unreachable. Set false on successful remap.
	time_t			last_updated;	//!< Last time the cluster mappings were updated.
	CONF_SECTION		*module;	//!< Module configuration.

	fr_redis_conf_t		*conf;		//!< Base configuration data such as the database number
						//!< and passwords.

	cluster_node_t		*node;		//!< Structure containing a node id, its address and
						//!< a pool of its connections.

	fr_fifo_t		*free_nodes;	//!< Queue of free nodes (or nodes waiting to be reused).
	rbtree_t		*used_nodes;	//!< Tree of used nodes.

	cluster_key_slot_t	key_slot[KEY_SLOTS];		//!< Lookup table of slots to pools.
	cluster_key_slot_t	key_slot_pending[KEY_SLOTS];	//!< Pending key slot table.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;		//!< Mutex to synchronise cluster operations.
#endif
};


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

	q = memchr(key, '}', key_len);
	if (!q || (q < p) || (q == p + 1)) goto all; /* no }, or } before {, or {}, hash everything */

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
	int ret;

	cluster_node_t const *my_a = a;
	cluster_node_t const *my_b = b;

	ret = fr_ipaddr_cmp(&my_a->addr.ipaddr, &my_b->addr.ipaddr);
	if (ret != 0) return ret;

	if (my_a->addr.port < my_b->addr.port) return -1;
	if (my_a->addr.port > my_b->addr.port) return +1;

	return 0;
}

/** Reconnect callback to apply new pool config
 *
 * @param[in] opaque data passed to the connection pool.
 */
static void _cluster_node_conf_apply(void *opaque)
{
	cluster_node_t *node = opaque;
	node->addr = node->pending_addr;
}

/** Establish a connection to a cluster node
 *
 * @note Must be called with the cluster mutex locked.
 * @note Configuration to use for the connection must be set in node->pending_addr, not node->conf.
 *
 * @param[in] cluster to search in.
 * @param[in] node config.
 * @return
 *	 - CLUSTER_OP_SUCCESS on success.
 *	 - CLUSTER_OP_FAILED if the operation failed.
 */
static cluster_rcode_t cluster_node_connect(fr_redis_cluster_t *cluster, cluster_node_t *node)
{
	char const *p;

	rad_assert(node->pending_addr.ipaddr.af);

	/*
	 *	Write out the IP address and Port in string form
	 */
	p = inet_ntop(node->pending_addr.ipaddr.af, &node->pending_addr.ipaddr.ipaddr,
		      node->name, sizeof(node->name));
#ifndef NDEBUG
	rad_assert(p);
#else
	UNUSED_VAR(p);
#endif

	/*
	 *	Node has never been used before, needs a pool allocated for it.
	 */
	if (!node->pool) {
		char buffer[256];

		snprintf(buffer, sizeof(buffer), "%s [%i]", cluster->conf->prefix, node->id);

		node->addr = node->pending_addr;
		node->pool = fr_connection_pool_init(cluster, cf_section_sub_find(cluster->module, "pool"), node,
						     fr_redis_cluster_conn_create, NULL, buffer, NULL);
		if (!node->pool) return CLUSTER_OP_FAILED;
		fr_connection_pool_reconnect_func(node->pool, _cluster_node_conf_apply);
		return CLUSTER_OP_SUCCESS;
	}

	/*
	 *	Apply the new config to the possibly live pool
	 */
	if (fr_connection_pool_reconnect(node->pool) < 0) return CLUSTER_OP_FAILED;

	return CLUSTER_OP_SUCCESS;
}

/** Parse a -MOVED or -ASK redirect
 *
 * Converts the body of the -MOVED or -ASK error into an IPv4/6 address and port.
 *
 * @param[out] key_slot value extracted from redirect string (may be NULL).
 * @param[out] node_addr Redis node ipaddr and port extracted from redirect string.
 * @param[in] redirect to process.
 * @return
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_BAD_INPUT if the server returned an invalid redirect.
 */
static cluster_rcode_t cluster_node_conf_from_redirect(uint16_t *key_slot, cluster_node_addr_t *node_addr,
						       redisReply *redirect)
{
	char		*p, *q;
	unsigned long	key;
	uint16_t	port;
	fr_ipaddr_t	ipaddr;

	rad_assert(redirect->type == REDIS_REPLY_ERROR);

	p = redirect->str;
	if (strncmp(REDIS_ERROR_MOVED_STR, redirect->str, sizeof(REDIS_ERROR_MOVED_STR) - 1) == 0) {
		q = p + sizeof(REDIS_ERROR_MOVED_STR);	/* not a typo, skip space too */
	} else if (strncmp(REDIS_ERROR_ASK_STR, redirect->str, sizeof(REDIS_ERROR_ASK_STR) - 1) == 0) {
		q = p + sizeof(REDIS_ERROR_ASK_STR);	/* not a typo, skip space too */
	} else {
		fr_strerror_printf("No '-MOVED' or '-ASK' prefix");
		return CLUSTER_OP_BAD_INPUT;
	}
	if ((q - p) >= redirect->len) {
		fr_strerror_printf("Truncated");
		return CLUSTER_OP_BAD_INPUT;
	}
	p = q;
	key = strtoul(p, &q, 10);
	if (key > KEY_SLOTS) {
		fr_strerror_printf("Key %lu outside of redis slot range", key);
		return CLUSTER_OP_BAD_INPUT;
	}
	p = q;

	if (*p != ' ') {
		fr_strerror_printf("Missing key/host separator");
		return CLUSTER_OP_BAD_INPUT;
	}
	p++;			/* Skip the ' ' */

	if (fr_pton_port(&ipaddr, &port, p, redirect->len - (p - redirect->str), AF_UNSPEC, false) < 0) {
		return CLUSTER_OP_BAD_INPUT;
	}
	rad_assert(ipaddr.af);

	if (key_slot) *key_slot = key;
	if (node_addr) {
		node_addr->ipaddr = ipaddr;
		node_addr->port = port;
	}

	return CLUSTER_OP_SUCCESS;
}

/** Apply a cluster map received from a cluster node
 *
 * @note Errors may be retrieved with fr_strerror().
 * @note Must be called with the cluster mutex held.
 *
 * @param[in,out] cluster to apply map to.
 * @param[in] reply from #cluster_map_get.
 * @return
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_FAILED on failure.
  *	- CLUSTER_OP_NO_CONNECTION connection failure.
 *	- CLUSTER_OP_BAD_INPUT if the map didn't provide nodes for all keyslots.
 */
static cluster_rcode_t cluster_map_apply(fr_redis_cluster_t *cluster, redisReply *reply)
{
	size_t		i;
	uint8_t		r = 0;
	uint32_t	total = reply->elements;

	cluster_rcode_t	rcode;

	uint8_t		rollback[UINT8_MAX];		// Set of nodes to re-add to the queue on failure.
	bool		active[UINT8_MAX];		// Set of nodes active in the new cluster map.

#ifndef NDEBUG
#  define SET_ADDR(_addr, _map) \
do { \
	int _ret; \
	_ret = fr_pton(&_addr.ipaddr, _map->element[0]->str, _map->element[0]->len, AF_UNSPEC, false);\
	rad_assert(_ret == 0);\
	_addr.port = _map->element[1]->integer; \
} while (0)
#else
#  define SET_ADDR(_addr, _map) \
do { \
	fr_pton(&_addr.ipaddr, _map->element[0]->str, _map->element[0]->len, AF_UNSPEC, false);\
	_addr.port = _map->element[1]->integer; \
} while (0)
#endif

#define SET_INACTIVE(_node) \
do { \
	(_node)->active = false; \
	rbtree_deletebydata(cluster->used_nodes, _node); \
	fr_fifo_push(cluster->free_nodes, _node); \
} while (0)

#define SET_ACTIVE(_node) \
do { \
	(_node)->active = true; \
	rbtree_insert(cluster->used_nodes, _node); \
	fr_fifo_pop(cluster->free_nodes); \
	active[(_node)->id] = true; \
	rollback[r++] = (_node)->id; \
} while (0)

	rad_assert(reply->type == REDIS_REPLY_ARRAY);

	memset(&rollback, 0, sizeof(rollback));
	memset(active, 0, sizeof(active));

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
		cluster_node_t		*found, *spare;
		cluster_node_t		find;
		cluster_key_slot_t	tmpl_slot;
		redisReply		*map = reply->element[i];

		memset(&tmpl_slot, 0, sizeof(tmpl_slot));

		SET_ADDR(find.addr, map->element[2]);
		found = rbtree_finddata(cluster->used_nodes, &find);
		if (found) {
			active[found->id] = true;
			goto skip_master;
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
			rcode = CLUSTER_OP_FAILED;
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

	skip_master:
		tmpl_slot.master = found->id;

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
			total++;
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
			rcode = CLUSTER_OP_BAD_INPUT;
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
		cluster_node_t *found;

		if (cluster->node[i].active) {
			/* Sanity check for duplicates that are active */
			found = rbtree_finddata(cluster->used_nodes, &cluster->node[i]);
			rad_assert(found);
			rad_assert(found->active);
			rad_assert(found->id == i);
		}
#endif

		if (!active[i] && cluster->node[i].active) SET_INACTIVE(&cluster->node[i]);
	}

	cluster->remapping = false;
	cluster->last_updated = time(NULL);

	/*
	 *	Sanity checks
	 */
	rad_assert(rbtree_num_elements(cluster->used_nodes) == total);
	rad_assert(((talloc_array_length(cluster->node) - 1) - rbtree_num_elements(cluster->used_nodes)) ==
		   fr_fifo_num_elements(cluster->free_nodes));

	return CLUSTER_OP_SUCCESS;
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
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static int cluster_map_node_validate(redisReply *node, int map_idx, int node_idx)
{
	fr_ipaddr_t ipaddr;

	if (node->type != REDIS_REPLY_ARRAY) {
		fr_strerror_printf("Cluster map %i node %i is wrong type, expected array got %s",
				   map_idx, node_idx,
				   fr_int2str(redis_reply_types, node->element[1]->type, "<UNKNOWN>"));
		return CLUSTER_OP_BAD_INPUT;
	}

	if (node->elements != 2) {
		fr_strerror_printf("Cluster map %i node %i has incorrect number of elements, expected 2 got %zu",
				   map_idx, node_idx, node->elements);
		return CLUSTER_OP_BAD_INPUT;
	}

	if (node->element[0]->type != REDIS_REPLY_STRING) {
		fr_strerror_printf("Cluster map %i node %i ip address is wrong type, expected string got %s",
				   map_idx, node_idx,
				   fr_int2str(redis_reply_types, node->element[0]->type, "<UNKNOWN>"));
		return CLUSTER_OP_BAD_INPUT;
	}

	if (fr_pton(&ipaddr, node->element[0]->str, node->element[0]->len, AF_UNSPEC, false) < 0) {
		return CLUSTER_OP_BAD_INPUT;
	}

	if (node->element[1]->type != REDIS_REPLY_INTEGER) {
		fr_strerror_printf("Cluster map %i node %i port is wrong type, expected integer got %s",
				   map_idx, node_idx,
				   fr_int2str(redis_reply_types, node->element[1]->type, "<UNKNOWN>"));
		return CLUSTER_OP_BAD_INPUT;
	}

	if (node->element[1]->integer < 0) {
		fr_strerror_printf("Cluster map %i node %i port is too low, expected >= 0 got %lli",
				   map_idx, node_idx, node->element[1]->integer);
		return CLUSTER_OP_BAD_INPUT;
	}

	if (node->element[1]->integer > UINT16_MAX) {
		fr_strerror_printf("Cluster map %i node %i port is too high, expected <= " STRINGIFY(UINT16_MAX)" "
				   "got %lli", map_idx, node_idx, node->element[1]->integer);
		return CLUSTER_OP_BAD_INPUT;
	}

	return CLUSTER_OP_SUCCESS;
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
 *	- CLUSTER_OP_IGNORED if 'cluster slots' returned an error (indicating clustering not supported).
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_FAILED if issuing the command resulted in an error.
 *	- CLUSTER_OP_NO_CONNECTION connection failure.
 *	- CLUSTER_OP_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static cluster_rcode_t cluster_map_get(redisReply **out, fr_redis_conn_t *conn)
{
	redisReply	*reply;
	size_t		i = 0;

	*out = NULL;

	reply = redisCommand(conn->handle, "cluster slots");
	switch (fr_redis_command_status(conn, reply)) {
	case REDIS_RCODE_RECONNECT:
		fr_redis_reply_free(reply);
		fr_strerror_printf("No connections available");
		return CLUSTER_OP_NO_CONNECTION;

	case REDIS_RCODE_ERROR:
	default:
		if (reply && reply->type == REDIS_REPLY_ERROR) {
			fr_redis_reply_free(reply);
			fr_strerror_printf("%.*s", (int)reply->len, reply->str);
			return CLUSTER_OP_IGNORED;
		}
		fr_strerror_printf("Unknown client error");
		return CLUSTER_OP_FAILED;

	case REDIS_RCODE_SUCCESS:
		break;
	}

	if (reply->type != REDIS_REPLY_ARRAY) {
		fr_strerror_printf("Bad response to \"cluster slots\" command, expected array got %s",
				   fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
		return CLUSTER_OP_BAD_INPUT;
	}

	/*
	 *	Clustering configured but no slots set
	 */
	if (reply->elements == 0) {
		fr_strerror_printf("Empty response to \"cluster slots\" command (zero length array)");
		return CLUSTER_OP_BAD_INPUT;
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
				   	   i, fr_int2str(redis_reply_types, map->type, "<UNKNOWN>"));
		error:
			fr_redis_reply_free(reply);
			return CLUSTER_OP_BAD_INPUT;
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
					   i, fr_int2str(redis_reply_types, map->element[0]->type, "<UNKNOWN>"));
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
					   i, fr_int2str(redis_reply_types, map->element[1]->type, "<UNKNOWN>"));
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

	return CLUSTER_OP_SUCCESS;
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
 *	- CLUSTER_OP_IGNORED if 'cluster slots' returned an error (indicating clustering not supported).
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_FAILED if issuing the 'cluster slots' command resulted in a protocol error.
 *	- CLUSTER_OP_NO_CONNECTION connection failure.
 *	- CLUSTER_OP_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static cluster_rcode_t cluster_remap(REQUEST *request, fr_redis_cluster_t *cluster, fr_redis_conn_t *conn)
{
	time_t		now;
	redisReply	*map;
	cluster_rcode_t	ret;
	size_t		i, j;

	/*
	 *	If the cluster was remapped very recently, or is being
	 *	remapped it's unlikely that it needs remapping again.
	 */
	if (cluster->remapping) {
	in_progress:
		RDEBUG("Cluster remapping in progress, ignoring remap request");
		return CLUSTER_OP_IGNORED;
	}

	now = time(NULL);
	if (now == cluster->last_updated) {
	too_soon:
		RDEBUG("Cluster was updated less than a second ago, ignoring remap request");
		return CLUSTER_OP_IGNORED;
	}

	RINFO("Initiating cluster remap");

	/*
	 *	Remap the cluster
	 */
	ret = cluster_map_get(&map, conn);
	switch (ret) {
	case CLUSTER_OP_BAD_INPUT:		/* Validation error */
	case CLUSTER_OP_NO_CONNECTION:		/* Connection error */
	case CLUSTER_OP_FAILED:			/* Error issuing command */
		return ret;

	case CLUSTER_OP_IGNORED:		/* Clustering not enabled, or not supported */
		cluster->remap_needed = false;
		return CLUSTER_OP_IGNORED;

	case CLUSTER_OP_SUCCESS:		/* Success */
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
		goto in_progress;
	}
	if (now == cluster->last_updated) {
		pthread_mutex_unlock(&cluster->mutex);
		goto too_soon;
	}
	ret = cluster_map_apply(cluster, map);
	if (ret == CLUSTER_OP_SUCCESS) cluster->remap_needed = false;	/* Change on successful remap */
	pthread_mutex_unlock(&cluster->mutex);

	fr_redis_reply_free(map);	/* Free the map */
	if (ret < 0) return CLUSTER_OP_FAILED;

	return CLUSTER_OP_SUCCESS;
}

/** Retrieve or associate a node with the server indicated in the redirect
 *
 * @note Errors may be retrieved with fr_strerror().
 *
 * @param[out] out Where to write the node representing the redirect server.
 * @param[in] cluster to draw node from.
 * @param[in] reply Redis reply containing the redirect information.
 * @return
 *	- CLUSTER_OP_SUCCESS on success.
 *	- CLUSTER_OP_FAILED no more nodes available.
 *	- CLUSTER_OP_NO_CONNECTION connection failure.
 *	- CLUSTER_OP_BAD_INPUT on validation failure (bad data returned from Redis).
 */
static cluster_rcode_t cluster_redirect(cluster_node_t **out, fr_redis_cluster_t *cluster, redisReply *reply)
{
	cluster_node_t		find, *found, *spare;
	fr_redis_conn_t		*rconn;

	uint16_t		key;

	memset(&find, 0, sizeof(find));

	*out = NULL;

	if (cluster_node_conf_from_redirect(&key, &find.addr, reply) < 0) return CLUSTER_OP_FAILED;

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
		return CLUSTER_OP_SUCCESS;
	}

	/*
	 *	Otherwise grab a free node and try and connect
	 *	it to the server we were redirected to.
	 */
	spare = fr_fifo_peek(cluster->free_nodes);
	if (!spare) {
		fr_strerror_printf("Reached maximum connected nodes");
		pthread_mutex_unlock(&cluster->mutex);
		return CLUSTER_OP_FAILED;
	}
	spare->pending_addr = find.addr;	/* Set the config to be applied */
	if (cluster_node_connect(cluster, spare) < 0) {
		pthread_mutex_unlock(&cluster->mutex);
		return CLUSTER_OP_NO_CONNECTION;
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
	rconn = fr_connection_get(found->pool);
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
		return CLUSTER_OP_NO_CONNECTION;
	}
	fr_connection_release(found->pool, rconn);
	*out = found;

	return CLUSTER_OP_SUCCESS;
}

/** Walk all used pools adding them to the live node list
 *
 * @param context Where to write the node we found.
 * @param data node to check.
 * @return
 *	- 0 continue walking.
 *	- -1 found suitable node.
 */
static int _cluster_pool_walk(void *context, void *data)
{
	cluster_nodes_live_t	*live = context;
	cluster_node_t		*node = data;

	rad_assert(node->pool);

	if (live->skip == node->id) return 0;	/* Skip the dead node */

	live->node[live->next].pool_state = fr_connection_pool_state(node->pool);
	live->node[live->next++].id = node->id;

	return 0;
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
static int cluster_node_find_live(cluster_node_t **live_node, fr_redis_conn_t **live_conn,
				  REQUEST *request, fr_redis_cluster_t *cluster, cluster_node_t *skip)
{
	uint32_t		i;

	cluster_nodes_live_t	*live;
	struct timeval		now;

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

	rad_assert(live->next);			/* There should be at least one */
	if (live->next == 1) goto no_alts;	/* Weird, but conceivable */

	gettimeofday(&now, NULL);

	/*
	 *	Weighted random selection
	 */
	for (i = 0; (i < cluster->conf->max_alt) && live->next; i++) {
		fr_redis_conn_t 	*conn;
		cluster_node_t		*node;
		redisReply		*reply;
		fr_redis_rcode_t	rcode;
		uint8_t			j;
		int			first, last, pivot;	/* Must be signed for BS */
		unsigned int		find, cumulative = 0;

		RDEBUG3("(Re)assigning node weights:");
		RINDENT();
		/*
		 *	(Re)assign the weights
		 */
		for (j = 0; j < live->next; j++) {
			struct timeval diff;
			uint64_t diff_ms;

			/*
			 *	Failed spawn recently, probably bad
			 */
			if ((((time_t)now.tv_sec - live->node[j].pool_state->last_failed) * 1000) < FAILED_PERIOD) {
				RDEBUG3("Node %i weight: " STRINGIFY(FAILED_WEIGHT), live->node[j].id);
				cumulative += FAILED_WEIGHT;
				live->node[j].cumulative = cumulative;
				continue;
			}

			/*
			 *	Closed recently, probably bad
			 */
			fr_timeval_subtract(&diff, &now, &live->node[j].pool_state->last_closed);
			diff_ms = FR_TIMEVAL_TO_MS(&diff);
			if (diff_ms < CLOSED_PERIOD) {
				RDEBUG3("Node %i weight: " STRINGIFY(CLOSED_WEIGHT), live->node[j].id);
				cumulative += CLOSED_WEIGHT;
				live->node[j].cumulative = cumulative;
				continue;
			}

			/*
			 *	Released too long ago, don't know
			 */
			fr_timeval_subtract(&diff, &now, &live->node[j].pool_state->last_released);
			diff_ms = FR_TIMEVAL_TO_MS(&diff);
			if (diff_ms > RELEASED_PERIOD) {
				RDEBUG3("Node %i weight: " STRINGIFY(RELEASED_MIN_WEIGHT), live->node[j].id);
				cumulative += RELEASED_MIN_WEIGHT;
				live->node[j].cumulative = cumulative;
				continue;
			}

			/*
			 *	Released not long ago, might be ok.
			 */
			cumulative += RELEASED_MIN_WEIGHT + (RELEASED_PERIOD - diff_ms);
			RDEBUG3("Node %i weight: %" PRIu64, live->node[j].id,
				(RELEASED_MIN_WEIGHT + (RELEASED_PERIOD - diff_ms)));
			live->node[j].cumulative = cumulative;
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
		 *	Resolve the index to the actual node
		 *	We use IDs to save memory...
		 */
		node = &cluster->node[live->node[pivot].id];
		rad_assert(live->node[pivot].id == node->id);

		RDEBUG2("Selected node %i (using random value %i)", node->id, find);
		conn = fr_connection_get(node->pool);
		if (!conn) {
			RERROR("No connections available to node %i %s:%i", node->id,
			       node->name, node->addr.port);
		next:
			if (pivot == live->next) {
				live->next--;
				continue;
			}
			memcpy(&live->node[pivot], &live->node[live->next - 1], sizeof(live->node[pivot]));
			live->next--;
			continue;
		}

		RDEBUG2("[%i] Executing command: PING", node->id);
		/*
		 *	Try 'pinging' the node
		 */
		reply = redisCommand(conn->handle, "PING");
		rcode = fr_redis_command_status(conn, reply);
		if (rcode != REDIS_RCODE_SUCCESS) {
			RERROR("[%i] PING failed to %s:%i: %s", node->id, node->name,
			       node->addr.port, fr_strerror());

			if (rcode == REDIS_RCODE_RECONNECT) {
				fr_connection_close(node->pool, conn);
			} else {
				fr_connection_release(node->pool, conn);
			}
			fr_redis_reply_free(reply);
			goto next;
		}

		if (reply->type != REDIS_REPLY_STATUS) {
			RERROR("[%i] Bad PING response from %s:%i, expected status got %s",
			       node->id, node->name, node->addr.port,
			       fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			fr_connection_release(node->pool, conn);
			fr_redis_reply_free(reply);
			goto next;
		}

		RDEBUG2("[%i] Got response: %s", node->id, reply->str);
		fr_redis_reply_free(reply);

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
 * @param[in] instance data of type #cluster_node_t. Holds parameters for establishing new connection.
 * @param[in] timeout The maximum time allowed to complete the connection.
 * @return
 *	- New #fr_redis_conn_t on success.
 *	- NULL on failure.
 */
void *fr_redis_cluster_conn_create(TALLOC_CTX *ctx, void *instance, struct timeval const *timeout)
{
	cluster_node_t	*node = instance;
	fr_redis_conn_t		*conn = NULL;
	redisContext		*handle;
	redisReply		*reply = NULL;

	DEBUG2("%s [%i]: Connecting node to %s:%i",  node->conf->prefix, node->id, node->name, node->addr.port);

	handle = redisConnectWithTimeout(node->name, node->addr.port, *timeout);
	if ((handle != NULL) && handle->err) {
		ERROR("%s [%i]: Connection failed: %s", node->conf->prefix, node->id, handle->errstr);
		redisFree(handle);
		return NULL;
	} else if (!handle) {
		ERROR("%s [%i]: Connection failed", node->conf->prefix, node->id);
		return NULL;
	}

	if (node->conf->password) {
		DEBUG3("%s [%i]: Executing: AUTH %s", node->conf->prefix, node->id, node->conf->password);
		reply = redisCommand(handle, "AUTH %s", node->conf->password);
		if (!reply) {
			ERROR("%s [%i]: Failed authenticating: %s", node->conf->prefix, node->id, handle->errstr);
		error:
			if (reply) fr_redis_reply_free(reply);
			redisFree(handle);
			return NULL;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s [%i]: Failed authenticating: %s", node->conf->prefix,
				      node->id, reply->str);
				goto error;
			}
			fr_redis_reply_free(reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s [%i]: Failed authenticating: %s", node->conf->prefix, node->id, reply->str);
			goto error;

		default:
			ERROR("%s [%i]: Unexpected reply of type %s to AUTH", node->conf->prefix, node->id,
			      fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
			goto error;
		}
	}

	if (node->conf->database) {
		DEBUG3("%s [%i]: Executing: SELECT %i", node->conf->prefix, node->id, node->conf->database);
		reply = redisCommand(handle, "SELECT %i", node->conf->database);
		if (!reply) {
			ERROR("%s [%i]: Failed selecting database %i: %s", node->conf->prefix, node->id,
			      node->conf->database, handle->errstr);
			goto error;
		}

		switch (reply->type) {
		case REDIS_REPLY_STATUS:
			if (strcmp(reply->str, "OK") != 0) {
				ERROR("%s [%i]: Failed selecting database %i: %s", node->conf->prefix, node->id,
				      node->conf->database, reply->str);
				goto error;
			}
			fr_redis_reply_free(reply);
			break;	/* else it's OK */

		case REDIS_REPLY_ERROR:
			ERROR("%s [%i]: Failed selecting database %i: %s", node->conf->prefix, node->id,
			      node->conf->database, reply->str);
			goto error;

		default:
			ERROR("%s [%i]: Unexpected reply of type %s, to SELECT", node->conf->prefix, node->id,
			      fr_int2str(redis_reply_types, reply->type, "<UNKNOWN>"));
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
static cluster_key_slot_t *cluster_slot_by_key(fr_redis_cluster_t *cluster, REQUEST *request,
						uint8_t const *key, size_t key_len)
{
	cluster_key_slot_t *key_slot;

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
		if (RDEBUG_ENABLED2) {
			char *p;

			p = fr_aprints(request, (char const *)key, key_len, '"');
			RDEBUG2("Key \"%s\" -> slot %zu", p, key_slot - cluster->key_slot);
			talloc_free(p);
		}

		return key_slot;
	}
	RDEBUG3("Single node available, skipping key selection");

	return &cluster->key_slot[0];
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
    fr_redis_reply_free(reply);
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
	cluster_node_t		*node;
	cluster_key_slot_t	*key_slot;
	uint8_t			first, i;
	int			used_nodes;

	rad_assert(cluster);
	rad_assert(state);
	rad_assert(conn);

	memset(state, 0, sizeof(*state));

	used_nodes = rbtree_num_elements(cluster->used_nodes);
	if (used_nodes == 0) {
		REDEBUG("No nodes in cluster");
		return REDIS_RCODE_RECONNECT;
	}

again:
	key_slot = cluster_slot_by_key(cluster, request, key, key_len);

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
			*conn = fr_connection_get(node->pool);
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
	*conn = fr_connection_get(node->pool);
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
		if (cluster_remap(request, cluster, *conn) == CLUSTER_OP_SUCCESS) {
			fr_connection_release(node->pool, *conn);
			goto again;	/* New map, try again */
		}
		RDEBUG2("%s", fr_strerror());
	}

	state->node = node;
	state->key = key;
	state->key_len = key_len;

	RDEBUG2("[%i] >>> Using cluster node %s:%i", state->node->id, state->node->name, state->node->addr.port);

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
	rad_assert(state && state->node && state->node->pool);
	rad_assert(conn && *conn);

 	RDEBUG2("[%i] <<< Command returned: %s", state->node->id, fr_int2str(redis_rcodes, status, "<UNKNOWN>"));

	/*
	 *	Caller indicated we should close the connection
	 */
	if (state->close_conn) {
		RDEBUG2("[%i] Connection no longer viable, closing it", state->node->id);
		fr_connection_close(state->node->pool, *conn);
		*conn = NULL;
		state->close_conn = false;
	}

	/*
	 *	If we have a proven live connection, and something
	 *	has set the remap_needed flag, do that now before
	 *	releasing the connection.
	 */
	if (cluster->remap_needed) switch(status) {
	case REDIS_RCODE_MOVE:		/* We're going to remap anyway */
	case REDIS_RCODE_RECONNECT:	/* The connection's dead */
		break;

	default:
		/*
		 *	Remap the cluster. On success, will clear the
		 *	remap_needed flag.
		 */
		if (cluster_remap(request, cluster, *conn) != CLUSTER_OP_SUCCESS) RDEBUG2("%s", fr_strerror());
	}

	/*
	 *	Check the result of the last redis command, and do
	 *	something appropriate.
	 */
	switch (status) {
	case REDIS_RCODE_SUCCESS:
		fr_connection_release(state->node->pool, *conn);
		*conn = NULL;
		return REDIS_RCODE_SUCCESS;

	/*
	 *	Command error, not fixable.
	 */
	case REDIS_RCODE_ERROR:
		REDEBUG("[%i] Command failed: %s", state->node->id, fr_strerror());
		fr_connection_release(state->node->pool, *conn);
		*conn = NULL;
		return REDIS_RCODE_ERROR;

	/*
	 *	Cluster's unstable, try again.
	 */
	case REDIS_RCODE_TRY_AGAIN:
		if (state->retries++ >= cluster->conf->max_retries) {
			REDEBUG("[%i] Hit maximum retry attempts", state->node->id);
			fr_connection_release(state->node->pool, *conn);
			*conn = NULL;
			return REDIS_RCODE_ERROR;
		}

		if (!*conn) *conn = fr_connection_get(state->node->pool);

		if (FR_TIMEVAL_TO_MS(&cluster->conf->retry_delay)) {
			struct timespec ts;

			ts.tv_sec = cluster->conf->retry_delay.tv_sec;
			ts.tv_nsec = cluster->conf->retry_delay.tv_usec * 1000;
			nanosleep(&ts, NULL);
		}
		goto try_again;

	/*
	 *	Connection's dead, check to see if we can switch nodes,
	 *	or, failing that, reconnect the connection.
	 */
	case REDIS_RCODE_RECONNECT:
	{
		cluster_key_slot_t *key_slot;

		RERROR("[%i] Failed communicating with %s:%i: %s", state->node->id, state->node->name,
		       state->node->addr.port, fr_strerror());

		fr_connection_close(state->node->pool, *conn);	/* He's dead jim */

		if (state->reconnects++ > state->in_pool) {
			REDEBUG("[%i] Hit maximum reconnect attempts", state->node->id);
			cluster->remap_needed = true;
			return REDIS_RCODE_RECONNECT;
		}

		/*
		 *	Refresh the key slot
		 */
		key_slot = cluster_slot_by_key(cluster, request, state->key, state->key_len);
		state->node = &cluster->node[key_slot->master];

		*conn = fr_connection_get(state->node->pool);
		if (!*conn) {
			REDEBUG("[%i] No connections available for %s:%i", state->node->id, state->node->name,
				state->node->addr.port);
			return REDIS_RCODE_RECONNECT;
		}

		state->retries = 0;
	}
		goto try_again;

	/*
	 *	-MOVE is treated identically to -ASK, except it may
	 *	trigger a cluster remap.
	 */
	case REDIS_RCODE_MOVE:
		if (cluster_remap(request, cluster, *conn) != CLUSTER_OP_SUCCESS) RDEBUG2("%s", fr_strerror());
		/* FALL-THROUGH */

	/*
	 *	-ASK process a redirect.
	 */
	case REDIS_RCODE_ASK:
	{
		cluster_node_t *new;

		fr_connection_release(state->node->pool, *conn);	/* Always release the old connection */

		RDEBUG("[%i] Processing redirect \"%s\"", state->node->id, (*reply)->str);
		if (state->redirects++ >= cluster->conf->max_redirects) {
			REDEBUG("[%i] Reached max_redirects (%i)", state->node->id, state->redirects);
			return REDIS_RCODE_ERROR;
		}

		switch (cluster_redirect(&new, cluster, *reply)) {
		case CLUSTER_OP_SUCCESS:
			if (new == state->node) {
				REDEBUG("[%i] %s:%i issued redirect to itself", state->node->id,
					state->node->name, state->node->addr.port);
				return REDIS_RCODE_ERROR;
			}

			RDEBUG("[%i] Redirected from %s:%i to [%i] %s:%i", state->node->id, state->node->name,
			       state->node->addr.port, new->id, new->name, new->addr.port);
			state->node = new;

			*conn = fr_connection_get(state->node->pool);
			if (!*conn) return REDIS_RCODE_RECONNECT;

			/*
			 *	Reset these counters, their scope is
			 *	a single node in the cluster.
			 */
			state->reconnects = 0;
			state->retries = 0;
			state->in_pool = fr_connection_pool_state(state->node->pool)->num;
			goto try_again;

		case CLUSTER_OP_NO_CONNECTION:
			cluster->remap_needed = true;
			return REDIS_RCODE_RECONNECT;

		default:
			return REDIS_RCODE_ERROR;
		}
	}
	}

try_again:
	RDEBUG2("[%i] >>> Using cluster node %s:%i", state->node->id, state->node->name, state->node->addr.port);

	fr_redis_reply_free(*reply);
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
 * @param[in] ipaddr of node.
 * @param[in] port of node.
 * @param[in] create Establish a connection to the specified node if it
 *	was previously unknown to the cluster client.
 * @return
 *	- 0 on success.
 *	- -1 if no such node exists.
 */
int fr_redis_cluster_pool_by_node_addr(fr_connection_pool_t **pool, fr_redis_cluster_t *cluster,
				       fr_ipaddr_t *ipaddr, uint16_t port, bool create)
{
	cluster_node_t	find, *found;

	find.addr.ipaddr = *ipaddr;
	find.addr.port = port;

	pthread_mutex_lock(&cluster->mutex);
	found = rbtree_finddata(cluster->used_nodes, &find);
	if (!found) {
		cluster_node_t *spare;
		char buffer[INET6_ADDRSTRLEN];
		char const *hostname;

		if (!create) {
			pthread_mutex_unlock(&cluster->mutex);

			hostname = inet_ntop(ipaddr->af, &ipaddr->ipaddr, buffer, sizeof(buffer));
			rad_assert(hostname);	/* addr.ipaddr is probably corrupt */;
			fr_strerror_printf("No existing node found with address %s, port %i", hostname, port);
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
	rad_assert(((talloc_array_length(cluster->node) - 1) - rbtree_num_elements(cluster->used_nodes)) ==
		   fr_fifo_num_elements(cluster->free_nodes));
	pthread_mutex_unlock(&cluster->mutex);

	*pool = found->pool;

	return 0;
}

#ifdef HAVE_PTHREAD_H
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
#endif

/** Allocate and initialise a new cluster structure
 *
 * This holds all the data necessary to manage a pool of pools for a specific redis cluster.
 *
 * @note Will not error out unless cs.pool.start > 0.  This is consistent with other pool based
 *	modules/code.
 *
 * @param ctx to link the lifetime of the cluster structure to.
 * @param module Configuration section to search for 'server' conf pairs in.
 * @param conf Base redis server configuration. Cluster nodes share database number and password.
 * @return
 *	- New #fr_redis_cluster_t on success.
 *	- NULL on error.
 */
fr_redis_cluster_t *fr_redis_cluster_alloc(TALLOC_CTX *ctx, CONF_SECTION *module, fr_redis_conf_t *conf)
{
	uint8_t			i;
	uint16_t		s;

	CONF_SECTION		*mycs;
	char const		*cs_name1, *cs_name2;

	CONF_PAIR		*cp;
	int			af = AF_UNSPEC;		/* AF of first server */

	int			num_nodes;
	fr_redis_cluster_t	*cluster;

	cluster = talloc_zero(NULL, fr_redis_cluster_t);
	if (!cluster) {
		ERROR("%s: Out of memory", conf->prefix);
		return NULL;
	}

	if (!conf->prefix) {
		cs_name1 = cf_section_name1(module);
		cs_name2 = cf_section_name2(module);
		if (!cs_name2) cs_name2 = cs_name1;
		conf->prefix = talloc_asprintf(conf, "rlm_%s (%s)", cs_name1, cs_name2);
	}

	/*
	 *	Ensure we always have a pool section (even if it's empty)
	 */
	mycs = cf_section_sub_find(module, "pool");
	if (!mycs) {
		mycs = cf_section_alloc(module, "pool", NULL);
		cf_section_add(module, mycs);
	}

	if (conf->max_nodes == UINT8_MAX) {
		ERROR("%s: Maximum number of connected nodes allowed is %i", conf->prefix, UINT8_MAX - 1);
		talloc_free(cluster);
		return NULL;
	}

	if (conf->max_nodes == 0) {
		ERROR("%s: Minimum number of nodes allowed is 1", conf->prefix);
		talloc_free(cluster);
		return NULL;
	}

	cp = cf_pair_find(module, "server");
	if (!cp) {
		ERROR("%s: No servers configured", conf->prefix);
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
	if (fr_link_talloc_ctx_free(ctx, cluster) < 0) {
	oom:
		ERROR("%s: Out of memory", conf->prefix);

	error:
		talloc_free(cluster);
		return NULL;
	}

	cluster->node = talloc_zero_array(cluster, cluster_node_t, conf->max_nodes + 1);
	if (!cluster->node) goto oom;

	cluster->used_nodes = rbtree_create(cluster, _cluster_node_cmp, NULL, 0);
	cluster->free_nodes = fr_fifo_create(cluster, conf->max_nodes, NULL);
	cluster->conf = conf;

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&cluster->mutex, NULL);
	talloc_set_destructor(cluster, _fr_redis_cluster_free);
#endif

	/*
	 *	Node id 0 is reserved, so we can detect misconfigured
	 *	clusters.
	 */
	for (i = 1; i < (cluster->conf->max_nodes + 1); i++) {
		cluster->node[i].id = i;
		cluster->node[i].conf = conf;

		/* Push them all into the queue */
		fr_fifo_push(cluster->free_nodes, &cluster->node[i]);
	}

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
		cluster_node_t	*node;
		fr_redis_conn_t	*conn;
		redisReply	*map;
		size_t		j, k;

		node = fr_fifo_peek(cluster->free_nodes);
		if (!node) {
			ERROR("%s: Number of bootstrap servers exceeds 'max_nodes'", conf->prefix);
			goto error;
		}

		server = cf_pair_value(cp);
		if (fr_pton_port(&node->pending_addr.ipaddr, &node->pending_addr.port, server,
				 talloc_array_length(server) - 1, af, true) < 0) {
			ERROR("%s: Failed parsing server \"%s\": %s", conf->prefix, server, fr_strerror());
			goto error;
		}
		if (!node->pending_addr.port) node->pending_addr.port = conf->port;

		if (cluster_node_connect(cluster, node) < 0) {
			WARN("%s: Connecting to %s:%i failed", conf->prefix, node->name, node->pending_addr.port);
			continue;
		}

		if (!rbtree_insert(cluster->used_nodes, node)) {
			WARN("%s: Skipping duplicate bootstrap server \"%s\"", conf->prefix, server);
			continue;
		}
		node->active = true;
		fr_fifo_pop(cluster->free_nodes);

		/*
		 *	Prefer the same IPaddr family as the first node
		 */
		if (af == AF_UNSPEC) af = node->addr.ipaddr.af;

		/*
		 *	Fine to leave this node configured, if we do find
		 *	a live node, and it's not in the map, it'll be cleared out.
		 */
		conn = fr_connection_get(node->pool);
		if (!conn) {
			WARN("%s: Can't contact bootstrap server \"%s\"", conf->prefix, server);
			continue;
		}

		switch (cluster_map_get(&map, conn)) {
		/*
		 *	We got a valid map! See if we can apply it...
		 */
		case CLUSTER_OP_SUCCESS:
			fr_connection_release(node->pool, conn);

			INFO("%s: Cluster map consists of %zu key ranges", conf->prefix, map->elements);
			for (j = 0; j < map->elements; j++) {
				redisReply *map_node = map->element[j];

				INFO("%s: %zu - keys %lli-%lli", conf->prefix, j,
				     map_node->element[0]->integer,
				     map_node->element[1]->integer);
				INFO("%s:  master: %s:%lli", conf->prefix,
				     map_node->element[2]->element[0]->str,
				     map_node->element[2]->element[1]->integer);
				for (k = 3; k < map_node->elements; k++) {
					INFO("%s:  slave%zu: %s:%lli", conf->prefix, k - 3,
					     map_node->element[k]->element[0]->str,
					     map_node->element[k]->element[1]->integer);
				}
			}

			if (cluster_map_apply(cluster, map) < 0) {
				WARN("%s: Applying cluster map failed: %s", conf->prefix, fr_strerror());
				fr_redis_reply_free(map);
				continue;
			}
			fr_redis_reply_free(map);

			return cluster;

		/*
		 *	Unusable bootstrap node
		 */
		case CLUSTER_OP_BAD_INPUT:
			WARN("%s: Bootstrap server \"%s\" returned invalid data: %s",
			     conf->prefix, server, fr_strerror());
			fr_connection_release(node->pool, conn);
			continue;

		case CLUSTER_OP_NO_CONNECTION:
			WARN("%s: Can't contact bootstrap server \"%s\": %s",
			     conf->prefix, server, fr_strerror());
			fr_connection_close(node->pool, conn);
			continue;

		/*
		 *	Clustering not enabled, or not supported,
		 *	by this node, skip it and check the others.
		 */
		case CLUSTER_OP_FAILED:
		case CLUSTER_OP_IGNORED:
			DEBUG2("%s: Bootstrap server \"%s\" returned: %s",
			       conf->prefix, server, fr_strerror());
			fr_connection_release(node->pool, conn);
			break;
		}
	} while ((cp = cf_pair_find_next(module, cp, "server")));

	/*
	 *	Catch pool.start != 0
	 */
	num_nodes = rbtree_num_elements(cluster->used_nodes);
	if (!num_nodes) {
		ERROR("%s: Can't contact any bootstrap servers", conf->prefix);
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
