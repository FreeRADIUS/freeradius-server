/*
 *   This program is free software; you can redistribute it and/or modify
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
 * @file cluster.h
 * @brief Common functions for interacting with Redis cluster via Hiredis
 *
 * @author Arran Cudbard-Bell
 *
 * @copyright 2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2015 Network RADIUS (info@networkradius.com)
 * @copyright 2015 The FreeRADIUS server project
 */

#ifndef LIBFREERADIUS_REDIS_CLUSTER_H
#define	LIBFREERADIUS_REDIS_CLUSTER_H

RCSIDH(cluster_h, "$Id$")

#include <freeradius-devel/server/pool.h>

typedef struct fr_redis_cluster fr_redis_cluster_t;
typedef struct fr_redis_cluster_key_slot_s fr_redis_cluster_key_slot_t;
typedef struct fr_redis_cluster_node_s fr_redis_cluster_node_t;

/** Redis connection sequence state
 *
 * Tracks how many operations we've performed attempting to execute a single command.
 *
 * Used by callers of the cluster code.  Allocated on the stack and passed to
 * #fr_redis_cluster_state_init and #fr_redis_cluster_state_next.
 */
typedef struct {
	bool			close_conn;	//!< Set by caller of fr_redis_cluster_state_next,
						//!< to indicate that connection must be closed, as it's
						//!< now in an unknown state.

	uint8_t const		*key;		//!< Key we performed hashing on.
	size_t			key_len;	//!< Length of the key.

	fr_redis_cluster_node_t	*node;		//!< Node we're communicating with.
	uint32_t		redirects;	//!< How many redirects have we followed.

	uint32_t		retries;	//!< How many times we've received TRYAGAIN
	uint32_t		in_pool;	//!< How many available connections are there in the pool.
	uint32_t		reconnects;	//!< How many connections we've tried in this pool.
} fr_redis_cluster_state_t;

/** Return values for internal functions
 */
typedef enum {
	FR_REDIS_CLUSTER_RCODE_IGNORED		= 1,	//!< Operation ignored.
	FR_REDIS_CLUSTER_RCODE_SUCCESS		= 0,	//!< Operation completed successfully.
	FR_REDIS_CLUSTER_RCODE_FAILED		= -1,	//!< Operation failed.
	FR_REDIS_CLUSTER_RCODE_NO_CONNECTION	= -2,	//!< Operation failed because we couldn't find
							//!< a live connection.
	FR_REDIS_CLUSTER_RCODE_BAD_INPUT	= -3	//!< Validation error.
} fr_redis_cluster_rcode_t;

extern fr_table_num_sorted_t const fr_redis_cluster_rcodes_table[];
extern size_t fr_redis_cluster_rcodes_table_len;

fr_redis_cluster_rcode_t fr_redis_cluster_remap(REQUEST *request, fr_redis_cluster_t *cluster, fr_redis_conn_t *conn);

/*
 *	Callback for the connection pool to create a new connection
 */
void *fr_redis_cluster_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_t timeout);

/*
 *	Functions to resolve a key to a cluster node
 */
fr_redis_cluster_key_slot_t const	*fr_redis_cluster_slot_by_key(fr_redis_cluster_t *cluster, REQUEST *request,
								      uint8_t const *key, size_t key_len);

fr_redis_cluster_node_t const	*fr_redis_cluster_master(fr_redis_cluster_t *cluster,
							 fr_redis_cluster_key_slot_t const *key_slot);

fr_redis_cluster_node_t const	*fr_redis_cluster_slave(fr_redis_cluster_t *cluster,
							fr_redis_cluster_key_slot_t const *key_slot,
							uint8_t slave_num);

int fr_redis_cluster_ipaddr(fr_ipaddr_t *out, fr_redis_cluster_node_t const *node);

int fr_redis_cluster_port(uint16_t *out, fr_redis_cluster_node_t const *node);



/*
 *	Reserve/release connections, follow redirects, reconnect
 *	connections implement retry delays.
 */
fr_redis_rcode_t fr_redis_cluster_state_init(fr_redis_cluster_state_t *state, fr_redis_conn_t **conn,
					     fr_redis_cluster_t *cluster, REQUEST *request,
					     uint8_t const *key, size_t key_len, bool read_only);

fr_redis_rcode_t fr_redis_cluster_state_next(fr_redis_cluster_state_t *state, fr_redis_conn_t **conn,
					     fr_redis_cluster_t *cluster, REQUEST *request,
					     fr_redis_rcode_t status, redisReply **reply);

/*
 *	Useful for running commands over every node, such as PING
 *	or KEYS.
 */
int fr_redis_cluster_pool_by_node_addr(fr_pool_t **pool, fr_redis_cluster_t *cluster,
				       fr_socket_addr_t *node, bool create);
ssize_t fr_redis_cluster_node_addr_by_role(TALLOC_CTX *ctx, fr_socket_addr_t *out[],
					   fr_redis_cluster_t *cluster, bool is_master, bool is_slave);

/*
 *	Initialise a new cluster connection, and perform initial mapping.
 */
bool fr_redis_cluster_min_version(fr_redis_cluster_t *cluster, char const *min_version);

fr_redis_cluster_t *fr_redis_cluster_alloc(TALLOC_CTX *ctx,
					   CONF_SECTION *module,
					   fr_redis_conf_t *conf,
					   bool enable_triggers,
					   char const *log_prefix,
					   char const *trigger_prefix,
					   VALUE_PAIR *trigger_args);

#endif	/* LIBFREERADIUS_REDIS_CLUSTER_H */
