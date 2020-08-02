#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/pool.h
 * @brief API to manage pools of persistent connections to external resources.
 *
 * @copyright 2012 The FreeRADIUS server project
 * @copyright 2012 Alan DeKok (aland@deployingradius.com)
 */
RCSIDH(pool_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_pool_s fr_pool_t;
typedef struct fr_pool_state_s fr_pool_state_t;

#ifdef __cplusplus
}
#endif

#include <freeradius-devel/server/stats.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fr_pool_state_s {
	uint32_t	pending;		//!< Number of pending open connections.
	fr_time_t	last_checked;		//!< Last time we pruned the connection pool.
	fr_time_t	last_spawned;		//!< Last time we spawned a connection.
	fr_time_t	last_failed;		//!< Last time we tried to spawn a connection but failed.
	fr_time_t	last_throttled;		//!< Last time we refused to spawn a connection because
						//!< the last connection failed, or we were already spawning
						//!< a connection.
	fr_time_t	last_at_max;		//!< Last time we hit the maximum number of allowed
						//!< connections.
	fr_time_t	last_released;		//!< Last time a connection was released.
	fr_time_t	last_closed;		//!< Last time a connection was closed.

	fr_time_t	last_held_min;		//!< Last time we warned about a low latency event.
	fr_time_t	last_held_max;		//!< Last time we warned about a high latency event.

	uint32_t	next_delay;    	 	//!< The next delay time.  cleanup.  Initialized to
						//!< cleanup_interval, and decays from there.

	uint64_t	count;			//!< Number of connections spawned over the lifetime
						//!< of the pool.
	uint32_t       	num;			//!< Number of connections in the pool.
	uint32_t	active;	 		//!< Number of currently reserved connections.

	bool		reconnecting;		//!< We are currently reconnecting the pool.
};

/** Alter the opaque data of a connection pool during reconnection event
 *
 * This function will be called whenever we have been signalled to
 * reconnect all the connections in a pool.
 *
 * It is called at a point where we have determined that no connection
 * spawning is in progress, so it is safe to modify any pointers or
 * memory associated with the opaque data.
 *
 * @param[in] pool being reconnected.
 * @param[in] opaque pointer passed to fr_pool_init.
 */
typedef void (*fr_pool_reconnect_t)(fr_pool_t *pool, void *opaque);

/** Create a new connection handle
 *
 * This function will be called whenever the connection pool manager needs
 * to spawn a new connection, and on reconnect.
 *
 * Memory should be talloced in the provided context to hold the module's
 * connection structure. The context is allocated in the NULL context,
 * but will be freed when fr_pool_t is freed via some internal magic.
 *
 * There is no delete callback, so operations such as closing sockets and
 * freeing library connection handles should be done by a destructor attached
 * to memory allocated beneath the provided ctx.
 *
 * @note A function pointer matching this prototype must be passed
 *	to fr_pool_init.
 *
 * @param[in,out] ctx to allocate memory in.
 * @param[in] opaque pointer passed to fr_pool_init.
 * @param[in] timeout The maximum time in ms the function has to complete
 *	the connection.  Should be enforced by the function.
 * @return
 *	- NULL on error.
 *	- A connection handle on success.
 */
typedef void *(*fr_pool_connection_create_t)(TALLOC_CTX *ctx, void *opaque, fr_time_delta_t timeout);

/** Check a connection handle is still viable
 *
 * Should check the state  of a connection handle.
 *
 * @note NULL may be passed to fr_pool_init, if there is no way to check
 * the state of a connection handle.
 * @note Not currently use by connection pool manager.
 * @param[in] opaque pointer passed to fr_pool_init.
 * @param[in] connection handle returned by fr_pool_connection_create_t.
 * @return
 *	- 0 on success.
 *	- < 0 on error or if the connection is unusable.
 */
typedef int (*fr_pool_connection_alive_t)(void *opaque, void *connection);

/*
 *	Pool allocation/initialisation
 */
fr_pool_t	*fr_pool_init(TALLOC_CTX *ctx,
			      CONF_SECTION const *cs,
			      void *opaque,
			      fr_pool_connection_create_t c,
			      fr_pool_connection_alive_t a,
			      char const *log_prefix);
int		fr_pool_start(fr_pool_t *pool);

fr_pool_t	*fr_pool_copy(TALLOC_CTX *ctx, fr_pool_t *pool, void *opaque);


/*
 *	Pool get/set
 */
void	fr_pool_enable_triggers(fr_pool_t *pool,
					   char const *trigger_prefix, VALUE_PAIR *vp);

fr_time_delta_t fr_pool_timeout(fr_pool_t *pool);

int fr_pool_start_num(fr_pool_t *pool);

void const *fr_pool_opaque(fr_pool_t *pool);

void	fr_pool_ref(fr_pool_t *pool);

fr_pool_state_t const *fr_pool_state(fr_pool_t *pool);

void	fr_pool_reconnect_func(fr_pool_t *pool, fr_pool_reconnect_t reconnect);

/*
 *	Pool management
 */
int	fr_pool_reconnect(fr_pool_t *pool, REQUEST *request);

void	fr_pool_free(fr_pool_t *pool);

/*
 *	Connection lifecycle
 */
void	*fr_pool_connection_get(fr_pool_t *pool, REQUEST *request);

void	fr_pool_connection_release(fr_pool_t *pool, REQUEST *request, void *conn);

void	*fr_pool_connection_reconnect(fr_pool_t *pool, REQUEST *request, void *conn);

int	fr_pool_connection_close(fr_pool_t *pool, REQUEST *request, void *conn);

#ifdef __cplusplus
}
#endif
