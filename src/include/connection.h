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
#ifndef FR_CONNECTION_H
#define FR_CONNECTION_H
/**
 * $Id$
 *
 * @file connection.h
 * @brief Structures, prototypes and global variables for server connection pools.
 *
 * @copyright 2012  The FreeRADIUS server project
 * @copyright 2012  Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(connection_h, "$Id$")

#include <freeradius-devel/conffile.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_connection_pool_t fr_connection_pool_t;

typedef struct fr_connection_pool_state {
	uint32_t	pending;		//!< Number of pending open connections.
	time_t		last_checked;		//!< Last time we pruned the connection pool.
	time_t		last_spawned;		//!< Last time we spawned a connection.
	time_t		last_failed;		//!< Last time we tried to spawn a connection but failed.
	time_t		last_throttled;		//!< Last time we refused to spawn a connection because
						//!< the last connection failed, or we were already spawning
						//!< a connection.
	time_t		last_at_max;		//!< Last time we hit the maximum number of allowed
						//!< connections.
	struct timeval	last_released;		//!< Last time a connection was released.
	struct timeval	last_closed;		//!< Last time a connection was closed.

	int		next_delay;    	 	//!< The next delay time.  cleanup.  Initialized to
						//!< cleanup_interval, and decays from there.

	uint64_t	count;			//!< Number of connections spawned over the lifetime
						//!< of the pool.
	uint32_t       	num;			//!< Number of connections in the pool.
	uint32_t	active;	 		//!< Number of currently reserved connections.

	bool		reconnecting;		//!< We are currently reconnecting the pool.
} fr_connection_pool_state_t;

/** Alter the opaque data of a connection pool during reconnection event
 *
 * This function will be called whenever we have been signalled to
 * reconnect all the connections in a pool.
 *
 * It is called at a point where we have determined that no connection
 * spawning is in progress, so it is safe to modify any pointers or
 * memory associated with the opaque data.
 *
 * @param[in,out] opaque pointer passed to fr_connection_pool_init.
 */
typedef void (*fr_connection_pool_reconnect_t)(void *opaque);

/** Create a new connection handle
 *
 * This function will be called whenever the connection pool manager needs
 * to spawn a new connection, and on reconnect.
 *
 * Memory should be talloced in the parent context to hold the module's
 * connection structure. The parent context is allocated in the NULL
 * context, but will be freed when fr_connection_t is freed.
 *
 * There is no delete callback, so operations such as closing sockets and
 * freeing library connection handles should be done by a destructor attached
 * to memory allocated beneath ctx.
 *
 * @note A function pointer matching this prototype must be passed
 * to fr_connection_pool_init.
 *
 * @param[in,out] ctx to allocate memory in.
 * @param[in] opaque pointer passed to fr_connection_pool_init.
 * @param[in] timeout The maximum time in ms the function has to complete
 *	the connection.  Should be enforced by the function.
 * @return
 *	- NULL on error.
 *	- A connection handle on success.
 */
typedef void *(*fr_connection_create_t)(TALLOC_CTX *ctx, void *opaque, struct timeval const *timeout);

/** Check a connection handle is still viable
 *
 * Should check the state  of a connection handle.
 *
 * @note NULL may be passed to fr_connection_pool_init, if there is no way to check
 * the state of a connection handle.
 * @note Not currently use by connection pool manager.
 * @param[in] opaque pointer passed to fr_connection_pool_init.
 * @param[in] connection handle returned by fr_connection_create_t.
 * @return
 *	- 0 on success.
 *	- < 0 on error or if the connection is unusable.
 */
typedef int (*fr_connection_alive_t)(void *opaque, void *connection);

/*
 *	Pool allocation/initialisation
 */
fr_connection_pool_t	*fr_connection_pool_init(TALLOC_CTX *ctx,
						 CONF_SECTION *cs,
						 void *opaque,
						 fr_connection_create_t c,
						 fr_connection_alive_t a,
						 char const *log_prefix,
						 char const *trigger_prefix);

fr_connection_pool_t	*fr_connection_pool_module_init(CONF_SECTION *module,
							void *opaque,
							fr_connection_create_t c,
							fr_connection_alive_t a,
							char const *prefix);

fr_connection_pool_t	*fr_connection_pool_copy(TALLOC_CTX *ctx, fr_connection_pool_t *pool, void *opaque);


/*
 *	Pool get/set
 */
struct timeval fr_connection_pool_timeout(fr_connection_pool_t *pool);

void const *fr_connection_pool_opaque(fr_connection_pool_t *pool);

fr_connection_pool_state_t const *fr_connection_pool_state(fr_connection_pool_t *pool);

void	fr_connection_pool_reconnect_func(fr_connection_pool_t *pool, fr_connection_pool_reconnect_t reconnect);

/*
 *	Pool management
 */
int	fr_connection_pool_reconnect(fr_connection_pool_t *pool);

void	fr_connection_pool_free(fr_connection_pool_t *pool);

/*
 *	Connection lifecycle
 */
void	*fr_connection_get(fr_connection_pool_t *pool);

void	fr_connection_release(fr_connection_pool_t *pool, void *conn);

void	*fr_connection_reconnect(fr_connection_pool_t *pool, void *conn);

int	fr_connection_close(fr_connection_pool_t *pool, void *conn);

#ifdef __cplusplus
}
#endif

#endif /* FR_CONNECTION_H*/
