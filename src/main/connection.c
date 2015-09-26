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
 * @file connection.c
 * @brief Handle pools of connections (threads, sockets, etc.)
 * @note This API must be used by all modules in the public distribution that
 * maintain pools of connections.
 *
 * @copyright 2012  The FreeRADIUS server project
 * @copyright 2012  Alan DeKok <aland@deployingradius.com>
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/heap.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

typedef struct fr_connection fr_connection_t;

static int fr_connection_pool_check(fr_connection_pool_t *pool);

#ifndef NDEBUG
#ifdef HAVE_PTHREAD_H
/* #define PTHREAD_DEBUG (1) */
#endif
#endif

/** An individual connection within the connection pool
 *
 * Defines connection counters, timestamps, and holds a pointer to the
 * connection handle itself.
 *
 * @see fr_connection_pool_t
 */
struct fr_connection {
	fr_connection_t	*prev;			//!< Previous connection in list.
	fr_connection_t	*next;			//!< Next connection in list.

	time_t		created;		//!< Time connection was created.
	struct timeval 	last_reserved;		//!< Last time the connection was reserved.

	struct timeval	last_released;  	//!< Time the connection was released.

	uint32_t	num_uses;		//!< Number of times the connection has been reserved.
	uint64_t	number;			//!< Unique ID assigned when the connection is created,
						//!< these will monotonically increase over the
						//!< lifetime of the connection pool.
	void		*connection;		//!< Pointer to whatever the module uses for a connection
						//!< handle.
	bool		in_use;			//!< Whether the connection is currently reserved.

	int		heap;			//!< For the next connection heap.

	bool		needs_reconnecting;	//!< Reconnect this connection before use.

#ifdef PTHREAD_DEBUG
	pthread_t	pthread_id;		//!< When 'in_use == true'.
#endif
};

/** A connection pool
 *
 * Defines the configuration of the connection pool, all the counters and
 * timestamps related to the connection pool, the mutex that stops multiple
 * threads leaving the pool in an inconsistent state, and the callbacks
 * required to open, close and check the status of connections within the pool.
 *
 * @see fr_connection
 */
struct fr_connection_pool_t {
	int		ref;			//!< Reference counter to prevent connection
						//!< pool being freed multiple times.
	uint32_t       	start;			//!< Number of initial connections.
	uint32_t       	min;			//!< Minimum number of concurrent connections to keep open.
	uint32_t       	max;			//!< Maximum number of concurrent connections to allow.
	uint32_t       	spare;			//!< Number of spare connections to try.
	uint32_t       	retry_delay;		//!< seconds to delay re-open after a failed open.
	uint32_t       	cleanup_interval; 	//!< Initial timer for how often we sweep the pool
						//!< for free connections. (0 is infinite).
	int		delay_interval;		//!< When we next do a cleanup.  Initialized to
						//!< cleanup_interval, and increase from there based
						//!< on the delay.
	uint64_t	max_uses;		//!< Maximum number of times a connection can be used
						//!< before being closed.
	uint32_t	max_pending;		//!< Max number of connections to open.
	uint32_t	lifetime;		//!< How long a connection can be open before being
						//!< closed (irrespective of whether it's idle or not).
	uint32_t       	idle_timeout;		//!< How long a connection can be idle before
						//!< being closed.
	struct timeval	connect_timeout;	//!< New connection timeout, enforced by the create
						//!< callback.

	bool		spread;			//!< If true we spread requests over the connections,
						//!< using the connection released longest ago, first.

	fr_heap_t	*heap;			//!< For the next connection heap

	fr_connection_t	*head;			//!< Start of the connection list.
	fr_connection_t *tail;			//!< End of the connection list.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;			//!< Mutex used to keep consistent state when making
						//!< modifications in threaded mode.
	pthread_cond_t	done_spawn;		//!< Threads that need to ensure no spawning is in progress,
						//!< should block on this condition if pending != 0.
	pthread_cond_t	done_reconnecting;	//!< Before calling the create callback, threads should
						//!< block on this condition if reconnecting == true.
#endif

	CONF_SECTION	*cs;			//!< Configuration section holding the section of parsed
						//!< config file that relates to this pool.
	void		*opaque;		//!< Pointer to context data that will be passed to callbacks.

	char const	*log_prefix;		//!< Log prefix to prepend to all log messages created
						//!< by the connection pool code.

	char const	*trigger_prefix;	//!< Prefix to prepend to names of all triggers
						//!< fired by the connection pool code.

	fr_connection_create_t	create;		//!< Function used to create new connections.
	fr_connection_alive_t	alive;		//!< Function used to check status of connections.
	fr_connection_pool_reconnect_t reconnect;	//!< Called during connection pool reconnect.

	fr_connection_pool_state_t state;	//!< Stats and state of the connection pool.
};

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#  define PTHREAD_COND_BROADCAST pthread_cond_broadcast
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#  define PTHREAD_COND_BROADCAST(_x)
#endif

static const CONF_PARSER connection_config[] = {
	{ FR_CONF_OFFSET("start", PW_TYPE_INTEGER, fr_connection_pool_t, start), .dflt = "5" },
	{ FR_CONF_OFFSET("min", PW_TYPE_INTEGER, fr_connection_pool_t, min), .dflt = "5" },
	{ FR_CONF_OFFSET("max", PW_TYPE_INTEGER, fr_connection_pool_t, max), .dflt = "10" },
	{ FR_CONF_OFFSET("spare", PW_TYPE_INTEGER, fr_connection_pool_t, spare), .dflt = "3" },
	{ FR_CONF_OFFSET("uses", PW_TYPE_INTEGER64, fr_connection_pool_t, max_uses), .dflt = "0" },
	{ FR_CONF_OFFSET("lifetime", PW_TYPE_INTEGER, fr_connection_pool_t, lifetime), .dflt = "0" },
	{ FR_CONF_OFFSET("cleanup_delay", PW_TYPE_INTEGER, fr_connection_pool_t, cleanup_interval) },
	{ FR_CONF_OFFSET("cleanup_interval", PW_TYPE_INTEGER, fr_connection_pool_t, cleanup_interval), .dflt = "30" },
	{ FR_CONF_OFFSET("idle_timeout", PW_TYPE_INTEGER, fr_connection_pool_t, idle_timeout), .dflt = "60" },
	{ FR_CONF_OFFSET("connect_timeout", PW_TYPE_TIMEVAL, fr_connection_pool_t, connect_timeout), .dflt = "3.0" },
	{ FR_CONF_OFFSET("retry_delay", PW_TYPE_INTEGER, fr_connection_pool_t, retry_delay), .dflt = "1" },
	{ FR_CONF_OFFSET("spread", PW_TYPE_BOOLEAN, fr_connection_pool_t, spread), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/** Order connections by reserved most recently
 */
static int last_reserved_cmp(void const *one, void const *two)
{
	fr_connection_t const *a = one;
	fr_connection_t const *b = two;

	if (a->last_reserved.tv_sec < b->last_reserved.tv_sec) return -1;
	if (a->last_reserved.tv_sec > b->last_reserved.tv_sec) return +1;

	if (a->last_reserved.tv_usec < b->last_reserved.tv_usec) return -1;
	if (a->last_reserved.tv_usec > b->last_reserved.tv_usec) return +1;

	return 0;
}

/** Order connections by released longest ago
 */
static int last_released_cmp(void const *one, void const *two)
{
	fr_connection_t const *a = one;
	fr_connection_t const *b = two;

	if (b->last_released.tv_sec < a->last_released.tv_sec) return -1;
	if (b->last_released.tv_sec > a->last_released.tv_sec) return +1;

	if (b->last_released.tv_usec < a->last_released.tv_usec) return -1;
	if (b->last_released.tv_usec > a->last_released.tv_usec) return +1;

	return 0;
}

/** Removes a connection from the connection list
 *
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in] this Connection to delete.
 */
static void fr_connection_unlink(fr_connection_pool_t *pool, fr_connection_t *this)
{
	if (this->prev) {
		rad_assert(pool->head != this);
		this->prev->next = this->next;
	} else {
		rad_assert(pool->head == this);
		pool->head = this->next;
	}
	if (this->next) {
		rad_assert(pool->tail != this);
		this->next->prev = this->prev;
	} else {
		rad_assert(pool->tail == this);
		pool->tail = this->prev;
	}

	this->prev = this->next = NULL;
}

/** Adds a connection to the head of the connection list
 *
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in] this Connection to add.
 */
static void fr_connection_link_head(fr_connection_pool_t *pool, fr_connection_t *this)
{
	rad_assert(pool != NULL);
	rad_assert(this != NULL);
	rad_assert(pool->head != this);
	rad_assert(pool->tail != this);

	if (pool->head) {
		pool->head->prev = this;
	}

	this->next = pool->head;
	this->prev = NULL;
	pool->head = this;
	if (!pool->tail) {
		rad_assert(this->next == NULL);
		pool->tail = this;
	} else {
		rad_assert(this->next != NULL);
	}
}

/** Send a connection pool trigger.
 *
 * @param[in] pool to send trigger for.
 * @param[in] name_suffix trigger name suffix.
 */
static void fr_connection_exec_trigger(fr_connection_pool_t *pool, char const *name_suffix)
{
	char name[64];
	rad_assert(pool != NULL);
	rad_assert(name_suffix != NULL);
	snprintf(name, sizeof(name), "%s.%s", pool->trigger_prefix, name_suffix);
	exec_trigger(NULL, pool->cs, name, true);
}

/** Find a connection handle in the connection list
 *
 * Walks over the list of connections searching for a specified connection
 * handle and returns the first connection that contains that pointer.
 *
 * @note Will lock mutex and only release mutex if connection handle
 * is not found, so will usually return will mutex held.
 * @note Must be called with the mutex free.
 *
 * @param[in] pool to search in.
 * @param[in] conn handle to search for.
 * @return
 *	- Connection containing the specified handle.
 *	- NULL if non if connection was found.
 */
static fr_connection_t *fr_connection_find(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t *this;

	if (!pool || !conn) return NULL;

	PTHREAD_MUTEX_LOCK(&pool->mutex);

	/*
	 *	FIXME: This loop could be avoided if we passed a 'void
	 *	**connection' instead.  We could use "offsetof" in
	 *	order to find top of the parent structure.
	 */
	for (this = pool->head; this != NULL; this = this->next) {
		if (this->connection == conn) {
#ifdef PTHREAD_DEBUG
			pthread_t pthread_id;

			pthread_id = pthread_self();
			rad_assert(pthread_equal(this->pthread_id, pthread_id) != 0);
#endif

			rad_assert(this->in_use == true);
			return this;
		}
	}

	PTHREAD_MUTEX_UNLOCK(&pool->mutex);
	return NULL;
}

/** Spawns a new connection
 *
 * Spawns a new connection using the create callback, and returns it for
 * adding to the connection list.
 *
 * @note Will call the 'open' trigger.
 * @note Must be called with the mutex free.
 *
 * @param[in] pool to modify.
 * @param[in] now Current time.
 * @param[in] in_use whether the new connection should be "in_use" or not
 * @return
 *	- New connection struct.
 *	- NULL on error.
 */
static fr_connection_t *fr_connection_spawn(fr_connection_pool_t *pool, time_t now, bool in_use)
{
	uint64_t	number;
	uint32_t	max_pending;
	TALLOC_CTX	*ctx;

	fr_connection_t	*this;
	void		*conn;

	rad_assert(pool != NULL);

	/*
	 *	If we have NO connections, and we've previously failed
	 *	opening connections, don't open multiple connections until
	 *	we successfully open at least one.
	 */
	if ((pool->state.num == 0) && pool->state.pending && pool->state.last_failed) return NULL;

	PTHREAD_MUTEX_LOCK(&pool->mutex);
	rad_assert(pool->state.num <= pool->max);

	/*
	 *	Don't spawn too many connections at the same time.
	 */
	if ((pool->state.num + pool->state.pending) >= pool->max) {
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);

		ERROR("%s: Cannot open new connection, already at max", pool->log_prefix);
		return NULL;
	}

	/*
	 *	If the last attempt failed, wait a bit before
	 *	retrying.
	 */
	if (pool->state.last_failed && ((pool->state.last_failed + pool->retry_delay) > now)) {
		bool complain = false;

		if (pool->state.last_throttled != now) {
			complain = true;

			pool->state.last_throttled = now;
		}

		PTHREAD_MUTEX_UNLOCK(&pool->mutex);

		if (!RATE_LIMIT_ENABLED || complain) {
			ERROR("%s: Last connection attempt failed, waiting %d seconds before retrying",
			      pool->log_prefix, pool->retry_delay);
		}

		return NULL;
	}

	/*
	 *	We limit the rate of new connections after a failed attempt.
	 */
	if (pool->state.pending > pool->max_pending) {
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);
		RATE_LIMIT(WARN("%s: Cannot open a new connection due to rate limit after failure",
				pool->log_prefix));
		return NULL;
	}

	pool->state.pending++;
	number = pool->state.count++;

	/*
	 *	Don't starve out the thread trying to reconnect
	 *	the pool, by continuously opening new connections.
	 */
#ifdef HAVE_PTHREAD_H
	while (pool->state.reconnecting) pthread_cond_wait(&pool->done_reconnecting, &pool->mutex);
#endif

	/*
	 *	Unlock the mutex while we try to open a new
	 *	connection.  If there are issues with the back-end,
	 *	opening a new connection may take a LONG time.  In
	 *	that case, we want the other connections to continue
	 *	to be used.
	 */
	PTHREAD_MUTEX_UNLOCK(&pool->mutex);

	/*
	 *	The true value for max_pending is the smaller of
	 *	free connection slots, or pool->max_pending.
	 */
	max_pending = (pool->max - pool->state.num);
	if (pool->max_pending < max_pending) max_pending = pool->max_pending;
	INFO("%s: Opening additional connection (%" PRIu64 "), %u of %u pending slots used",
	     pool->log_prefix, number, pool->state.pending, max_pending);

	/*
	 *	Allocate a new top level ctx for the create callback
	 *	to hang its memory off of.
	 */
	ctx = talloc_init("fr_connection_ctx");
	if (!ctx) return NULL;

	/*
	 *	This may take a long time, which prevents other
	 *	threads from releasing connections.  We don't care
	 *	about other threads opening new connections, as we
	 *	already have no free connections.
	 */
	conn = pool->create(ctx, pool->opaque, &pool->connect_timeout);
	if (!conn) {
		ERROR("%s: Opening connection failed (%" PRIu64 ")", pool->log_prefix, number);

		pool->state.last_failed = now;
		PTHREAD_MUTEX_LOCK(&pool->mutex);
		pool->max_pending = 1;
		pool->state.pending--;

		PTHREAD_COND_BROADCAST(&pool->done_spawn);
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);

		talloc_free(ctx);

		return NULL;
	}

	/*
	 *	And lock the mutex again while we link the new
	 *	connection back into the pool.
	 */
	PTHREAD_MUTEX_LOCK(&pool->mutex);

	this = talloc_zero(pool, fr_connection_t);
	if (!this) {
		PTHREAD_COND_BROADCAST(&pool->done_spawn);
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);

		talloc_free(ctx);

		return NULL;
	}
	fr_link_talloc_ctx_free(this, ctx);

	this->created = now;
	this->connection = conn;
	this->in_use = in_use;

	this->number = number;
	gettimeofday(&this->last_reserved, NULL);
	this->last_released = this->last_reserved;

	/*
	 *	The connection pool is starting up.  Insert the
	 *	connection into the heap.
	 */
	if (!in_use) fr_heap_insert(pool->heap, this);

	fr_connection_link_head(pool, this);

	/*
	 *	Do NOT insert the connection into the heap.  That's
	 *	done when the connection is released.
	 */

	pool->state.num++;

	rad_assert(pool->state.pending > 0);
	pool->state.pending--;

	/*
	 *	We've successfully opened one more connection.  Allow
	 *	more connections to open in parallel.
	 */
	if (pool->max_pending < pool->max) pool->max_pending++;

	pool->state.last_spawned = time(NULL);
	pool->delay_interval = pool->cleanup_interval;
	pool->state.next_delay = pool->cleanup_interval;
	pool->state.last_failed = 0;

	PTHREAD_COND_BROADCAST(&pool->done_spawn);
	PTHREAD_MUTEX_UNLOCK(&pool->mutex);

	fr_connection_exec_trigger(pool, "open");

	return this;
}

/** Close an existing connection.
 *
 * Removes the connection from the list, calls the delete callback to close
 * the connection, then frees memory allocated to the connection.
 *
 * @note Will call the 'close' trigger.
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in,out] this Connection to delete.
 */
static void fr_connection_close_internal(fr_connection_pool_t *pool, fr_connection_t *this)
{
	/*
	 *	If it's in use, release it.
	 */
	if (this->in_use) {
#ifdef PTHREAD_DEBUG
		pthread_t pthread_id = pthread_self();
		rad_assert(pthread_equal(this->pthread_id, pthread_id) != 0);
#endif

		this->in_use = false;

		rad_assert(pool->state.active != 0);
		pool->state.active--;

	} else {
		/*
		 *	Connection isn't used, remove it from the heap.
		 */
		fr_heap_extract(pool->heap, this);
	}

	fr_connection_exec_trigger(pool, "close");

	fr_connection_unlink(pool, this);

	rad_assert(pool->state.num > 0);
	pool->state.num--;
	talloc_free(this);
}

/** Check whether a connection needs to be removed from the pool
 *
 * Will verify that the connection is within idle_timeout, max_uses, and
 * lifetime values. If it is not, the connection will be closed.
 *
 * @note Will only close connections not in use.
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in,out] this Connection to manage.
 * @param[in] now Current time.
 * @return
 *	- 0 if connection was closed.
 *	- 1 if connection handle was left open.
 */
static int fr_connection_manage(fr_connection_pool_t *pool,
				fr_connection_t *this,
				time_t now)
{
	rad_assert(pool != NULL);
	rad_assert(this != NULL);

	/*
	 *	Don't terminated in-use connections
	 */
	if (this->in_use) return 1;

	if (this->needs_reconnecting) {
		DEBUG("%s: Closing expired connection (%" PRIu64 "): Needs reconnecting", pool->log_prefix,
		      this->number);
	do_delete:
		if (pool->state.num <= pool->min) {
			DEBUG("%s: You probably need to lower \"min\"", pool->log_prefix);
		}
		fr_connection_close_internal(pool, this);
		return 0;
	}

	if ((pool->max_uses > 0) &&
	    (this->num_uses >= pool->max_uses)) {
		DEBUG("%s: Closing expired connection (%" PRIu64 "): Hit max_uses limit", pool->log_prefix,
		      this->number);
		goto do_delete;
	}

	if ((pool->lifetime > 0) &&
	    ((this->created + pool->lifetime) < now)) {
		DEBUG("%s: Closing expired connection (%" PRIu64 "): Hit lifetime limit",
		      pool->log_prefix, this->number);
		goto do_delete;
	}

	if ((pool->idle_timeout > 0) &&
	    ((this->last_released.tv_sec + pool->idle_timeout) < now)) {
		INFO("%s: Closing connection (%" PRIu64 "): Hit idle_timeout, was idle for %u seconds",
		     pool->log_prefix, this->number, (int) (now - this->last_released.tv_sec));
		goto do_delete;
	}

	return 1;
}


/** Check whether any connections need to be removed from the pool
 *
 * Maintains the number of connections in the pool as per the configuration
 * parameters for the connection pool.
 *
 * @note Will only run checks the first time it's called in a given second,
 * to throttle connection spawning/closing.
 * @note Will only close connections not in use.
 * @note Must be called with the mutex held, will release mutex before
 * returning.
 *
 * @param[in,out] pool to manage.
 * @return 1
 */
static int fr_connection_pool_check(fr_connection_pool_t *pool)
{
	uint32_t spawn, idle, extra;
	time_t now = time(NULL);
	fr_connection_t *this, *next;

	if (pool->state.last_checked == now) {
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);
		return 1;
	}

	/*
	 *	Some idle connections are OK, if they're within the
	 *	configured "spare" range.  Any extra connections
	 *	outside of that range can be closed.
	 */
	idle = pool->state.num - pool->state.active;
	if (idle <= pool->spare) {
		extra = 0;
	} else {
		extra = idle - pool->spare;
	}

	/*
	 *	The other end can close connections.  If so, we'll
	 *	have fewer than "min".  When that happens, open more
	 *	connections to enforce "min".
	 */
	if ((pool->state.num + pool->state.pending) <= pool->min) {
		spawn = pool->min - (pool->state.num + pool->state.pending);
		extra = 0;

	/*
	 *	If we're about to create more than "max",
	 *	don't create more.
	 */
	} else if ((pool->state.num + pool->state.pending) >= pool->max) {
		/*
		 *	Ensure we don't spawn more connections.  If
		 *	there are extra idle connections, we can
		 *	delete all of them.
		 */
		spawn = 0;
		/* leave extra alone from above */

	/*
	 *	min < num < max
	 *
	 *	AND we don't have enough idle connections.
	 *	Open some more.
	 */
	} else if (idle <= pool->spare) {
		/*
		 *	Not enough spare connections.  Spawn a few.
		 *	But cap the pool size at "max"
		 */
		spawn = pool->spare - idle;
		extra = 0;

		if ((pool->state.num + pool->state.pending + spawn) > pool->max) {
			spawn = pool->max - (pool->state.num + pool->state.pending);
		}

	/*
	 *	min < num < max
	 *
	 *	We have more than enough idle connections, AND
	 *	some are pending.  Don't open or close any.
	 */
	} else if (pool->state.pending) {
		spawn = 0;
		extra = 0;

	/*
	 *	We have too many idle connections, but closing
	 *	some would take us below "min", so we only
	 *	close enough to take us to "min".
	 */
	} else if ((pool->min + extra) >= pool->state.num) {
		spawn = 0;
		extra = pool->state.num - pool->min;

	} else {
		/*
		 *	Closing the "extra" connections won't take us
		 *	below "min".  It's therefore safe to close
		 *	them all.
		 */
		spawn = 0;
		/* leave extra alone from above */
	}

	/*
	 *	Only try to open spares if we're not already attempting to open
	 *	a connection. Avoids spurious log messages.
	 */
	if (spawn) {
		INFO("%s: Need %i more connections to reach %i spares",
		     pool->log_prefix, spawn, pool->spare);
		PTHREAD_MUTEX_UNLOCK(&pool->mutex);
		fr_connection_spawn(pool, now, false); /* ignore return code */
		PTHREAD_MUTEX_LOCK(&pool->mutex);
	}

	/*
	 *	We haven't spawned connections in a while, and there
	 *	are too many spare ones.  Close the one which has been
	 *	unused for the longest.
	 */
	if (extra && (now >= (pool->state.last_spawned + pool->delay_interval))) {
		fr_connection_t *found;

		found = NULL;
		for (this = pool->tail; this != NULL; this = this->prev) {
			if (this->in_use) continue;

			if (!found ||
			    timercmp(&this->last_reserved, &found->last_reserved, <)) {
				found = this;
			}
		}

		rad_assert(found != NULL);

		INFO("%s: Closing connection (%" PRIu64 "), from %d unused connections", pool->log_prefix,
		     found->number, extra);
		fr_connection_close_internal(pool, found);

		/*
		 *	Decrease the delay for the next time we clean
		 *	up.
		 */
		pool->state.next_delay >>= 1;
		if (pool->state.next_delay == 0) pool->state.next_delay = 1;
		pool->delay_interval += pool->state.next_delay;
	}

	/*
	 *	Pass over all of the connections in the pool, limiting
	 *	lifetime, idle time, max requests, etc.
	 */
	for (this = pool->head; this != NULL; this = next) {
		next = this->next;
		fr_connection_manage(pool, this, now);
	}

	pool->state.last_checked = now;
	PTHREAD_MUTEX_UNLOCK(&pool->mutex);

	return 1;
}

/** Get a connection from the connection pool
 *
 * @note Must be called with the mutex free.
 *
 * @param[in,out] pool to reserve the connection from.
 * @param[in] spawn whether to spawn a new connection
 * @return
 *	- A pointer to the connection handle.
 *	- NULL on error.
 */
static void *fr_connection_get_internal(fr_connection_pool_t *pool, bool spawn)
{
	time_t now;
	fr_connection_t *this;

	if (!pool) return NULL;

	PTHREAD_MUTEX_LOCK(&pool->mutex);

	now = time(NULL);

	/*
	 *	Grab the link with the lowest latency, and check it
	 *	for limits.  If "connection manage" says the link is
	 *	no longer usable, go grab another one.
	 */
	do {
		this = fr_heap_peek(pool->heap);
		if (!this) break;
	} while (!fr_connection_manage(pool, this, now));

	/*
	 *	We have a working connection.  Extract it from the
	 *	heap and use it.
	 */
	if (this) {
		fr_heap_extract(pool->heap, this);
		goto do_return;
	}

	/*
	 *	We don't have a connection.  Try to open a new one.
	 */
	rad_assert(pool->state.active == pool->state.num);

	if (pool->state.num == pool->max) {
		bool complain = false;

		/*
		 *	Rate-limit complaints.
		 */
		if (pool->state.last_at_max != now) {
			complain = true;
			pool->state.last_at_max = now;
		}

		PTHREAD_MUTEX_UNLOCK(&pool->mutex);
		if (!RATE_LIMIT_ENABLED || complain) {
			ERROR("%s: No connections available and at max connection limit", pool->log_prefix);
		}

		return NULL;
	}

	PTHREAD_MUTEX_UNLOCK(&pool->mutex);

	if (!spawn) return NULL;

	DEBUG("%s: %i of %u connections in use.  You  may need to increase \"spare\"", pool->log_prefix,
	      pool->state.active, pool->state.num);
	this = fr_connection_spawn(pool, now, true); /* MY connection! */
	if (!this) return NULL;
	PTHREAD_MUTEX_LOCK(&pool->mutex);

do_return:
	pool->state.active++;
	this->num_uses++;
	gettimeofday(&this->last_reserved, NULL);
	this->in_use = true;

#ifdef PTHREAD_DEBUG
	this->pthread_id = pthread_self();
#endif
	PTHREAD_MUTEX_UNLOCK(&pool->mutex);

	DEBUG("%s: Reserved connection (%" PRIu64 ")", pool->log_prefix, this->number);

	return this->connection;
}

/** Create a new connection pool
 *
 * Allocates structures used by the connection pool, initialises the various
 * configuration options and counters, and sets the callback functions.
 *
 * Will also spawn the number of connections specified by the 'start'
 * configuration options.
 *
 * @note Will call the 'start' trigger.
 *
 * @param[in] ctx Context to link pool's destruction to.
 * @param[in] cs pool section.
 * @param[in] opaque data pointer to pass to callbacks.
 * @param[in] c Callback to create new connections.
 * @param[in] a Callback to check the status of connections.
 * @param[in] log_prefix prefix to prepend to all log messages.
 * @param[in] trigger_prefix prefix to prepend to all trigger names.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_connection_pool_t *fr_connection_pool_init(TALLOC_CTX *ctx,
					      CONF_SECTION *cs,
					      void *opaque,
					      fr_connection_create_t c,
					      fr_connection_alive_t a,
					      char const *log_prefix,
					      char const *trigger_prefix)
{
	uint32_t i;
	fr_connection_pool_t *pool;
	fr_connection_t *this;
	time_t now;

	if (!cs || !opaque || !c) return NULL;

	now = time(NULL);

	/*
	 *	Pool is allocated in the NULL context as
	 *	threads are likely to allocate memory
	 *	beneath the pool.
	 */
	pool = talloc_zero(NULL, fr_connection_pool_t);
	if (!pool) return NULL;

	/*
	 *	Ensure the pool is freed at the same time
	 *	as its parent.
	 */
	if (fr_link_talloc_ctx_free(ctx, pool) < 0) {
		talloc_free(pool);

		return NULL;
	}

	pool->cs = cs;
	pool->opaque = opaque;
	pool->create = c;
	pool->alive = a;

	pool->head = pool->tail = NULL;

	/*
	 *	We keep a heap of connections, sorted by the last time
	 *	we STARTED using them.  Newly opened connections
	 *	aren't in the heap.  They're only inserted in the list
	 *	once they're released.
	 *
	 *	We do "most recently started" instead of "most
	 *	recently used", because MRU is done as most recently
	 *	*released*.  We want to order connections by
	 *	responsiveness, and MRU prioritizes high latency
	 *	connections.
	 *
	 *	We want most recently *started*, which gives
	 *	preference to low latency links, and pushes high
	 *	latency links down in the priority heap.
	 *
	 *	https://code.facebook.com/posts/1499322996995183/solving-the-mystery-of-link-imbalance-a-metastable-failure-state-at-scale/
	 */
	if (!pool->spread) {
		pool->heap = fr_heap_create(last_reserved_cmp, offsetof(fr_connection_t, heap));
	/*
	 *	For some types of connections we need to used a different
	 *	algorithm, because load balancing benefits are secondary
	 *	to maintaining a cache of open connections.
	 *
	 *	With libcurl's multihandle, connections can only be reused
	 *	if all handles that make up the multhandle are done processing
	 *	their requests.
	 *
	 *	We can't tell when that's happened using libcurl, and even
	 *	if we could, blocking until all servers had responded
	 *	would have huge cost.
	 *
	 *	The solution is to order the heap so that the connection that
	 *	was released longest ago is at the top.
	 *
	 *	That way we maximise time between connection use.
	 */
	} else {
		pool->heap = fr_heap_create(last_released_cmp, offsetof(fr_connection_t, heap));
	}
	if (!pool->heap) {
		talloc_free(pool);
		return NULL;
	}

	pool->log_prefix = log_prefix ? talloc_typed_strdup(pool, log_prefix) : "core";
	pool->trigger_prefix = trigger_prefix ? talloc_typed_strdup(pool, trigger_prefix) : "";

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&pool->mutex, NULL);
	pthread_cond_init(&pool->done_spawn, NULL);
	pthread_cond_init(&pool->done_reconnecting, NULL);
#endif

	DEBUG("%s: Initialising connection pool", pool->log_prefix);

	if (cf_section_parse(cs, pool, connection_config) < 0) goto error;

	/*
	 *	Some simple limits
	 */
	if (pool->max == 0) {
		cf_log_err_cs(cs, "Cannot set 'max' to zero");
		goto error;
	}
	pool->max_pending = pool->max; /* can open all connections now */

	if (pool->min > pool->max) {
		cf_log_err_cs(cs, "Cannot set 'min' to more than 'max'");
		goto error;
	}

	FR_INTEGER_BOUND_CHECK("max", pool->max, <=, 1024);
	FR_INTEGER_BOUND_CHECK("start", pool->start, <=, pool->max);
	FR_INTEGER_BOUND_CHECK("spare", pool->spare, <=, (pool->max - pool->min));

	if (pool->lifetime > 0) {
		FR_INTEGER_COND_CHECK("idle_timeout", pool->idle_timeout, (pool->idle_timeout <= pool->lifetime), 0);
	}

	if (pool->idle_timeout > 0) {
		FR_INTEGER_BOUND_CHECK("cleanup_interval", pool->cleanup_interval, <=, pool->idle_timeout);
	}

	/*
	 *	Some libraries treat 0.0 as infinite timeout, others treat it
	 *	as instantaneous timeout.  Solve the inconsistency by making
	 *	the smallest allowable timeout 100ms.
	 */
	FR_TIMEVAL_BOUND_CHECK("connect_timeout", &pool->connect_timeout, >=, 0, 100000);

	/*
	 *	Don't open any connections.  Instead, force the limits
	 *	to only 1 connection.
	 *
	 */
	if (check_config) {
		pool->start = pool->min = pool->max = 1;
		return pool;
	}

	/*
	 *	Create all of the connections, unless the admin says
	 *	not to.
	 */
	for (i = 0; i < pool->start; i++) {
		this = fr_connection_spawn(pool, now, false);
		if (!this) {
		error:
			fr_connection_pool_free(pool);
			return NULL;
		}
	}

	fr_connection_exec_trigger(pool, "start");

	return pool;
}

/** Allocate a new pool using an existing one as a template
 *
 * @param ctx to allocate new pool in.
 * @param pool to copy.
 * @param opaque data to pass to connection function.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_connection_pool_t *fr_connection_pool_copy(TALLOC_CTX *ctx, fr_connection_pool_t *pool, void *opaque)
{
	return fr_connection_pool_init(ctx, pool->cs, opaque, pool->create,
				       pool->alive, pool->log_prefix, pool->trigger_prefix);
}

/** Get the number of connections currently in the pool
 *
 * @param[in] pool to count connections for.
 * @return the number of connections in the pool
 */
fr_connection_pool_state_t const *fr_connection_pool_state(fr_connection_pool_t *pool)
{
	return &pool->state;
}

/** Connection pool get timeout
 *
 * @param[in] pool to get connection timeout for.
 * @return the connection timeout configured for the pool.
 */
struct timeval fr_connection_pool_timeout(fr_connection_pool_t *pool)
{
	return pool->connect_timeout;
}

/** Return the opaque data associated with a connection pool
 *
 * @param pool to return data for.
 * @return opaque data associated with pool.
 */
void const *fr_connection_pool_opaque(fr_connection_pool_t *pool)
{
	return pool->opaque;
}

/** Increment pool reference by one.
 *
 * @param[in] pool to increment reference counter for.
 */
void fr_connection_pool_ref(fr_connection_pool_t *pool)
{
	pool->ref++;
}

/** Set a reconnection callback for the connection pool
 *
 * This can be called at any time during the pool's lifecycle.
 *
 * @param[in] pool to set reconnect callback for.
 * @param reconnect callback to call when reconnecting pool's connections.
 */
void fr_connection_pool_reconnect_func(fr_connection_pool_t *pool, fr_connection_pool_reconnect_t reconnect)
{
	pool->reconnect = reconnect;
}

/** Mark connections for reconnection, and spawn at least 'start' connections
 *
 * @note This call may block whilst waiting for pending connection attempts to complete.
 *
 * This intended to be called on a connection pool that's in use, to have it reflect
 * a configuration change, or because the administrator knows that all connections
 * in the pool are inviable and need to be reconnected.
 *
 * @param[in] pool to reconnect.
 * @return
 *	-  0 On success.
 *	- -1 If we couldn't create start connections, this may be ignored
 *	     depending on the context in which this function is being called.
 */
int fr_connection_pool_reconnect(fr_connection_pool_t *pool)
{
	uint32_t	i;
	fr_connection_t	*this;
	time_t		now;

	PTHREAD_MUTEX_LOCK(&pool->mutex);

	/*
	 *	Pause new spawn attempts (we release the mutex
	 *	during our cond wait).
	 */
	pool->state.reconnecting = true;

#ifdef HAVE_PTHREAD_H
	/*
	 *	When the loop exits, we'll hold the lock for the pool,
	 *	and we're guaranteed the connection create callback
	 *	will not be using the opaque data.
	 */
	while (pool->state.pending) pthread_cond_wait(&pool->done_spawn, &pool->mutex);
#endif

	/*
	 *	We want to ensure at least 'start' connections
	 *	have been reconnected. We can't call reconnect
	 *	because, we might get the same connection each
	 *	time we reserve one, so we close 'start'
	 *	connections, and then attempt to spawn them again.
	 */
	for (i = 0; i < pool->start; i++) {
		this = fr_heap_peek(pool->heap);
		if (!this) break;	/* There wasn't 'start' connections available */

		fr_connection_close_internal(pool, this);
	}

	/*
	 *	Mark all remaining connections in the pool as
	 *	requiring reconnection.
	 */
	for (this = pool->head; this; this = this->next) this->needs_reconnecting = true;

	/*
	 *	Call the reconnect callback (if one's set)
	 *	This may modify the opaque data associated
	 *	with the pool.
	 */
	if (pool->reconnect) pool->reconnect(pool->opaque);

#ifdef HAVE_PTHREAD_H
	/*
	 *	Allow new spawn attempts, and wakeup any threads
	 *	waiting to spawn new connections.
	 */
	pool->state.reconnecting = false;
	PTHREAD_COND_BROADCAST(&pool->done_reconnecting);
	PTHREAD_MUTEX_UNLOCK(&pool->mutex);
#endif

	fr_connection_exec_trigger(pool, "reconnect");

	now = time(NULL);

	/*
	 *	Now attempt to spawn 'start' connections.
	 */
	for (i = 0; i < pool->start; i++) {
		this = fr_connection_spawn(pool, now, false);
		if (!this) return -1;
	}

	return 0;
}

/** Delete a connection pool
 *
 * Closes, unlinks and frees all connections in the connection pool, then frees
 * all memory used by the connection pool.
 *
 * @note Will call the 'stop' trigger.
 * @note Must be called with the mutex free.
 *
 * @param[in,out] pool to delete.
 */
void fr_connection_pool_free(fr_connection_pool_t *pool)
{
	fr_connection_t *this;

	if (!pool) return;

	/*
	 *	More modules hold a reference to this pool, don't free
	 *	it yet.
	 */
	if (pool->ref > 0) {
		pool->ref--;
		return;
	}

	DEBUG("%s: Removing connection pool", pool->log_prefix);

	PTHREAD_MUTEX_LOCK(&pool->mutex);

	/*
	 *	Don't loop over the list.  Just keep removing the head
	 *	until they're all gone.
	 */
	while ((this = pool->head) != NULL) {
		INFO("%s: Closing connection (%" PRIu64 ")", pool->log_prefix, this->number);

		fr_connection_close_internal(pool, this);
	}

	fr_heap_delete(pool->heap);

	fr_connection_exec_trigger(pool, "stop");

	rad_assert(pool->head == NULL);
	rad_assert(pool->tail == NULL);
	rad_assert(pool->state.num == 0);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&pool->mutex);
	pthread_cond_destroy(&pool->done_spawn);
	pthread_cond_destroy(&pool->done_reconnecting);
#endif

	talloc_free(pool);
}

/** Reserve a connection in the connection pool
 *
 * Will attempt to find an unused connection in the connection pool, if one is
 * found, will mark it as in in use increment the number of active connections
 * and return the connection handle.
 *
 * If no free connections are found will attempt to spawn a new one, conditional
 * on a connection spawning not already being in progress, and not being at the
 * 'max' connection limit.
 *
 * @note fr_connection_release must be called once the caller has finished
 * using the connection.
 *
 * @see fr_connection_release
 * @param[in,out] pool to reserve the connection from.
 * @return
 *	- A pointer to the connection handle.
 *	- NULL on error.
 */
void *fr_connection_get(fr_connection_pool_t *pool)
{
	return fr_connection_get_internal(pool, true);
}

/** Release a connection
 *
 * Will mark a connection as unused and decrement the number of active
 * connections.
 *
 * @see fr_connection_get
 * @param[in,out] pool to release the connection in.
 * @param[in,out] conn to release.
 */
void fr_connection_release(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t *this;

	this = fr_connection_find(pool, conn);
	if (!this) return;

	this->in_use = false;

	/*
	 *	Record when the connection was last released
	 */
	gettimeofday(&this->last_released, NULL);
	pool->state.last_released = this->last_released;

	/*
	 *	Insert the connection in the heap.
	 *
	 *	This will either be based on when we *started* using it
	 *	(allowing fast links to be re-used, and slow links to be
	 *	gradually expired), or when we released it (allowing
	 *	the maximum amount of time between connection use).
	 */
	fr_heap_insert(pool->heap, this);

	rad_assert(pool->state.active != 0);
	pool->state.active--;

	DEBUG("%s: Released connection (%" PRIu64 ")", pool->log_prefix, this->number);

	/*
	 *	We mirror the "spawn on get" functionality by having
	 *	"delete on release".  If there are too many spare
	 *	connections, go manage the pool && clean some up.
	 */
	fr_connection_pool_check(pool);
}

/** Reconnect a suspected inviable connection
 *
 * This should be called by the module if it suspects that a connection is
 * not viable (e.g. the server has closed it).
 *
 * When implementing a module that uses the connection pool API, it is advisable
 * to pass a pointer to the pointer to the handle (void **conn)
 * to all functions which may call reconnect. This is so that if a new handle
 * is created and returned, the handle pointer can be updated up the callstack,
 * and a function higher up the stack doesn't attempt to use a now invalid
 * connection handle.
 *
 * @note Will free any talloced memory hung off the context of the connection,
 *	being reconnected.
 *
 * @warning After calling reconnect the caller *MUST NOT* attempt to use
 *	the old handle in any other operations, as its memory will have been
 *	freed.
 *
 * @see fr_connection_get
 * @param[in,out] pool to reconnect the connection in.
 * @param[in,out] conn to reconnect.
 * @return new connection handle if successful else NULL.
 */
void *fr_connection_reconnect(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t	*this;

	if (!pool || !conn) return NULL;

	/*
	 *	If fr_connection_find is successful the pool is now locked
	 */
	this = fr_connection_find(pool, conn);
	if (!this) return NULL;

	INFO("%s: Deleting inviable connection (%" PRIu64 ")", pool->log_prefix, this->number);

	fr_connection_close_internal(pool, this);
	fr_connection_pool_check(pool);			/* Whilst we still have the lock (will release the lock) */

	/*
	 *	Return an existing connection or spawn a new one.
	 */
	return fr_connection_get_internal(pool, true);
}

/** Delete a connection from the connection pool.
 *
 * Resolves the connection handle to a connection, then (if found)
 * closes, unlinks and frees that connection.
 *
 * @note Must be called with the mutex free.
 *
 * @param[in,out] pool Connection pool to modify.
 * @param[in] conn to delete.
 * @return
 *	- 0 If the connection could not be found.
 *	- 1 if the connection was deleted.
 */
int fr_connection_close(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t *this;

	this = fr_connection_find(pool, conn);
	if (!this) return 0;

	/*
	 *	Record the last time a connection was closed
	 */
	gettimeofday(&pool->state.last_closed, NULL);

	INFO("%s: Deleting connection (%" PRIu64 ")", pool->log_prefix, this->number);

	fr_connection_close_internal(pool, this);
	fr_connection_pool_check(pool);
	return 1;
}
