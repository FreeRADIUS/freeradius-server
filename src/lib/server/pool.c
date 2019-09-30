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
 * @file pool.c
 * @brief Handle pools of connections (threads, sockets, etc.)
 * @note This API must be used by all modules in the public distribution that
 * maintain pools of connections.
 *
 * @copyright 2012 The FreeRADIUS server project
 * @copyright 2012 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#define LOG_PREFIX "%s - "
#define LOG_PREFIX_ARGS pool->log_prefix

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/modpriv.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/heap.h>
#include <freeradius-devel/util/misc.h>

#include <time.h>

typedef struct fr_pool_connection_s fr_pool_connection_t;

static int connection_check(fr_pool_t *pool, REQUEST *request);

/** An individual connection within the connection pool
 *
 * Defines connection counters, timestamps, and holds a pointer to the
 * connection handle itself.
 *
 * @see fr_pool_t
 */
struct fr_pool_connection_s {
	fr_pool_connection_t	*prev;			//!< Previous connection in list.
	fr_pool_connection_t	*next;			//!< Next connection in list.
	int32_t		heap_id;			//!< For the next connection heap.

	time_t		created;		//!< Time connection was created.
	fr_time_t	last_reserved;		//!< Last time the connection was reserved.

	fr_time_t	last_released;  	//!< Time the connection was released.

	uint32_t	num_uses;		//!< Number of times the connection has been reserved.
	uint64_t	number;			//!< Unique ID assigned when the connection is created,
						//!< these will monotonically increase over the
						//!< lifetime of the connection pool.
	void		*connection;		//!< Pointer to whatever the module uses for a connection
						//!< handle.
	bool		in_use;			//!< Whether the connection is currently reserved.

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
struct fr_pool_s {
	int		ref;			//!< Reference counter to prevent connection
						//!< pool being freed multiple times.
	uint32_t	start;			//!< Number of initial connections.
	uint32_t	min;			//!< Minimum number of concurrent connections to keep open.
	uint32_t	max;			//!< Maximum number of concurrent connections to allow.
	uint32_t	max_pending;		//!< Max number of pending connections to allow.
	uint32_t	spare;			//!< Number of spare connections to try.
	uint64_t	max_uses;		//!< Maximum number of times a connection can be used
						//!< before being closed.
	uint32_t	pending_window;		//!< Sliding window of pending connections.

	fr_time_delta_t	retry_delay;		//!< seconds to delay re-open after a failed open.
	fr_time_delta_t	cleanup_interval; 	//!< Initial timer for how often we sweep the pool
						//!< for free connections. (0 is infinite).
	fr_time_delta_t	delay_interval;		//!< When we next do a cleanup.  Initialized to
						//!< cleanup_interval, and increase from there based
						//!< on the delay.
	fr_time_delta_t	lifetime;		//!< How long a connection can be open before being
						//!< closed (irrespective of whether it's idle or not).
	fr_time_delta_t	idle_timeout;		//!< How long a connection can be idle before
						//!< being closed.
	fr_time_delta_t	connect_timeout;	//!< New connection timeout, enforced by the create
						//!< callback.

	bool		spread;			//!< If true we spread requests over the connections,
						//!< using the connection released longest ago, first.

	fr_heap_t	*heap;			//!< For the next connection heap

	fr_pool_connection_t	*head;		//!< Start of the connection list.
	fr_pool_connection_t	*tail;		//!< End of the connection list.

	pthread_mutex_t	mutex;			//!< Mutex used to keep consistent state when making
						//!< modifications in threaded mode.
	pthread_cond_t	done_spawn;		//!< Threads that need to ensure no spawning is in progress,
						//!< should block on this condition if pending != 0.
	pthread_cond_t	done_reconnecting;	//!< Before calling the create callback, threads should
						//!< block on this condition if reconnecting == true.

	CONF_SECTION const *cs;			//!< Configuration section holding the section of parsed
						//!< config file that relates to this pool.
	void		*opaque;		//!< Pointer to context data that will be passed to callbacks.

	char const	*log_prefix;		//!< Log prefix to prepend to all log messages created
						//!< by the connection pool code.

	bool		triggers_enabled;	//!< Whether we call the trigger functions.

	char const	*trigger_prefix;	//!< Prefix to prepend to names of all triggers
						//!< fired by the connection pool code.
	VALUE_PAIR	*trigger_args;		//!< Arguments to make available in connection pool triggers.

	fr_time_delta_t	held_trigger_min;	//!< If a connection is held for less than the specified
						//!< period, fire a trigger.
	fr_time_delta_t	held_trigger_max;	//!< If a connection is held for longer than the specified
						//!< period, fire a trigger.

	fr_pool_connection_create_t	create;	//!< Function used to create new connections.
	fr_pool_connection_alive_t	alive;	//!< Function used to check status of connections.

	fr_pool_reconnect_t	reconnect;	//!< Called during connection pool reconnect.

	fr_pool_state_t	state;			//!< Stats and state of the connection pool.
};

static const CONF_PARSER pool_config[] = {
	{ FR_CONF_OFFSET("start", FR_TYPE_UINT32, fr_pool_t, start), .dflt = "5" },
	{ FR_CONF_OFFSET("min", FR_TYPE_UINT32, fr_pool_t, min), .dflt = "5" },
	{ FR_CONF_OFFSET("max", FR_TYPE_UINT32, fr_pool_t, max), .dflt = "10" },
	{ FR_CONF_OFFSET("max_pending", FR_TYPE_UINT32, fr_pool_t, max_pending), .dflt = "0" },
	{ FR_CONF_OFFSET("spare", FR_TYPE_UINT32, fr_pool_t, spare), .dflt = "3" },
	{ FR_CONF_OFFSET("uses", FR_TYPE_UINT64, fr_pool_t, max_uses), .dflt = "0" },
	{ FR_CONF_OFFSET("lifetime", FR_TYPE_TIME_DELTA, fr_pool_t, lifetime), .dflt = "0" },
	{ FR_CONF_OFFSET("cleanup_interval", FR_TYPE_TIME_DELTA, fr_pool_t, cleanup_interval), .dflt = "30" },
	{ FR_CONF_OFFSET("idle_timeout", FR_TYPE_TIME_DELTA, fr_pool_t, idle_timeout), .dflt = "60" },
	{ FR_CONF_OFFSET("connect_timeout", FR_TYPE_TIME_DELTA, fr_pool_t, connect_timeout), .dflt = "3.0" },
	{ FR_CONF_OFFSET("held_trigger_min", FR_TYPE_TIME_DELTA, fr_pool_t, held_trigger_min), .dflt = "0.0" },
	{ FR_CONF_OFFSET("held_trigger_max", FR_TYPE_TIME_DELTA, fr_pool_t, held_trigger_max), .dflt = "0.5" },
	{ FR_CONF_OFFSET("retry_delay", FR_TYPE_TIME_DELTA, fr_pool_t, retry_delay), .dflt = "1" },
	{ FR_CONF_OFFSET("spread", FR_TYPE_BOOL, fr_pool_t, spread), .dflt = "no" },
	CONF_PARSER_TERMINATOR
};

/** Order connections by reserved most recently
 */
static int8_t last_reserved_cmp(void const *one, void const *two)
{
	fr_pool_connection_t const *a = one, *b = two;

	return fr_time_cmp(a->last_reserved, b->last_reserved);
}

/** Order connections by released longest ago
 */
static int8_t last_released_cmp(void const *one, void const *two)
{
	fr_pool_connection_t const *a = one, *b = two;

	return fr_time_cmp(a->last_released, b->last_released);
}

/** Removes a connection from the connection list
 *
 * @note Must be called with the mutex held.
 *
 * @param[in] pool	to modify.
 * @param[in] this	Connection to delete.
 */
static void connection_unlink(fr_pool_t *pool, fr_pool_connection_t *this)
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
 * @param[in] pool	to modify.
 * @param[in] this	Connection to add.
 */
static void connection_link_head(fr_pool_t *pool, fr_pool_connection_t *this)
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
 * @param[in] pool	to send trigger for.
 * @param[in] request	The current request (may be NULL).
 * @param[in] event	trigger name suffix.
 */
static inline void fr_pool_trigger_exec(fr_pool_t *pool, REQUEST *request, char const *event)
{
	char	name[128];

	rad_assert(pool != NULL);
	rad_assert(event != NULL);

	if (!pool->triggers_enabled) return;

	snprintf(name, sizeof(name), "%s.%s", pool->trigger_prefix, event);
	trigger_exec(request, pool->cs, name, true, pool->trigger_args);
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
 * @param[in] pool	to search in.
 * @param[in] conn	handle to search for.
 * @return
 *	- Connection containing the specified handle.
 *	- NULL if non if connection was found.
 */
static fr_pool_connection_t *connection_find(fr_pool_t *pool, void *conn)
{
	fr_pool_connection_t *this;

	if (!pool || !conn) return NULL;

	pthread_mutex_lock(&pool->mutex);

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
			/* coverity[missing_unlock] */
			return this;
		}
	}

	pthread_mutex_unlock(&pool->mutex);
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
 * @param[in] pool	to modify.
 * @param[in] request	The current request.
 * @param[in] now	Current time.
 * @param[in] in_use	whether the new connection should be "in_use" or not
 * @param[in] unlock	whether we should unlock the mutex before returning
 * @return
 *	- New connection struct.
 *	- NULL on error.
 */
static fr_pool_connection_t *connection_spawn(fr_pool_t *pool, REQUEST *request, fr_time_t now, bool in_use, bool unlock)
{
	uint64_t		number;
	uint32_t		pending_window;
	TALLOC_CTX		*ctx;

	fr_pool_connection_t	*this;
	void			*conn;

	rad_assert(pool != NULL);

	/*
	 *	If we have NO connections, and we've previously failed
	 *	opening connections, don't open multiple connections until
	 *	we successfully open at least one.
	 */
	if ((pool->state.num == 0) && pool->state.pending && pool->state.last_failed) return NULL;

	pthread_mutex_lock(&pool->mutex);
	rad_assert(pool->state.num <= pool->max);

	/*
	 *	Don't spawn too many connections at the same time.
	 */
	if ((pool->state.num + pool->state.pending) >= pool->max) {
		pthread_mutex_unlock(&pool->mutex);

		ROPTIONAL(RERROR, ERROR, "Cannot open new connection, already at max");
		return NULL;
	}

	/*
	 *	If the last attempt failed, wait a bit before
	 *	retrying.
	 */
	if (pool->state.last_failed && ((pool->state.last_failed + pool->retry_delay) > now)) {
		bool complain = false;

		if ((now - pool->state.last_throttled) >= NSEC) {
			complain = true;

			pool->state.last_throttled = now;
		}

		pthread_mutex_unlock(&pool->mutex);

		if (!RATE_LIMIT_ENABLED || complain) {
			ROPTIONAL(RERROR, ERROR, "Last connection attempt failed, waiting %pV seconds before retrying",
				  fr_box_time_delta(pool->state.last_failed + pool->retry_delay - now));
		}

		return NULL;
	}

	/*
	 *	We limit the rate of new connections after a failed attempt.
	 */
	if (pool->state.pending > pool->pending_window) {
		pthread_mutex_unlock(&pool->mutex);
		RATE_LIMIT(ROPTIONAL(RWARN, WARN, "Cannot open a new connection due to rate limit after failure"));

		return NULL;
	}

	pool->state.pending++;
	number = pool->state.count++;

	/*
	 *	Don't starve out the thread trying to reconnect
	 *	the pool, by continuously opening new connections.
	 */
	while (pool->state.reconnecting) pthread_cond_wait(&pool->done_reconnecting, &pool->mutex);

	/*
	 *	Unlock the mutex while we try to open a new
	 *	connection.  If there are issues with the back-end,
	 *	opening a new connection may take a LONG time.  In
	 *	that case, we want the other connections to continue
	 *	to be used.
	 */
	pthread_mutex_unlock(&pool->mutex);

	/*
	 *	The true value for pending_window is the smaller of
	 *	free connection slots, or pool->pending_window.
	 */
	pending_window = (pool->max - pool->state.num);
	if (pool->pending_window < pending_window) pending_window = pool->pending_window;
	ROPTIONAL(RDEBUG2, DEBUG2, "Opening additional connection (%" PRIu64 "), %u of %u pending slots used",
		  number, pool->state.pending, pending_window);

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
	conn = pool->create(ctx, pool->opaque, pool->connect_timeout);
	if (!conn) {
		ROPTIONAL(RERROR, ERROR, "Opening connection failed (%" PRIu64 ")", number);

		pool->state.last_failed = now;
		pthread_mutex_lock(&pool->mutex);
		pool->pending_window = 1;
		pool->state.pending--;

		/*
		 *	Must be done inside the mutex, reconnect callback
		 *	may modify args.
		 */
		fr_pool_trigger_exec(pool, request, "fail");
		pthread_cond_broadcast(&pool->done_spawn);
		pthread_mutex_unlock(&pool->mutex);

		talloc_free(ctx);

		return NULL;
	}

	/*
	 *	And lock the mutex again while we link the new
	 *	connection back into the pool.
	 */
	pthread_mutex_lock(&pool->mutex);

	this = talloc_zero(pool, fr_pool_connection_t);
	if (!this) {
		pthread_cond_broadcast(&pool->done_spawn);
		pthread_mutex_unlock(&pool->mutex);

		talloc_free(ctx);

		return NULL;
	}
	talloc_link_ctx(this, ctx);

	this->created = now;
	this->connection = conn;
	this->in_use = in_use;

	this->number = number;
	this->last_reserved = fr_time();
	this->last_released = this->last_reserved;

	/*
	 *	The connection pool is starting up.  Insert the
	 *	connection into the heap.
	 */
	if (!in_use) fr_heap_insert(pool->heap, this);

	connection_link_head(pool, this);

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
	if ((pool->pending_window < pool->max) &&
	    ((pool->max_pending == 0) || (pool->pending_window < pool->max_pending))) {
		pool->pending_window++;
	}

	pool->state.last_spawned = fr_time();
	pool->delay_interval = pool->cleanup_interval;
	pool->state.next_delay = pool->cleanup_interval;
	pool->state.last_failed = 0;

	/*
	 *	Must be done inside the mutex, reconnect callback
	 *	may modify args.
	 */
	fr_pool_trigger_exec(pool, request, "open");

	pthread_cond_broadcast(&pool->done_spawn);
	if (unlock) pthread_mutex_unlock(&pool->mutex);

	/* coverity[missing_unlock] */
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
 * @param[in] pool	to modify.
 * @param[in] request	The current request.
 * @param[in] this	Connection to delete.
 */
static void connection_close_internal(fr_pool_t *pool, REQUEST *request, fr_pool_connection_t *this)
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

	fr_pool_trigger_exec(pool, request, "close");

	connection_unlink(pool, this);

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
 * @param[in] pool	to modify.
 * @param[in] request	The current request.
 * @param[in] this	Connection to manage.
 * @param[in] now	Current time.
 * @return
 *	- 0 if connection was closed.
 *	- 1 if connection handle was left open.
 */
static int connection_manage(fr_pool_t *pool, REQUEST *request, fr_pool_connection_t *this, time_t now)
{
	rad_assert(pool != NULL);
	rad_assert(this != NULL);

	/*
	 *	Don't terminated in-use connections
	 */
	if (this->in_use) return 1;

	if (this->needs_reconnecting) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Closing expired connection (%" PRIu64 "): Needs reconnecting",
			  this->number);
	do_delete:
		if (pool->state.num <= pool->min) {
			ROPTIONAL(RDEBUG2, DEBUG2, "You probably need to lower \"min\"");
		}
		connection_close_internal(pool, request, this);
		return 0;
	}

	if ((pool->max_uses > 0) &&
	    (this->num_uses >= pool->max_uses)) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Closing expired connection (%" PRIu64 "): Hit max_uses limit",
			  this->number);
		goto do_delete;
	}

	if ((pool->lifetime > 0) &&
	    ((this->created + pool->lifetime) < now)) {
		ROPTIONAL(RDEBUG2, DEBUG2, "Closing expired connection (%" PRIu64 "): Hit lifetime limit",
			  this->number);
		goto do_delete;
	}

	if ((pool->idle_timeout > 0) &&
	    ((this->last_released + pool->idle_timeout) < now)) {
		ROPTIONAL(RINFO, INFO, "Closing connection (%" PRIu64 "): Hit idle_timeout, was idle for %pVs",
		     	  this->number, fr_box_time_delta(now - this->last_released));
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
 * @note Must be called with the mutex held, will release mutex before returning.
 *
 * @param[in] pool	to manage.
 * @param[in] request	The current request.
 * @return 1
 */
static int connection_check(fr_pool_t *pool, REQUEST *request)
{
	uint32_t	spawn, idle, extra;
	fr_time_t		now = fr_time();
	fr_pool_connection_t	*this, *next;

	if ((now - pool->state.last_checked) >= NSEC) {
		pthread_mutex_unlock(&pool->mutex);
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
	if ((pool->state.num + pool->state.pending) < pool->min) {
		spawn = pool->min - (pool->state.num + pool->state.pending);
		extra = 0;

		ROPTIONAL(RINFO, INFO, "Need %i more connections to reach min connections (%i)", spawn, pool->min);

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
	} else if (idle < pool->spare) {
		/*
		 *	Not enough spare connections.  Spawn a few.
		 *	But cap the pool size at "max"
		 */
		spawn = pool->spare - idle;
		extra = 0;

		if ((pool->state.num + pool->state.pending + spawn) > pool->max) {
			spawn = pool->max - (pool->state.num + pool->state.pending);
		}

		ROPTIONAL(RINFO, INFO, "Need %i more connections to reach %i spares", spawn, pool->spare);

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
		pthread_mutex_unlock(&pool->mutex);
		(void) connection_spawn(pool, request, now, false, true);
		pthread_mutex_lock(&pool->mutex);
	}

	/*
	 *	We haven't spawned connections in a while, and there
	 *	are too many spare ones.  Close the one which has been
	 *	unused for the longest.
	 */
	if (extra && (now >= (pool->state.last_spawned + pool->delay_interval))) {
		fr_pool_connection_t *found = NULL;

		for (this = pool->tail; this != NULL; this = this->prev) {
			if (this->in_use) continue;

			if (!found || (this->last_reserved < found->last_reserved)) found = this;
		}

		if (!fr_cond_assert(found)) goto done;

		ROPTIONAL(RDEBUG2, DEBUG2, "Closing connection (%" PRIu64 "), from %d unused connections",
			  found->number, extra);
		connection_close_internal(pool, request, found);

		/*
		 *	Decrease the delay for the next time we clean up.
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
		connection_manage(pool, request, this, now);
	}

	pool->state.last_checked = now;
done:
	pthread_mutex_unlock(&pool->mutex);

	return 1;
}

/** Get a connection from the connection pool
 *
 * @note Must be called with the mutex free.
 *
 * @param[in] pool	to reserve the connection from.
 * @param[in] request	The current request.
 * @param[in] spawn	whether to spawn a new connection
 * @return
 *	- A pointer to the connection handle.
 *	- NULL on error.
 */
static void *connection_get_internal(fr_pool_t *pool, REQUEST *request, bool spawn)
{
	fr_time_t now;
	fr_pool_connection_t *this;

	if (!pool) return NULL;

	pthread_mutex_lock(&pool->mutex);

	now = fr_time();

	/*
	 *	Grab the link with the lowest latency, and check it
	 *	for limits.  If "connection manage" says the link is
	 *	no longer usable, go grab another one.
	 */
	do {
		this = fr_heap_peek(pool->heap);
		if (!this) break;
	} while (!connection_manage(pool, request, this, now));

	/*
	 *	We have a working connection.  Extract it from the
	 *	heap and use it.
	 */
	if (this) {
		fr_heap_extract(pool->heap, this);
		goto do_return;
	}

	if (pool->state.num == pool->max) {
		bool complain = false;

		/*
		 *	Rate-limit complaints.
		 */
		if ((now - pool->state.last_at_max) > NSEC) {
			complain = true;
			pool->state.last_at_max = now;
		}

		pthread_mutex_unlock(&pool->mutex);
		if (!RATE_LIMIT_ENABLED || complain) {
			ROPTIONAL(RERROR, ERROR, "No connections available and at max connection limit");
			/*
			 *	Must be done inside the mutex, reconnect callback
			 *	may modify args.
			 */
			fr_pool_trigger_exec(pool, request, "none");
		}

		return NULL;
	}

	pthread_mutex_unlock(&pool->mutex);

	if (!spawn) return NULL;

	ROPTIONAL(RDEBUG2, DEBUG2, "%i of %u connections in use.  You  may need to increase \"spare\"",
	       pool->state.active, pool->state.num);

	/*
	 *	Returns unlocked on failure, or locked on success
	 */
	this = connection_spawn(pool, request, now, true, false);
	if (!this) return NULL;

do_return:
	pool->state.active++;
	this->num_uses++;
	this->last_reserved = fr_time();
	this->in_use = true;

#ifdef PTHREAD_DEBUG
	this->pthread_id = pthread_self();
#endif
	pthread_mutex_unlock(&pool->mutex);

	ROPTIONAL(RDEBUG2, DEBUG2, "Reserved connection (%" PRIu64 ")", this->number);

	return this->connection;
}

/** Enable triggers for a connection pool
 *
 * @param[in] pool		to enable triggers for.
 * @param[in] trigger_prefix	prefix to prepend to all trigger names.  Usually a path
 *				to the module's trigger configuration .e.g.
 *      			@verbatim modules.<name>.pool @endverbatim
 *				@verbatim <trigger name> @endverbatim is appended to form
 *				the complete path.
 * @param[in] trigger_args	to make available in any triggers executed by the connection pool.
 *				These will usually be VALUE_PAIR (s) describing the host
 *				associated with the pool.
 *				Trigger args will be copied, input trigger_args should be freed
 *				if necessary.
 */
void fr_pool_enable_triggers(fr_pool_t *pool, char const *trigger_prefix, VALUE_PAIR *trigger_args)
{
	pool->triggers_enabled = true;

	talloc_const_free(pool->trigger_prefix);
	MEM(pool->trigger_prefix = trigger_prefix ? talloc_typed_strdup(pool, trigger_prefix) : "");

	fr_pair_list_free(&pool->trigger_args);

	if (!trigger_args) return;

	MEM(fr_pair_list_copy(pool, &pool->trigger_args, trigger_args) >= 0);
}

/** Create a new connection pool
 *
 * Allocates structures used by the connection pool, initialises the various
 * configuration options and counters, and sets the callback functions.
 *
 * Will also spawn the number of connections specified by the 'start' configuration
 * option.
 *
 * @note Will call the 'start' trigger.
 *
 * @param[in] ctx		Context to link pool's destruction to.
 * @param[in] cs		pool section.
 * @param[in] opaque data	pointer to pass to callbacks.
 * @param[in] c			Callback to create new connections.
 * @param[in] a			Callback to check the status of connections.
 * @param[in] log_prefix	prefix to prepend to all log messages.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_pool_t *fr_pool_init(TALLOC_CTX *ctx,
			CONF_SECTION const *cs,
			void *opaque,
			fr_pool_connection_create_t c, fr_pool_connection_alive_t a,
			char const *log_prefix)
{
	fr_pool_t		*pool = NULL;

	if (!cs || !opaque || !c) return NULL;

	/*
	 *	Pool is allocated in the NULL context as
	 *	threads are likely to allocate memory
	 *	beneath the pool.
	 */
	MEM(pool = talloc_zero(NULL, fr_pool_t));

	/*
	 *	Ensure the pool is freed at the same time
	 *	as its parent.
	 */
	if (talloc_link_ctx(ctx, pool) < 0) {
		ERROR("%s: Failed linking pool ctx", __FUNCTION__);
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
		pool->heap = fr_heap_talloc_create(pool, last_reserved_cmp, fr_pool_connection_t, heap_id);
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
		pool->heap = fr_heap_talloc_create(pool, last_released_cmp, fr_pool_connection_t, heap_id);
	}
	if (!pool->heap) {
		ERROR("%s: Failed creating connection heap", __FUNCTION__);
	error:
		fr_pool_free(pool);
		return NULL;
	}

	pool->log_prefix = log_prefix ? talloc_typed_strdup(pool, log_prefix) : "core";
	pthread_mutex_init(&pool->mutex, NULL);
	pthread_cond_init(&pool->done_spawn, NULL);
	pthread_cond_init(&pool->done_reconnecting, NULL);

	DEBUG2("Initialising connection pool");

	{
		CONF_SECTION *mutable;

		memcpy(&mutable, &cs, sizeof(mutable));

		if (cf_section_rules_push(mutable, pool_config) < 0) goto error;
		if (cf_section_parse(pool, pool, mutable) < 0) {
			PERROR("Configuration parsing failed");
			goto error;
		}
	}

	/*
	 *	Some simple limits
	 */
	if (pool->max == 0) {
		cf_log_err(cs, "Cannot set 'max' to zero");
		goto error;
	}

	/* coverity[missing_unlock] */
	pool->pending_window = (pool->max_pending > 0) ? pool->max_pending : pool->max;

	if (pool->min > pool->max) {
		cf_log_err(cs, "Cannot set 'min' to more than 'max'");
		goto error;
	}

	FR_INTEGER_BOUND_CHECK("max", pool->max, <=, 1024);
	FR_INTEGER_BOUND_CHECK("start", pool->start, <=, pool->max);
	FR_INTEGER_BOUND_CHECK("spare", pool->spare, <=, (pool->max - pool->min));

	if (pool->lifetime > 0) {
		FR_TIME_DELTA_COND_CHECK("idle_timeout", pool->idle_timeout,
					 (pool->idle_timeout <= pool->lifetime), 0);
	}

	if (pool->idle_timeout > 0) {
		FR_TIME_DELTA_BOUND_CHECK("cleanup_interval", pool->cleanup_interval, <=, pool->idle_timeout);
	}

	/*
	 *	Some libraries treat 0.0 as infinite timeout, others treat it
	 *	as instantaneous timeout.  Solve the inconsistency by making
	 *	the smallest allowable timeout 100ms.
	 */
	FR_TIME_DELTA_BOUND_CHECK("connect_timeout", pool->connect_timeout, >=, fr_time_delta_from_msec(100));

	/*
	 *	Don't open any connections.  Instead, force the limits
	 *	to only 1 connection.
	 *
	 */
	if (check_config) {
		pool->start = pool->min = pool->max = 1;
		return pool;
	}

	return pool;
}

int fr_pool_start(fr_pool_t *pool)
{
	uint32_t		i;
	fr_pool_connection_t 	*this;

	/*
	 *	Create all of the connections, unless the admin says
	 *	not to.
	 */
	for (i = 0; i < pool->start; i++) {
		/*
		 *	Call time() once for each spawn attempt as there
		 *	could be a significant delay.
		 */
		this = connection_spawn(pool, NULL, time(NULL), false, true);
		if (!this) {
			ERROR("Failed spawning initial connections");
			return -1;
		}
	}

	fr_pool_trigger_exec(pool, NULL, "start");

	return 0;
}

/** Allocate a new pool using an existing one as a template
 *
 * @param[in] ctx	to allocate new pool in.
 * @param[in] pool	to copy.
 * @param[in] opaque	data to pass to connection function.
 * @return
 *	- New connection pool.
 *	- NULL on error.
 */
fr_pool_t *fr_pool_copy(TALLOC_CTX *ctx, fr_pool_t *pool, void *opaque)
{
	fr_pool_t *copy;

	copy = fr_pool_init(ctx, pool->cs, opaque, pool->create, pool->alive, pool->log_prefix);
	if (!copy) return NULL;

	if (pool->trigger_prefix) fr_pool_enable_triggers(copy, pool->trigger_prefix, pool->trigger_args);

	return copy;
}

/** Get the number of connections currently in the pool
 *
 * @param[in] pool to count connections for.
 * @return the number of connections in the pool
 */
fr_pool_state_t const *fr_pool_state(fr_pool_t *pool)
{
	return &pool->state;
}

/** Connection pool get timeout
 *
 * @param[in] pool to get connection timeout for.
 * @return the connection timeout configured for the pool.
 */
fr_time_delta_t fr_pool_timeout(fr_pool_t *pool)
{
	return pool->connect_timeout;
}

/** Connection pool get start
 *
 * @param[in] pool to get connection start for.
 * @return the connection start value configured for the pool.
 */
int fr_pool_start_num(fr_pool_t *pool)
{
	return pool->start;
}

/** Return the opaque data associated with a connection pool
 *
 * @param pool to return data for.
 * @return opaque data associated with pool.
 */
void const *fr_pool_opaque(fr_pool_t *pool)
{
	return pool->opaque;
}

/** Increment pool reference by one.
 *
 * @param[in] pool to increment reference counter for.
 */
void fr_pool_ref(fr_pool_t *pool)
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
void fr_pool_reconnect_func(fr_pool_t *pool, fr_pool_reconnect_t reconnect)
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
 * @param[in] pool	to reconnect.
 * @param[in] request	The current request.
 * @return
 *	-  0 On success.
 *	- -1 If we couldn't create start connections, this may be ignored
 *	     depending on the context in which this function is being called.
 */
int fr_pool_reconnect(fr_pool_t *pool, REQUEST *request)
{
	uint32_t		i;
	fr_pool_connection_t	*this;
	time_t			now;

	pthread_mutex_lock(&pool->mutex);

	/*
	 *	Pause new spawn attempts (we release the mutex
	 *	during our cond wait).
	 */
	pool->state.reconnecting = true;

	/*
	 *	When the loop exits, we'll hold the lock for the pool,
	 *	and we're guaranteed the connection create callback
	 *	will not be using the opaque data.
	 */
	while (pool->state.pending) pthread_cond_wait(&pool->done_spawn, &pool->mutex);

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

		connection_close_internal(pool, request, this);
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
	if (pool->reconnect) pool->reconnect(pool, pool->opaque);

	/*
	 *	Must be done inside the mutex, reconnect callback
	 *	may modify args.
	 */
	fr_pool_trigger_exec(pool, request, "reconnect");

	/*
	 *	Allow new spawn attempts, and wakeup any threads
	 *	waiting to spawn new connections.
	 */
	pool->state.reconnecting = false;
	pthread_cond_broadcast(&pool->done_reconnecting);
	pthread_mutex_unlock(&pool->mutex);

	now = time(NULL);

	/*
	 *	Now attempt to spawn 'start' connections.
	 */
	for (i = 0; i < pool->start; i++) {
		this = connection_spawn(pool, request, now, false, true);
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
void fr_pool_free(fr_pool_t *pool)
{
	fr_pool_connection_t *this;

	if (!pool) return;

	/*
	 *	More modules hold a reference to this pool, don't free
	 *	it yet.
	 */
	if (pool->ref > 0) {
		pool->ref--;
		return;
	}

	DEBUG2("Removing connection pool");

	pthread_mutex_lock(&pool->mutex);

	/*
	 *	Don't loop over the list.  Just keep removing the head
	 *	until they're all gone.
	 */
	while ((this = pool->head) != NULL) {
		INFO("Closing connection (%" PRIu64 ")", this->number);

		connection_close_internal(pool, NULL, this);
	}

	fr_pool_trigger_exec(pool, NULL, "stop");

	rad_assert(pool->head == NULL);
	rad_assert(pool->tail == NULL);
	rad_assert(pool->state.num == 0);

	pthread_mutex_destroy(&pool->mutex);
	pthread_cond_destroy(&pool->done_spawn);
	pthread_cond_destroy(&pool->done_reconnecting);

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
 * @note fr_pool_connection_release must be called once the caller has finished
 * using the connection.
 *
 * @see fr_pool_connection_release
 * @param[in] pool	to reserve the connection from.
 * @param[in] request	The current request.
 * @return
 *	- A pointer to the connection handle.
 *	- NULL on error.
 */
void *fr_pool_connection_get(fr_pool_t *pool, REQUEST *request)
{
	return connection_get_internal(pool, request, true);
}

/** Release a connection
 *
 * Will mark a connection as unused and decrement the number of active
 * connections.
 *
 * @see fr_pool_connection_get
 * @param[in] pool	to release the connection in.
 * @param[in] request	The current request.
 * @param[in] conn	to release.
 */
void fr_pool_connection_release(fr_pool_t *pool, REQUEST *request, void *conn)
{
	fr_pool_connection_t	*this;
	fr_time_delta_t		held;
	bool			trigger_min = false, trigger_max = false;

	this = connection_find(pool, conn);
	if (!this) return;

	this->in_use = false;

	/*
	 *	Record when the connection was last released
	 */
	this->last_reserved = fr_time();
	pool->state.last_released = this->last_released;

	/*
	 *	This is done inside the mutex to ensure
	 *	updates are atomic.
	 */
	held = this->last_released - this->last_reserved;

	/*
	 *	Check we've not exceeded out trigger limits
	 *
	 *      These should only fire once per second.
	 */
	if (pool->held_trigger_min &&
	    (held < pool->held_trigger_min) &&
	    ((this->last_released - pool->state.last_held_min) >= NSEC)) {
	    	trigger_min = true;
	    	pool->state.last_held_min = this->last_released;
	}

	if (pool->held_trigger_min &&
	    (held > pool->held_trigger_max) &&
	    ((this->last_released - pool->state.last_held_max) >= NSEC)) {
	    	trigger_max = true;
	    	pool->state.last_held_max = this->last_released;
	}

	fr_stats_bins(&pool->state.held_stats, this->last_reserved, this->last_released);

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

	ROPTIONAL(RDEBUG2, DEBUG2, "Released connection (%" PRIu64 ")", this->number);

	/*
	 *	We mirror the "spawn on get" functionality by having
	 *	"delete on release".  If there are too many spare
	 *	connections, go manage the pool && clean some up.
	 */
	connection_check(pool, request);

	if (trigger_min) fr_pool_trigger_exec(pool, request, "min");
	if (trigger_max) fr_pool_trigger_exec(pool, request, "max");
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
 * @see fr_pool_connection_get
 * @param[in] pool	to reconnect the connection in.
 * @param[in] request	The current request.
 * @param[in] conn	to reconnect.
 * @return new connection handle if successful else NULL.
 */
void *fr_pool_connection_reconnect(fr_pool_t *pool, REQUEST *request, void *conn)
{
	fr_pool_connection_t	*this;

	if (!pool || !conn) return NULL;

	/*
	 *	If connection_find is successful the pool is now locked
	 */
	this = connection_find(pool, conn);
	if (!this) return NULL;

	ROPTIONAL(RINFO, INFO, "Deleting inviable connection (%" PRIu64 ")", this->number);

	connection_close_internal(pool, request, this);
	connection_check(pool, request);			/* Whilst we still have the lock (will release the lock) */

	/*
	 *	Return an existing connection or spawn a new one.
	 */
	return connection_get_internal(pool, request, true);
}

/** Delete a connection from the connection pool.
 *
 * Resolves the connection handle to a connection, then (if found)
 * closes, unlinks and frees that connection.
 *
 * @note Must be called with the mutex free.
 *
 * @param[in] pool	Connection pool to modify.
 * @param[in] request	The current request.
 * @param[in] conn	to delete.
 * @return
 *	- 0 If the connection could not be found.
 *	- 1 if the connection was deleted.
 */
int fr_pool_connection_close(fr_pool_t *pool, REQUEST *request, void *conn)
{
	fr_pool_connection_t *this;

	this = connection_find(pool, conn);
	if (!this) return 0;

	/*
	 *	Record the last time a connection was closed
	 */
	pool->state.last_closed = fr_time();

	ROPTIONAL(RINFO, INFO, "Deleting connection (%" PRIu64 ")", this->number);

	connection_close_internal(pool, request, this);
	connection_check(pool, request);
	return 1;
}
