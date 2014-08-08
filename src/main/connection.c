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
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

typedef struct fr_connection fr_connection_t;

static int fr_connection_pool_check(fr_connection_pool_t *pool);

extern bool check_config;

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
	fr_connection_t	*prev;		//!< Previous connection in list.
	fr_connection_t	*next;		//!< Next connection in list.

	time_t		created;	//!< Time connection was created.
	time_t		last_used;	//!< Last time the connection was
					//!< reserved.

	uint32_t	num_uses;	//!< Number of times the connection
					//!< has been reserved.
	uint64_t	number;		//!< Unique ID assigned when the
					//!< connection is created, these will
					//!< monotonically increase over the
					//!< lifetime of the connection pool.
	void		*connection;	//!< Pointer to whatever the module
					//!< uses for a connection handle.
	bool		in_use;		//!< Whether the connection is currently
					//!< reserved.
#ifdef PTHREAD_DEBUG
	pthread_t	pthread_id;	//!< When 'in_use == true'
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
	uint32_t       	start;		//!< Number of initial connections
	uint32_t       	min;		//!< Minimum number of concurrent
					//!< connections to keep open.
	uint32_t       	max;		//!< Maximum number of concurrent
					//!< connections to allow.
	uint32_t       	spare;		//!< Number of spare connections to try
	uint32_t       	retry_delay;	//!< seconds to delay re-open
					//!< after a failed open.
	uint32_t       	cleanup_interval; //!< Initial timer for how
					  //!< often we sweep the pool
					  //!< for free connections.
					  //!< (0 is infinite).
	int		delay_interval;  //!< When we next do a
					//!< cleanup.  Initialized to
					//!< cleanup_interval, and increase
					//!< from there based on the delay.
	int		next_delay;     //!< The next delay time.
					//!< cleanup.  Initialized to
					//!< cleanup_interval, and decays
					//!< from there.
	uint64_t	max_uses;	//!< Maximum number of times a
					//!< connection can be used before being
					//!< closed.
	uint32_t	lifetime;	//!< How long a connection can be open
					//!< before being closed (irrespective
					//!< of whether it's idle or not).
	uint32_t       	idle_timeout;	//!< How long a connection can be idle
					//!< before being closed.

	bool		trigger;	//!< If true execute connection triggers
					//!< associated with the connection
					//!< pool.

	bool		spread;		//!< If true requests will be spread
					//!< across all connections, instead of
					//!< re-using the most recently used
					//!< connections first.

	time_t		last_checked;	//!< Last time we pruned the connection
					//!< pool.
	time_t		last_spawned;	//!< Last time we spawned a connection.
	time_t		last_failed;	//!< Last time we tried to spawn a
					//!< a connection but failed.
	time_t		last_throttled; //!< Last time we refused to spawn a
					//!< connection because the last
					//!< connection failed, or we were
					//!< already spawning a connection.
	time_t		last_at_max;	//!< Last time we hit the maximum number
					//!< of allowed connections.

	uint64_t	count;		//!< Number of connections spawned over
					//!< the lifetime of the pool.
	uint32_t       	num;		//!< Number of connections in the pool.
	uint32_t	active;	 	//!< Number of currently reserved connections.

	fr_connection_t	*head;		//!< Start of the connection list.
	fr_connection_t *tail;		//!< End of the connection list.

	bool		spawning;	//!< Whether we are currently attempting
					//!< to spawn a new connection.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t	mutex;		//!< Mutex used to keep consistent state
					//!< when making modifications in
					//!< threaded mode.
#endif

	CONF_SECTION	*cs;		//!< Configuration section holding
					//!< the section of parsed config file
					//!< that relates to this pool.
	void		*opaque;	//!< Pointer to context data that will
					//!< be passed to callbacks.

	char const	*log_prefix;	//!< Log prefix to prepend to all log
					//!< messages created by the connection
					//!< pool code.

	fr_connection_create_t	create;	//!< Function used to create new
					//!< connections.
	fr_connection_alive_t	alive;	//!< Function used to check status
					//!< of connections.
};

#ifndef HAVE_PTHREAD_H
#define pthread_mutex_lock(_x)
#define pthread_mutex_unlock(_x)
#endif

static const CONF_PARSER connection_config[] = {
	{ "start", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, start), "5" },
	{ "min", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, min), "5" },
	{ "max", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, max), "10" },
	{ "spare", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, spare), "3" },
	{ "uses", FR_CONF_OFFSET(PW_TYPE_INTEGER64, fr_connection_pool_t, max_uses), "0" },
	{ "lifetime", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, lifetime), "0" },
	{ "cleanup_delay", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, cleanup_interval), NULL},
	{ "cleanup_interval", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, cleanup_interval), "30" },
	{ "idle_timeout", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, idle_timeout), "60" },
	{ "retry_delay", FR_CONF_OFFSET(PW_TYPE_INTEGER, fr_connection_pool_t, retry_delay), "1" },
	{ "spread", FR_CONF_OFFSET(PW_TYPE_BOOLEAN, fr_connection_pool_t, spread), "no" },
	{ NULL, -1, 0, NULL, NULL }
};

/** Removes a connection from the connection list
 *
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in] this Connection to delete.
 */
static void fr_connection_unlink(fr_connection_pool_t *pool,
				 fr_connection_t *this)
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
static void fr_connection_link_head(fr_connection_pool_t *pool,
				    fr_connection_t *this)
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

/** Adds a connection to the tail of the connection list
 *
 * @note Must be called with the mutex held.
 *
 * @param[in,out] pool to modify.
 * @param[in] this Connection to add.
 */
static void fr_connection_link_tail(fr_connection_pool_t *pool,
				    fr_connection_t *this)
{
	rad_assert(pool != NULL);
	rad_assert(this != NULL);
	rad_assert(pool->head != this);
	rad_assert(pool->tail != this);

	if (pool->tail) {
		pool->tail->next = this;
	}
	this->prev = pool->tail;
	this->next = NULL;
	pool->tail = this;
	if (!pool->head) {
		rad_assert(this->prev == NULL);
		pool->head = this;
	} else {
		rad_assert(this->prev != NULL);
	}
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
 * @return the new connection struct or NULL on error.
 */
static fr_connection_t *fr_connection_spawn(fr_connection_pool_t *pool,
					    time_t now, bool in_use)
{
	TALLOC_CTX *ctx;

	fr_connection_t *this;
	void *conn;

	rad_assert(pool != NULL);

	/*
	 *	Prevent all threads from blocking if the resource
	 *	were managing connections for appears to be unavailable.
	 */
	if ((pool->num == 0) && pool->spawning) {
		return NULL;
	}

	pthread_mutex_lock(&pool->mutex);
	rad_assert(pool->num <= pool->max);

	/*
	 *	Don't spawn multiple connections at the same time.
	 */
	if (pool->spawning) {
		pthread_mutex_unlock(&pool->mutex);

		ERROR("%s: Cannot open new connection, connection spawning already in progress", pool->log_prefix);
		return NULL;
	}

	/*
	 *	If the last attempt failed, wait a bit before
	 *	retrying.
	 */
	if (pool->last_failed && ((pool->last_failed + pool->retry_delay) > now)) {
		bool complain = false;

		if (pool->last_throttled != now) {
			complain = true;

			pool->last_throttled = now;
		}

		pthread_mutex_unlock(&pool->mutex);

		if (!RATE_LIMIT_ENABLED || complain) {
			ERROR("%s: Last connection attempt failed, waiting %d seconds before retrying",
			      pool->log_prefix, pool->retry_delay);
		}

		return NULL;
	}

	pool->spawning = true;

	/*
	 *	Unlock the mutex while we try to open a new
	 *	connection.  If there are issues with the back-end,
	 *	opening a new connection may take a LONG time.  In
	 *	that case, we want the other connections to continue
	 *	to be used.
	 */
	pthread_mutex_unlock(&pool->mutex);

	INFO("%s: Opening additional connection (%" PRIu64 ")", pool->log_prefix, pool->count);

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
	conn = pool->create(ctx, pool->opaque);
	if (!conn) {
		ERROR("%s: Opening connection failed (%" PRIu64 ")", pool->log_prefix, pool->count);

		pool->last_failed = now;
		pool->spawning = false; /* atomic, so no lock is needed */
		return NULL;
	}

	/*
	 *	And lock the mutex again while we link the new
	 *	connection back into the pool.
	 */
	pthread_mutex_lock(&pool->mutex);

	this = talloc_zero(pool, fr_connection_t);
	if (!this) {
		pthread_mutex_unlock(&pool->mutex);
		return NULL;
	}
	fr_link_talloc_ctx_free(this, ctx);

	this->created = now;
	this->connection = conn;
	this->in_use = in_use;

	this->number = pool->count++;
	this->last_used = now;
	fr_connection_link_head(pool, this);
	pool->num++;
	pool->spawning = false;
	pool->last_spawned = time(NULL);
	pool->delay_interval = pool->cleanup_interval;
	pool->next_delay = pool->cleanup_interval;
	pool->last_failed = 0;

	pthread_mutex_unlock(&pool->mutex);

	if (pool->trigger) exec_trigger(NULL, pool->cs, "open", true);

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
static void fr_connection_close(fr_connection_pool_t *pool,
				fr_connection_t *this)
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

		rad_assert(pool->active != 0);
		pool->active--;
	}

	if (pool->trigger) exec_trigger(NULL, pool->cs, "close", true);

	fr_connection_unlink(pool, this);
	rad_assert(pool->num > 0);
	pool->num--;
	talloc_free(this);
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
 * @return the connection containing the specified handle, or NULL if non is
 * found.
 */
static fr_connection_t *fr_connection_find(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t *this;

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
			return this;
		}
	}

	pthread_mutex_unlock(&pool->mutex);
	return NULL;
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
 * @return 0 if the connection could not be found, else 1.
 */
int fr_connection_del(fr_connection_pool_t *pool, void *conn)
{
	fr_connection_t *this;

	this = fr_connection_find(pool, conn);
	if (!this) return 0;

	INFO("%s: Deleting connection (%" PRIu64 ")", pool->log_prefix, this->number);

	fr_connection_close(pool, this);
	fr_connection_pool_check(pool);
	return 1;
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
void fr_connection_pool_delete(fr_connection_pool_t *pool)
{
	fr_connection_t *this, *next;

	if (!pool) return;

	DEBUG("%s: Removing connection pool", pool->log_prefix);

	pthread_mutex_lock(&pool->mutex);

	for (this = pool->head; this != NULL; this = next) {
		next = this->next;

		INFO("%s: Closing connection (%" PRIu64 ")", pool->log_prefix, this->number);

		fr_connection_close(pool, this);
	}

	if (pool->trigger) exec_trigger(NULL, pool->cs, "stop", true);

	rad_assert(pool->head == NULL);
	rad_assert(pool->tail == NULL);
	rad_assert(pool->num == 0);

	talloc_free(pool);
}

/** Initialise a module specific connection pool
 *
 * @see fr_connection_pool_init
 *
 * @param[in] module section.
 * @param[in] opaque data pointer to pass to callbacks.
 * @param[in] c Callback to create new connections.
 * @param[in] a Callback to check the status of connections.
 * @param[in] prefix override, if NULL will be set automatically from the module CONF_SECTION.
 * @return A new connection pool or NULL on error.
 */
fr_connection_pool_t *fr_connection_pool_module_init(CONF_SECTION *module,
						     void *opaque,
						     fr_connection_create_t c,
						     fr_connection_alive_t a,
						     char const *prefix)
{
	CONF_SECTION *cs, *mycs;
	char buff[128];

	fr_connection_pool_t *pool;

	int ret;

#define CONNECTION_POOL_CF_KEY "connection_pool"
#define parent_name(_x) cf_section_name(cf_item_parent(cf_sectiontoitem(_x)))

	if (!prefix) {
		char const *cs_name1, *cs_name2;
		cs_name1 = cf_section_name1(module);
		cs_name2 = cf_section_name2(module);
		if (!cs_name2) cs_name2 = cs_name1;

		snprintf(buff, sizeof(buff), "rlm_%s (%s)", cs_name1, cs_name2);
		prefix = buff;
	}

	/*
	 *	Get sibling's pool config section
	 */
	ret = find_module_sibling_section(&cs, module, "pool");
	switch (ret) {
	case -1:
		return NULL;

	case 1:
		DEBUG4("%s: Using pool section from \"%s\"", prefix, parent_name(cs));
		break;

	case 0:
		DEBUG4("%s: Using local pool section", prefix);
		break;
	}

	/*
	 *	Get our pool config section
	 */
	mycs = cf_section_sub_find(module, "pool");
	if (!mycs) {
		DEBUG4("%s: Adding pool section to \"%s\" to store pool references", prefix,
		       cf_section_name(module));

		mycs = cf_section_alloc(module, "pool", NULL);
		cf_section_add(module, mycs);
	}

	/*
	 *	Sibling didn't have a pool config section
	 *	Use our own local pool.
	 */
	if (!cs) {
		DEBUG4("%s: \"%s.pool\" section not found, using \"%s.pool\"", prefix,
		       parent_name(cs), parent_name(mycs));
		cs = mycs;
	}

	/*
	 *	If fr_connection_pool_init has already been called
	 *	for this config section, reuse the previous instance.
	 *
	 *	This allows modules to pass in the config sections
	 *	they would like to use the connection pool from.
	 */
	pool = cf_data_find(cs, CONNECTION_POOL_CF_KEY);
	if (!pool) {
		DEBUG4("%s: No pool reference found in \"%s.pool\"", prefix, parent_name(cs));
		pool = fr_connection_pool_init(module, cs, opaque, c, a, prefix);
		if (!pool) return NULL;

		DEBUG4("%s: Adding pool reference %p to \"%s.pool\"", prefix, pool, parent_name(cs));
		cf_data_add(cs, CONNECTION_POOL_CF_KEY, pool, NULL);
		return pool;
	}

	DEBUG4("%s: Found pool reference %p in \"%s.pool\"", prefix, pool, parent_name(cs));

	/*
	 *	We're reusing pool data add it to our local config
	 *	section. This allows other modules to transitively
	 *	re-use a pool through this module.
	 */
	if (mycs != cs) {
		DEBUG4("%s: Copying pool reference %p from \"%s.pool\" to \"%s.pool\"", prefix, pool,
		       parent_name(cs), parent_name(mycs));
		cf_data_add(mycs, CONNECTION_POOL_CF_KEY, pool, NULL);
	}

	return pool;
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
 * @param[in] parent section.
 * @param[in] cs pool section.
 * @param[in] opaque data pointer to pass to callbacks.
 * @param[in] c Callback to create new connections.
 * @param[in] a Callback to check the status of connections.
 * @param[in] prefix to prepend to all log messages.
 * @return A new connection pool or NULL on error.
 */
fr_connection_pool_t *fr_connection_pool_init(CONF_SECTION *parent,
					      CONF_SECTION *cs,
					      void *opaque,
					      fr_connection_create_t c,
					      fr_connection_alive_t a,
					      char const *prefix)
{
	uint32_t i;
	fr_connection_pool_t *pool;
	fr_connection_t *this;
	time_t now;

	if (!parent || !cs || !opaque || !c) return NULL;

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
	if (fr_link_talloc_ctx_free(cs, pool) < 0) {
		talloc_free(pool);

		return NULL;
	}

	pool->cs = cs;
	pool->opaque = opaque;
	pool->create = c;
	pool->alive = a;

	pool->head = pool->tail = NULL;

	pool->log_prefix = prefix ? talloc_typed_strdup(pool, prefix) : "core";

#ifdef HAVE_PTHREAD_H
	pthread_mutex_init(&pool->mutex, NULL);
#endif

	DEBUG("%s: Initialising connection pool", pool->log_prefix);

	if (cf_section_parse(cs, pool, connection_config) < 0) goto error;
	if (cf_section_sub_find(cs, "trigger")) pool->trigger = true;

	/*
	 *	Some simple limits
	 */
	if (pool->max == 0) {
		cf_log_err_cs(cs, "Cannot set 'max' to zero");
		goto error;
	}

	if (pool->min > pool->max) {
		cf_log_err_cs(cs, "Cannot set 'min' to more than 'max'");
		goto error;
	}

	if (pool->max > 1024) pool->max = 1024;
	if (pool->start > pool->max) pool->start = pool->max;
	if (pool->spare > (pool->max - pool->min)) {
		pool->spare = pool->max - pool->min;
	}
	if ((pool->lifetime > 0) && (pool->idle_timeout > pool->lifetime)) {
		pool->idle_timeout = 0;
	}

	if ((pool->idle_timeout > 0) && (pool->cleanup_interval > pool->idle_timeout)) {
		pool->cleanup_interval = pool->idle_timeout;
	}

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
			fr_connection_pool_delete(pool);
			return NULL;
		}
	}

	if (pool->trigger) exec_trigger(NULL, pool->cs, "start", true);

	return pool;
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
 * @return 0 if the connection was closed, otherwise 1.
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

	if ((pool->max_uses > 0) &&
	    (this->num_uses >= pool->max_uses)) {
		DEBUG("%s: Closing expired connection (%" PRIu64 "): Hit max_uses limit", pool->log_prefix,
		      this->number);
	do_delete:
		if (pool->num <= pool->min) {
			RATE_LIMIT(WARN("%s: You probably need to lower \"min\"", pool->log_prefix));
		}
		fr_connection_close(pool, this);
		return 0;
	}

	if ((pool->lifetime > 0) &&
	    ((this->created + pool->lifetime) < now)) {
		DEBUG("%s: Closing expired connection (%" PRIu64 ")", pool->log_prefix, this->number);
		goto do_delete;
	}

	if ((pool->idle_timeout > 0) &&
	    ((this->last_used + pool->idle_timeout) < now)) {
		INFO("%s: Closing connection (%" PRIu64 "): Hit idle_timeout, was idle for %u seconds",
		     pool->log_prefix, this->number, (int) (now - this->last_used));
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

	if (pool->last_checked == now) {
		pthread_mutex_unlock(&pool->mutex);
		return 1;
	}

	/*
	 *	Some idle connections are OK, if they're within the
	 *	configured "spare" range.  Any extra connections
	 *	outside of that range can be closed.
	 */
	idle = pool->num - pool->active;
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
	if (pool->num <= pool->min) {
		if (pool->spawning) {
			spawn = 0;
		} else {
			spawn = pool->min - pool->num;
		}
		extra = 0;

	} else if (pool->num >= pool->max) {
		/*
		 *	Ensure we don't spawn more connections.  If
		 *	there are extra idle connections, we can
		 *	delete all of them.
		 */
		spawn = 0;
		/* leave extra alone from above */

	} else if (idle <= pool->spare) {
		/*
		 *	Not enough spare connections.  Spawn a few.
		 *	But cap the pool size at "max"
		 */
		spawn = pool->spare - idle;
		extra = 0;

		if ((pool->num + spawn) > pool->max) {
			spawn = pool->max - pool->num;
		}

	} else if ((pool->min + extra) >= pool->num) {
		/*
		 *	If closing the extra connections would take us
		 *	below "min", then don't do that.  Cap the
		 *	spare connections at the ones which will take
		 *	us exactly to "min".
		 */
		spawn = 0;
		extra = pool->num - pool->min;

	} else {
		/*
		 *	Closing the "extra" connections won't take us
		 *	below "min".  It's therefore safe to close
		 *	them all.
		 */
		spawn = 0;
		/* leave extra alone from above */
	}

	if (spawn) {
		INFO("%s: %i of %u connections in use.  Need more spares", pool->log_prefix, pool->active, pool->num);
		pthread_mutex_unlock(&pool->mutex);
		fr_connection_spawn(pool, now, false); /* ignore return code */
		pthread_mutex_lock(&pool->mutex);
	}

	/*
	 *	We haven't spawned connections in a while, and there
	 *	are too many spare ones.  Close the one which has been
	 *	unused for the longest.
	 */
	if (extra && (now >= (pool->last_spawned + pool->delay_interval))) {
		fr_connection_t *found;

		found = NULL;
		for (this = pool->tail; this != NULL; this = this->prev) {
			if (this->in_use) continue;

			if (!found ||
			   (this->last_used < found->last_used)) {
				found = this;
			}
		}

		rad_assert(found != NULL);

		INFO("%s: Closing connection (%" PRIu64 "), from %d unused connections", pool->log_prefix,
		     found->number, extra);
		fr_connection_close(pool, found);

		/*
		 *	Decrease the delay for the next time we clean
		 *	up.
		 */
		pool->next_delay >>= 1;
		if (pool->next_delay == 0) pool->next_delay = 1;
		pool->delay_interval += pool->next_delay;
	}

	/*
	 *	Pass over all of the connections in the pool, limiting
	 *	lifetime, idle time, max requests, etc.
	 */
	for (this = pool->head; this != NULL; this = next) {
		next = this->next;
		fr_connection_manage(pool, this, now);
	}

	pool->last_checked = now;
	pthread_mutex_unlock(&pool->mutex);

	return 1;
}

/** Get a connection from the connection pool
 *
 * @param[in,out] pool to reserve the connection from.
 * @param[in] spawn whether to spawn a new connection
 * @return a pointer to the connection handle, or NULL on error.
 */
static void *fr_connection_get_internal(fr_connection_pool_t *pool, int spawn)
{
	time_t now;
	fr_connection_t *this;

	if (!pool) return NULL;

	pthread_mutex_lock(&pool->mutex);

	now = time(NULL);
	for (this = pool->head; this != NULL; this = this->next) {
		if (!this->in_use) goto do_return;
	}
	rad_assert(pool->active == pool->num);

	if (pool->num == pool->max) {
		bool complain = false;

		/*
		 *	Rate-limit complaints.
		 */
		if (pool->last_at_max != now) {
			complain = true;
			pool->last_at_max = now;
		}

		pthread_mutex_unlock(&pool->mutex);

		if (!RATE_LIMIT_ENABLED || complain) {
			ERROR("%s: No connections available and at max connection limit", pool->log_prefix);
		}

		return NULL;
	}

	pthread_mutex_unlock(&pool->mutex);

	if (!spawn) return NULL;

	WARN("%s: %i of %u connections in use.  You probably need to increase \"spare\"", pool->log_prefix,
	     pool->active, pool->num);
	this = fr_connection_spawn(pool, now, true); /* MY connection! */
	if (!this) return NULL;
	pthread_mutex_lock(&pool->mutex);

do_return:
	pool->active++;
	this->num_uses++;
	this->last_used = now;
	this->in_use = true;

#ifdef PTHREAD_DEBUG
	this->pthread_id = pthread_self();
#endif
	pthread_mutex_unlock(&pool->mutex);

	DEBUG("%s: Reserved connection (%" PRIu64 ")", pool->log_prefix, this->number);

	return this->connection;
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
 * @return a pointer to the connection handle, or NULL on error.
 */
void *fr_connection_get(fr_connection_pool_t *pool)
{
	return fr_connection_get_internal(pool, true);
}

/** Get the number of connections currently in the pool
 *
 * @param pool to count connections for.
 * @return the number of connections in the pool
 */
int fr_connection_get_num(fr_connection_pool_t *pool)
{
	return pool->num;
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
	 *	Determines whether the last used connection gets
	 *	re-used first.
	 */
	if (pool->spread) {
		/*
		 *	Put it at the tail of the list, so
		 *	that it will get re-used last.
		 */
		if (this != pool->tail) {
			fr_connection_unlink(pool, this);
			fr_connection_link_tail(pool, this);
		}
	} else {
		/*
		 *	Put it at the head of the list, so
		 *	that it will get re-used quickly.
		 */
		if (this != pool->head) {
			fr_connection_unlink(pool, this);
			fr_connection_link_head(pool, this);
		}
	}

	rad_assert(pool->active != 0);
	pool->active--;

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
 * Will attempt to create a new connection handle using the create callback,
 * and if this is successful the new handle will be assigned to the existing
 * pool connection.
 *
 * If this is not successful, the connection will be removed from the pool.
 *
 * When implementing a module that uses the connection pool API, it is advisable
 * to pass a pointer to the pointer to the handle (void **conn)
 * to all functions which may call reconnect. This is so that if a new handle
 * is created and returned, the handle pointer can be updated up the callstack,
 * and a function higher up the stack doesn't attempt to use a now invalid
 * connection handle.
 *
 * @warning After calling reconnect the caller *MUST NOT* attempt to use
 * the old handle in any other operations, as its memory will have been freed.
 *
 * @see fr_connection_get
 * @param[in,out] pool to reconnect the connection in.
 * @param[in,out] conn to reconnect.
 * @return new connection handle if successful else NULL.
 */
void *fr_connection_reconnect(fr_connection_pool_t *pool, void *conn)
{
	void *new_conn;
	fr_connection_t *this;
	uint64_t conn_number;
	TALLOC_CTX *ctx;

	if (!pool || !conn) return NULL;

	/*
	 *	If fr_connection_find is successful the pool is now locked
	 */
	this = fr_connection_find(pool, conn);
	if (!this) return NULL;


	conn_number = this->number;

	/*
	 *	Destroy any handles associated with the fr_connection_t
	 */
	talloc_free_children(this);

	DEBUG("%s: Reconnecting (%" PRIu64 ")", pool->log_prefix, conn_number);

	/*
	 *	Allocate a new top level ctx for the create callback
	 *	to hang its memory off of.
	 */
	ctx = talloc_init("fr_connection_ctx");
	if (!ctx) return NULL;
	fr_link_talloc_ctx_free(this, ctx);

	new_conn = pool->create(ctx, pool->opaque);
	if (!new_conn) {
		/*
		 *	We can't create a new connection, so close
		 *	this one.
		 */
		fr_connection_close(pool, this);

		/*
		 *	Maybe there's a connection which is unused and
		 *	available.  If so, return it.
		 */
		pthread_mutex_unlock(&pool->mutex);
		new_conn = fr_connection_get_internal(pool, false);
		if (new_conn) return new_conn;

		RATE_LIMIT(ERROR("%s: Failed to reconnect (%" PRIu64 "), no free connections are available",
				 pool->log_prefix, conn_number));

		return NULL;
	}

	if (pool->trigger) exec_trigger(NULL, pool->cs, "close", true);
	this->connection = new_conn;
	pthread_mutex_unlock(&pool->mutex);

	return new_conn;
}
