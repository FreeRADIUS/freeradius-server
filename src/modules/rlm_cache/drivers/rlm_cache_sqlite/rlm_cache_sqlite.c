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
 * @file rlm_cache_sqlite.c
 * @brief Cache stored in a SQLite database.
 *
 * The database has one table, "cache", with one row per entry:
 *
 *	key	TEXT PRIMARY KEY	the cache key
 *	expires	INTEGER			the time at which the entry expires, in
 *					seconds since the epoch (not a TTL)
 *	data	TEXT			the entry, as written by cache_serialize()
 *
 * The driver removes the rows which have expired when it inserts an
 * entry, but not more than once a second.  sqlite is blocking for
 * every read / write, and we don't want to serialize all cache
 * entries.
 *
 * @copyright 2026 Network RADIUS SAS <legal@networkradius.com>
 */
#include <sqlite3.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

#include "../../rlm_cache.h"
#include "../../serialize.h"

#ifdef HAVE_PTHREAD_H
#  define PTHREAD_MUTEX_LOCK pthread_mutex_lock
#  define PTHREAD_MUTEX_UNLOCK pthread_mutex_unlock
#else
#  define PTHREAD_MUTEX_LOCK(_x)
#  define PTHREAD_MUTEX_UNLOCK(_x)
#endif

/** Mutable state
 *
 * The driver instance is read-only after instantiation.
 *
 * The server may drop privileges after it instantiates the module.  The
 * database is opened on the first request, so that the file belongs to the
 * UID which runs the server.
 *
 * @todo - create the file on instantiation, with the correct UID / GID.
 */
typedef struct rlm_cache_sqlite_state {
	sqlite3			*db;		//!< Database handle, NULL until the first request.

	sqlite3_stmt		*find;		//!< Retrieve an entry.
	sqlite3_stmt		*insert;	//!< Add or replace an entry.
	sqlite3_stmt		*expire;	//!< Remove an entry.
	sqlite3_stmt		*count;		//!< Count the entries which have not expired.
	sqlite3_stmt		*purge;		//!< Remove the entries which have expired.
	time_t			last_purge;	//!< When the driver last removed the entries which have expired.

#ifdef HAVE_PTHREAD_H
	pthread_mutex_t		mutex;		//!< One request at a time uses the database handle.
#endif
} rlm_cache_sqlite_state_t;

typedef struct rlm_cache_sqlite {
	char const		*filename;	//!< Path of the database file.
	rlm_cache_sqlite_state_t *state;	//!< See above.
} rlm_cache_sqlite_t;

static const CONF_PARSER driver_config[] = {
	{ "filename", FR_CONF_OFFSET(PW_TYPE_STRING, rlm_cache_sqlite_t, filename),
	  "${localstatedir}/spool/radius/cache.sqlite" },
	CONF_PARSER_TERMINATOR
};

static char const *schema[] = {
	"CREATE TABLE IF NOT EXISTS cache ("
		"key TEXT PRIMARY KEY NOT NULL, "
		"expires INTEGER NOT NULL, "
		"data TEXT NOT NULL)",
	"CREATE INDEX IF NOT EXISTS cache_expires ON cache (expires)",
	NULL
};

static int _mod_detach(rlm_cache_sqlite_t *driver)
{
	rlm_cache_sqlite_state_t *state = driver->state;

	if (!state) return 0;

	sqlite3_finalize(state->find);
	sqlite3_finalize(state->insert);
	sqlite3_finalize(state->expire);
	sqlite3_finalize(state->count);
	sqlite3_finalize(state->purge);
	if (state->db) sqlite3_close(state->db);

#ifdef HAVE_PTHREAD_H
	pthread_mutex_destroy(&state->mutex);
#endif
	talloc_free(state);

	return 0;
}

/** Create a new rlm_cache_sqlite instance
 *
 * @param conf sqlite specific conf section.
 * @param inst main rlm_cache instance.
 * @return 0 on success, -1 on failure.
 */
static int mod_instantiate(CONF_SECTION *conf, rlm_cache_t *inst)
{
	rlm_cache_sqlite_t *driver;

	driver = talloc_zero(inst, rlm_cache_sqlite_t);
	talloc_set_destructor(driver, _mod_detach);
	if (cf_section_parse(conf, driver, driver_config) < 0) return -1;

	if (!driver->filename || !*driver->filename) {
		cf_log_err_cs(conf, "The 'filename' option must not be empty");
		return -1;
	}

	driver->state = talloc_zero(NULL, rlm_cache_sqlite_state_t);
	if (!driver->state) return -1;

#ifdef HAVE_PTHREAD_H
	if (pthread_mutex_init(&driver->state->mutex, NULL) < 0) {
		ERROR("Failed initializing mutex: %s", fr_syserror(errno));
		return -1;
	}
#endif

	inst->driver = driver;

	return 0;
}

static int prepare(REQUEST *request, sqlite3 *db, sqlite3_stmt **out, char const *sql)
{
	if (sqlite3_prepare_v2(db, sql, -1, out, NULL) != SQLITE_OK) {
		REDEBUG("Failed preparing \"%s\": %s", sql, sqlite3_errmsg(db));
		return -1;
	}

	return 0;
}

/** Open the database and create the table, if the database is not open
 *
 * The caller holds the mutex.
 *
 * @return 0 on success, -1 on failure.
 */
static int db_open(REQUEST *request, rlm_cache_sqlite_t const *driver)
{
	rlm_cache_sqlite_state_t *state = driver->state;
	sqlite3			*db = NULL;
	char			*dir, *p;
	char			*err = NULL;
	int			i;

	if (state->db) return 0;

	/*
	 *	Create the directory which holds the database.
	 */
	dir = talloc_strdup(NULL, driver->filename);
	if (!dir) return -1;

	p = strrchr(dir, FR_DIR_SEP);
	if (p && (p != dir)) {
		*p = '\0';
		if (rad_mkdir(dir, 0700, -1, -1) < 0) {
			REDEBUG("Failed creating directory \"%s\": %s", dir, fr_syserror(errno));
			talloc_free(dir);
			return -1;
		}
	}
	talloc_free(dir);

	if (sqlite3_open_v2(driver->filename, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
		REDEBUG("Failed opening \"%s\": %s", driver->filename, db ? sqlite3_errmsg(db) : "out of memory");
		if (db) sqlite3_close(db);
		return -1;
	}

	/*
	 *	Other processes may use the same file.  Wait for them instead of
	 *	failing.
	 */
	sqlite3_busy_timeout(db, 5000);

	for (i = 0; schema[i]; i++) {
		if (sqlite3_exec(db, schema[i], NULL, NULL, &err) != SQLITE_OK) {
			REDEBUG("Failed running \"%s\": %s", schema[i], err);
			sqlite3_free(err);
			sqlite3_close(db);
			return -1;
		}
	}

	if ((prepare(request, db, &state->find, "SELECT expires, data FROM cache WHERE key = ?") < 0) ||
	    (prepare(request, db, &state->insert,
		     "INSERT OR REPLACE INTO cache (key, expires, data) VALUES (?, ?, ?)") < 0) ||
	    (prepare(request, db, &state->expire, "DELETE FROM cache WHERE key = ?") < 0) ||
	    (prepare(request, db, &state->count, "SELECT COUNT(*) FROM cache WHERE expires >= ?") < 0) ||
	    (prepare(request, db, &state->purge, "DELETE FROM cache WHERE expires < ?") < 0)) {
		sqlite3_finalize(state->find);
		sqlite3_finalize(state->insert);
		sqlite3_finalize(state->expire);
		sqlite3_finalize(state->count);
		sqlite3_finalize(state->purge);
		state->find = state->insert = state->expire = state->count = state->purge = NULL;
		sqlite3_close(db);
		return -1;
	}

	state->db = db;

	return 0;
}

/** Lock the database handle, and open the database if necessary
 *
 * @param out Where to write the database handle.
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @return 0 on success, -1 on failure.
 */
static int cache_acquire(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request)
{
	rlm_cache_sqlite_t const *driver = inst->driver;

	PTHREAD_MUTEX_LOCK(&driver->state->mutex);

	if (db_open(request, driver) < 0) {
		PTHREAD_MUTEX_UNLOCK(&driver->state->mutex);
		return -1;
	}

	*out = driver->state->db;

	return 0;
}

static void cache_release(rlm_cache_t *inst, UNUSED REQUEST *request, rlm_cache_handle_t **handle)
{
#ifdef HAVE_PTHREAD_H
	rlm_cache_sqlite_t const *driver = inst->driver;
#endif

	PTHREAD_MUTEX_UNLOCK(&driver->state->mutex);

	*handle = NULL;
}

/** Run a statement which returns no rows, and reset the statement
 *
 * @return CACHE_OK on success, CACHE_ERROR on failure.
 */
static cache_status_t step_done(REQUEST *request, rlm_cache_handle_t *handle, sqlite3_stmt *stmt)
{
	int ret = sqlite3_step(stmt);

	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);

	if (ret != SQLITE_DONE) {
		REDEBUG("Failed running statement: %s", sqlite3_errmsg(handle));
		return CACHE_ERROR;
	}

	return CACHE_OK;
}

/** Locate a cache entry
 *
 * @param out Where to write the pointer to the cache entry.
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Database handle.
 * @param key to search for.
 * @return CACHE_OK on success, CACHE_MISS if no entry found, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_find(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
				       rlm_cache_handle_t **handle, char const *key)
{
	rlm_cache_sqlite_t const *driver = inst->driver;
	sqlite3_stmt		*stmt = driver->state->find;
	rlm_cache_entry_t	*c;
	char			*data;
	int64_t			expires;
	int			ret;

	*out = NULL;

	sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
	ret = sqlite3_step(stmt);
	if (ret == SQLITE_DONE) {
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return CACHE_MISS;
	}

	if (ret != SQLITE_ROW) {
		REDEBUG("Failed retrieving entry for key \"%s\": %s", key, sqlite3_errmsg(*handle));
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);
		return CACHE_ERROR;
	}

	/*
	 *	cache_deserialize() writes to its input, and the statement owns
	 *	the column data, so work on a copy.
	 */
	expires = sqlite3_column_int64(stmt, 0);
	data = talloc_strndup(NULL, (char const *) sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));
	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);
	if (!data) return CACHE_ERROR;

	c = talloc_zero(NULL, rlm_cache_entry_t);
	if (!c) {
		talloc_free(data);
		return CACHE_ERROR;
	}

	if (cache_deserialize(c, data, -1) < 0) {
		REDEBUG("Failed parsing entry for key \"%s\": %s", key, fr_strerror());
		talloc_free(c);
		talloc_free(data);
		return CACHE_ERROR;
	}
	talloc_free(data);

	/*
	 *	The column is authoritative.
	 */
	c->expires = expires;
	c->key = talloc_strdup(c, key);
	*out = c;

	return CACHE_OK;
}

/** Add or replace an entry
 *
 * Rows which have expired are removed first, unless the driver already
 * removed them during the current second.
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Database handle.
 * @param c entry to insert.
 * @return CACHE_OK on success, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_insert(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_sqlite_t const *driver = inst->driver;
	sqlite3_stmt		*stmt;
	TALLOC_CTX		*pool;
	char			*to_store = NULL;
	cache_status_t		status;

	pool = talloc_pool(NULL, 1024);
	if (!pool) return CACHE_ERROR;

	if (cache_serialize(pool, &to_store, c) < 0) {
		REDEBUG("Failed serializing entry for key \"%s\"", c->key);
		talloc_free(pool);
		return CACHE_ERROR;
	}

	/*
	 *	The caller holds the mutex, so last_purge needs no other protection.
	 *	request->timestamp has a resolution of one second.  The test is
	 *	"!=" and not ">" so that a clock which moves backwards does not
	 *	stop the purge until the clock catches up.
	 */
	if (request->timestamp != driver->state->last_purge) {
		stmt = driver->state->purge;
		sqlite3_bind_int64(stmt, 1, (sqlite3_int64) request->timestamp);
		if (step_done(request, *handle, stmt) != CACHE_OK) {
			talloc_free(pool);
			return CACHE_ERROR;
		}

		driver->state->last_purge = request->timestamp;
	}

	stmt = driver->state->insert;
	sqlite3_bind_text(stmt, 1, c->key, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 2, (sqlite3_int64) c->expires);
	sqlite3_bind_text(stmt, 3, to_store, -1, SQLITE_STATIC);
	status = step_done(request, *handle, stmt);

	talloc_free(pool);

	return status;
}

/** Remove an entry
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Database handle.
 * @param c entry to expire.
 * @return CACHE_OK on success, CACHE_ERROR on error.
 */
static cache_status_t cache_entry_expire(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle,
					 rlm_cache_entry_t *c)
{
	rlm_cache_sqlite_t const *driver = inst->driver;
	sqlite3_stmt		*stmt = driver->state->expire;

	sqlite3_bind_text(stmt, 1, c->key, -1, SQLITE_STATIC);

	return step_done(request, *handle, stmt);
}

/** Return the number of entries which have not expired
 *
 * @param inst main rlm_cache instance.
 * @param request The current request.
 * @param handle Database handle.
 * @return the number of entries.
 */
static uint32_t cache_entry_count(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle)
{
	rlm_cache_sqlite_t const *driver = inst->driver;
	sqlite3_stmt		*stmt = driver->state->count;
	uint32_t		count = 0;

	sqlite3_bind_int64(stmt, 1, (sqlite3_int64) request->timestamp);
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		count = (uint32_t) sqlite3_column_int64(stmt, 0);
	} else {
		REDEBUG("Failed counting entries: %s", sqlite3_errmsg(*handle));
	}
	sqlite3_reset(stmt);
	sqlite3_clear_bindings(stmt);

	return count;
}

static void cache_entry_free(rlm_cache_entry_t *c)
{
	talloc_free(c);
}

extern cache_module_t rlm_cache_sqlite;
cache_module_t rlm_cache_sqlite = {
	.name		= "rlm_cache_sqlite",
	.instantiate	= mod_instantiate,
	.free		= cache_entry_free,

	.find		= cache_entry_find,
	.insert		= cache_entry_insert,
	.expire		= cache_entry_expire,
	.count		= cache_entry_count,

	.acquire	= cache_acquire,
	.release	= cache_release,
};
