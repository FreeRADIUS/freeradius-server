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

/*
 * $Id$
 * @file rlm_cache.h
 * @brief Cache values and merge them back into future requests.
 *
 * @copyright 2014  The FreeRADIUS server project
 * @copyright 2014  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(cache_h, "$Id$")

#include <freeradius-devel/radiusd.h>

typedef struct cache_module cache_module_t;

typedef void rlm_cache_handle_t;

#define MAX_ATTRMAP	128

typedef enum {
	CACHE_RECONNECT	= -2,				//!< Handle needs to be reconnected
	CACHE_ERROR	= -1,				//!< Fatal error
	CACHE_OK	= 0,				//!< Cache entry found/updated
	CACHE_MISS	= 1				//!< Cache entry notfound
} cache_status_t;

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct rlm_cache_t {
	char const		*name;		//!< Name of xlat function to register.

	char const		*driver_name;		//!< Datastore name
	void			*handle;		//!< Datastore handle.
	cache_module_t		*module;		//!< Datastore
	void			*driver;		//!< Driver module instance data.

	char const		*key;
	uint32_t		ttl;			//!< How long an entry is valid for.
	uint32_t		max_entries;		//!< Maximum entries allowed.
	int32_t			epoch;			//!< Time after which entries are considered valid.
	bool			stats;			//!< Generate statistics.

	vp_map_t	*maps;			//!< Attribute map applied to users.
							//!< and profiles.
	CONF_SECTION		*cs;
} rlm_cache_t;

typedef struct rlm_cache_entry_t {
	char const		*key;			//!< Key used to identify entry.
	long long int		hits;			//!< How many times the entry has been retrieved.
	time_t			created;		//!< When the entry was created.
	time_t			expires;		//!< When the entry expires.

	VALUE_PAIR		*control;		//!< Cached control list.
	VALUE_PAIR		*packet;		//!< Cached request list.
	VALUE_PAIR		*reply;			//!< Cached reply list.
	VALUE_PAIR		*state;			//!< Cached session-state list.
} rlm_cache_entry_t;

typedef int			(*cache_instantiate_t)(CONF_SECTION *conf, rlm_cache_t *inst);
typedef rlm_cache_entry_t	*(*cache_entry_alloc_t)(rlm_cache_t *inst, REQUEST *request);
typedef void			(*cache_entry_free_t)(rlm_cache_entry_t *c);

typedef cache_status_t		(*cache_entry_find_t)(rlm_cache_entry_t **out, rlm_cache_t *inst, REQUEST *request,
						      rlm_cache_handle_t **handle, char const *key);
typedef cache_status_t		(*cache_entry_insert_t)(rlm_cache_t *inst, REQUEST *request,
							rlm_cache_handle_t **handle, rlm_cache_entry_t *c);
typedef cache_status_t		(*cache_entry_expire_t)(rlm_cache_t *inst, REQUEST *request,
							rlm_cache_handle_t **handle, rlm_cache_entry_t *entry);
typedef uint32_t		(*cache_entry_count_t)(rlm_cache_t *inst, REQUEST *request,
						       rlm_cache_handle_t **handle);

typedef int			(*cache_acquire_t)(rlm_cache_handle_t **out, rlm_cache_t *inst, REQUEST *request);
typedef void			(*cache_release_t)(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle);
typedef int			(*cache_reconnect_t)(rlm_cache_t *inst, REQUEST *request, rlm_cache_handle_t **handle);

struct cache_module {
	char const		*name;			//!< Driver name.

	cache_instantiate_t	instantiate;		//!< (optional) Instantiate a driver.
	cache_entry_alloc_t	alloc;			//!< (optional) Allocate a new entry.
	cache_entry_free_t	free;			//!< (optional) Free memory used by an entry.

	cache_entry_find_t	find;			//!< Retrieve an existing cache entry.
	cache_entry_insert_t	insert;			//!< Add a new entry.
	cache_entry_expire_t	expire;			//!< Remove an old entry.
	cache_entry_count_t	count;			//!< Number of entries.

	cache_acquire_t		acquire;		//!< (optional) Get a lock or connection handle.
	cache_release_t		release;		//!< (optional) Release the lock or connection handle.
	cache_reconnect_t	reconnect;		//!< (optional) Reconnect a handle.
};
