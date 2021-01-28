#pragma once
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

/*
 * $Id$
 * @file rlm_cache.h
 * @brief Cache values and merge them back into future requests.
 *
 * @copyright 2014 The FreeRADIUS server project
 * @copyright 2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(cache_h, "$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/map.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

typedef struct rlm_cache_driver_s rlm_cache_driver_t;

typedef void rlm_cache_handle_t;

#define MAX_ATTRMAP	128

typedef enum {
	CACHE_RECONNECT	= -2,				//!< Handle needs to be reconnected
	CACHE_ERROR	= -1,				//!< Fatal error
	CACHE_OK	= 0,				//!< Cache entry found/updated
	CACHE_MISS	= 1				//!< Cache entry notfound
} cache_status_t;

/** Configuration for the rlm_cache module
 *
 * This is separate from the #rlm_cache_t struct, to limit driver's visibility of
 * rlm_cache instance data.
 */
typedef struct {
	char const		*name;			//!< Name of xlat function to register.
	char const		*driver_name;		//!< Driver name.
	tmpl_t		*key;			//!< What to expand to get the value of the key.
	uint32_t		ttl;			//!< How long an entry is valid for.
	uint32_t		max_entries;		//!< Maximum entries allowed.
	int32_t			epoch;			//!< Time after which entries are considered valid.
	bool			stats;			//!< Generate statistics.
} rlm_cache_config_t;

/*
 *	Define a structure for our module configuration.
 *
 *	These variables do not need to be in a structure, but it's
 *	a lot cleaner to do so, and a pointer to the structure can
 *	be used as the instance handle.
 */
typedef struct {
	rlm_cache_config_t	config;			//!< Must come first because of icky hacks.

	module_instance_t	*driver_inst;		//!< Driver's instance data.
	rlm_cache_driver_t const	*driver;		//!< Driver's exported interface.

	map_t		*maps;			//!< Attribute map applied to users.
							//!< and profiles.
	CONF_SECTION		*cs;
} rlm_cache_t;

typedef struct {
	uint8_t const		*key;			//!< Key used to identify entry.
	size_t			key_len;		//!< Length of key data.
	long long int		hits;			//!< How many times the entry has been retrieved.
	fr_unix_time_t		created;		//!< When the entry was created.
	fr_unix_time_t		expires;		//!< When the entry expires.

	map_t		*maps;			//!< Head of the maps list.
} rlm_cache_entry_t;

/** Allocate a new cache entry
 *
 */
typedef rlm_cache_entry_t *(*cache_entry_alloc_t)(rlm_cache_config_t const *config, void *instance, request_t *request);

/** Free a cache entry
 *
 * @note This callback is optional, but the driver assume responsibility for freeing the
 *	cache_entry_t on #cache_entry_expire_t.
 *
 * If the driver does not need to keep a local copy of the cache entry, it should provide
 * a callback to free the memory previously allocated for the cache entry by
 * #cache_entry_find_t or by rlm_cache.
 *
 * @param c entry to free.
 */
typedef void		(*cache_entry_free_t)(rlm_cache_entry_t *c);

/** Retrieve an entry from the cache
 *
 * If a cache entry is found, but the cache entry needs to be deserialized, the driver
 * is expected to allocate an appropriately sized #rlm_cache_entry_t, perform the deserialisation,
 * and write a pointer to the new entry to out, returning #CACHE_OK.
 *
 * If the #rlm_cache_handle_t is inviable, the driver should return #CACHE_RECONNECT, to have
 * it reinitialised/reconnected.
 *
 * @param[out] out Where to write a pointer to the retrieved entry (if there was one).
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @param[in] handle the driver gave us when we called #cache_acquire_t, or NULL if no
 *	#cache_acquire_t callback was provided.
 * @param[in] key to use to lookup cache entry
 * @param[in] key_len the length of the key string.
 * @return
 *	- #CACHE_RECONNECT - If handle needs to be reinitialised/reconnected.
 *	- #CACHE_ERROR - If the lookup couldn't be completed.
 *	- #CACHE_OK - Lookup was successful.
 *	- #CACHE_MISS - No cached entry was found.
 */
typedef cache_status_t	(*cache_entry_find_t)(rlm_cache_entry_t **out, rlm_cache_config_t const *config,
					      void *instance, request_t *request, void *handle,
					      uint8_t const *key, size_t key_len);

/** Insert an entry into the cache
 *
 * Serialize (if necessary) the entry passed to us, and write it to the cache with
 * the key c->key.
 *
 * The cache entry should not be freed by the driver, irrespective of success or failure.
 * If the entry needs to be freed after insertion because a local copy should not be kept,
 * the driver should provide a #cache_entry_free_t callback.
 *
 * If the #rlm_cache_handle_t is inviable, the driver should return #CACHE_RECONNECT, to have
 * it reinitialised/reconnected.
 *
 * @note This callback is not optional.
 *
 * @note This callback *must* overwrite existing cache entries on insert.
 *
 * @param config for this instance of the rlm_cache module.
 * @param instance Driver specific instance data.
 * @param request The current request.
 * @param handle the driver gave us when we called #cache_acquire_t, or NULL if no
 *	#cache_acquire_t callback was provided.
 * @param c to insert.
 * @return
 *	- #CACHE_RECONNECT - If handle needs to be reinitialised/reconnected.
 *	- #CACHE_ERROR - If the insert couldn't be completed.
 *	- #CACHE_OK - If the insert was successful.
 */
typedef cache_status_t	(*cache_entry_insert_t)(rlm_cache_config_t const *config, void *instance,
						request_t *request, void *handle,
						rlm_cache_entry_t const *c);

/** Remove an entry from the cache
 *
 * @note This callback is not optional.
 *
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @param[in] handle the driver gave us when we called #cache_acquire_t, or NULL if no
 *	#cache_acquire_t callback was provided.
 * @param[in] key of entry to expire.
 * @param[in] key_len the length of the key string.
 * @return
 *	- #CACHE_RECONNECT - If handle needs to be reinitialised/reconnected.
 *	- #CACHE_ERROR - If the entry couldn't be expired.
 *	- #CACHE_OK - If the entry was expired.
 *	- #CACHE_MISS - If the entry didn't exist, so couldn't be expired.
 */
typedef cache_status_t	(*cache_entry_expire_t)(rlm_cache_config_t const *config, void *instance,
						request_t *request, void *handle,
						uint8_t const *key, size_t key_len);

/** Update the ttl of an entry in the cace
 *
 * @note This callback optional. If it's not specified the cache code will expire and
 *	 recreate the entry with a new TTL.
 *
 * If the #rlm_cache_handle_t is inviable, the driver should return #CACHE_RECONNECT, to have
 * it reinitialised/reconnected.
 *
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @param[in] handle the driver gave us when we called #cache_acquire_t, or NULL if no
 *	#cache_acquire_t callback was provided.
 * @param[in] c to update the TTL of. c->ttl will have been set to the new value.
 * @return
 *	- #CACHE_RECONNECT - If handle needs to be reinitialised/reconnected.
 *	- #CACHE_ERROR - If the entry TTL couldn't be updated.
 *	- #CACHE_OK - If the entry's TTL was updated.
 */
typedef cache_status_t	(*cache_entry_set_ttl_t)(rlm_cache_config_t const *config, void *instance,
						 request_t *request, void *handle,
						 rlm_cache_entry_t *c);

/** Get the number of entries in the cache
 *
 * @note This callback is optional. Though max_entries will not be enforced if it is not provided.
 *
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @param handle the driver gave us when we called #cache_acquire_t, or NULL if no
 *	#cache_acquire_t callback was provided.
 * @return number of entries in the cache.
 */
typedef uint32_t	(*cache_entry_count_t)(rlm_cache_config_t const *config, void *instance,
					       request_t *request, void *handle);

/** Acquire a handle to access the cache
 *
 * @note This callback is optional. If it's not provided the handle argument to other callbacks
 *	will be NULL.
 *
 * @param[out] handle Where to write pointer to handle to access the cache with.
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int		(*cache_acquire_t)(void **handle, rlm_cache_config_t const *config, void *instance,
					   request_t *request);

/** Release a previously acquired handle
 *
 * @note This callback is optional.
 *
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.
 * @param[in] handle to release.
 */
typedef void		(*cache_release_t)(rlm_cache_config_t const *config, void *instance, request_t *request,
					   rlm_cache_handle_t *handle);

/** Reconnect a previously acquired handle
 *
 * @note This callback is optional.
 *
 * @param[in,out] handle to reinitialise/reconnect.
 * @param[in] config for this instance of the rlm_cache module.
 * @param[in] instance Driver specific instance data.
 * @param[in] request The current request.

 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
typedef int		(*cache_reconnect_t)(rlm_cache_handle_t **handle, rlm_cache_config_t const *config,
					     void *instance, request_t *request);

struct rlm_cache_driver_s {
	DL_MODULE_COMMON;					//!< Common fields for all loadable modules.
	FR_MODULE_COMMON;					//!< Common fields for all instantiated modules.
	FR_MODULE_THREADED_COMMON;				//!< Common fields for threaded modules.

	cache_entry_alloc_t		alloc;			//!< (optional) Allocate a new entry.
	cache_entry_free_t		free;			//!< (optional) Free memory used by an entry.

	cache_entry_find_t		find;			//!< Retrieve an existing cache entry.
	cache_entry_insert_t		insert;			//!< Add a new entry.
	cache_entry_expire_t		expire;			//!< Remove an old entry.
	cache_entry_set_ttl_t		set_ttl;		//!< (Optional) Update the TTL of an entry.
	cache_entry_count_t		count;			//!< (Optional) Number of entries currently in
								//!< the cache.

	cache_acquire_t			acquire;		//!< (optional) Acquire exclusive access to a resource
								//!< used to retrieve the cache entry.
	cache_release_t			release;		//!< (optional) Release access to resource acquired
								//!< with acquire callback.
	cache_reconnect_t		reconnect;		//!< (optional) Re-initialise resource.
};
