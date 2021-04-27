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

/** Structures and prototypes for hash / rbtree / patricia trie structures
 *
 * @file src/lib/util/htrie.h
 *
 * @copyright 2021 The FreeRADIUS server project
 */
RCSIDH(htrie_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/hash.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/trie.h>
#include <freeradius-devel/util/types.h>

typedef struct fr_htrie_s fr_htrie_t;

typedef void *(*fr_htrie_find_t)(fr_htrie_t *ht, void const *data);

typedef bool (*fr_htrie_insert_t)(fr_htrie_t *ht, void const *data);

typedef int (*fr_htrie_replace_t)(void **old, fr_htrie_t *ht, void const *data);

typedef void *(*fr_htrie_remove_t)(fr_htrie_t *ht, void const *data);

typedef bool (*fr_htrie_delete_t)(fr_htrie_t *ht, void const *data);

typedef uint32_t (*fr_htrie_num_elements_t)(fr_htrie_t *ht);

typedef enum {
	FR_HTRIE_INVALID = 0,
	FR_HTRIE_HASH,		//!< Data is stored in a hash.
	FR_HTRIE_RB,		//!< Data is stored in a rb tree.
	FR_HTRIE_TRIE,		//!< Data is stored in a prefix trie.
} fr_htrie_type_t;

/** Which functions are used for the different operations
 *
 */
typedef struct {
	fr_htrie_find_t		find;		//!< Absolute or prefix match.
	fr_htrie_find_t		match;		//!< exact prefix match
	fr_htrie_insert_t	insert;		//!< Insert a new item into the store.
	fr_htrie_replace_t	replace;	//!< Replace an existing item in store.
	fr_htrie_remove_t	remove;		//!< Remove an item from the store.
	fr_htrie_delete_t	delete;		//!< Remove (and possibly free) and item from the store.
	fr_htrie_num_elements_t	num_elements;	//!< Number of elements currently in the store.
} fr_htrie_funcs_t;

/** A hash/rb/prefix trie abstraction
 *
 */
struct fr_htrie_s {
	fr_htrie_type_t		type;		//!< type of the htrie
	void			*store;		//!< What we're using to store node data
	fr_htrie_funcs_t	funcs;		//!< Function pointers for the various operations.
};

fr_htrie_t *fr_htrie_alloc(TALLOC_CTX *ctx,
			   fr_htrie_type_t type,
			   fr_hash_t hash_data,
			   fr_cmp_t cmp_data,
			   fr_trie_key_t get_key,
			   fr_free_t free_data);

/** Match data in a htrie
 *
 */
static inline CC_HINT(nonnull) void *fr_htrie_match(fr_htrie_t *ht, void const *data)
{
	return ht->funcs.match(ht->store, data);
}

/** Find data in a htrie
 *
 */
static inline CC_HINT(nonnull) void *fr_htrie_find(fr_htrie_t *ht, void const *data)
{
	return ht->funcs.find(ht->store, data);
}

/** Insert data into a htrie
 *
 */
static inline CC_HINT(nonnull) bool fr_htrie_insert(fr_htrie_t *ht, void const *data)
{
	return ht->funcs.insert(ht->store, data);
}

/** Replace data in a htrie, freeing previous data if free_data cb was passed to fr_htrie_alloc
 *
 */
static inline CC_HINT(nonnull(2,3)) int fr_htrie_replace(void **old, fr_htrie_t *ht, void const *data)
{
	return ht->funcs.replace(old, ht->store, data);
}

/** Remove data from a htrie without freeing it
 *
 */
static inline CC_HINT(nonnull) void *fr_htrie_remove(fr_htrie_t *ht, void const *data)
{
	return ht->funcs.remove(ht->store, data);
}

/** Delete data from a htrie, freeing it if free_data cb was passed to fr_htrie_alloc
 *
 */
static inline CC_HINT(nonnull) bool fr_htrie_delete(fr_htrie_t *ht, void const *data)
{
	return ht->funcs.delete(ht->store, data);
}

/** Return the number of elements in the htrie
 *
 */
static inline CC_HINT(nonnull) int fr_htrie_num_elements(fr_htrie_t *ht)
{
	return ht->funcs.num_elements(ht->store);
}

static inline fr_htrie_type_t fr_htrie_hint(fr_type_t type)
{
	switch (type) {
	case FR_TYPE_INTEGER:
	case FR_TYPE_ETHERNET:
		return FR_HTRIE_HASH;

	case FR_TYPE_IP:
		return FR_HTRIE_TRIE;

	case FR_TYPE_STRING:
	case FR_TYPE_OCTETS:
		return FR_HTRIE_RB;

	default:
		return FR_HTRIE_INVALID;
	}
}

#ifdef __cplusplus
}
#endif
