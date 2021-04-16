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

typedef struct fr_htrie_s fr_htrie_t;

typedef void *(*fr_htrie_find_t)(fr_htrie_t *ht, void const *data);

typedef bool (*fr_htrie_insert_t)(fr_htrie_t *ht, void const *data);

typedef int (*fr_htrie_replace_t)(fr_htrie_t *ht, void const *data);

typedef void *(*fr_htrie_remove_t)(fr_htrie_t *ht, void const *data);

typedef bool (*fr_htrie_delete_t)(fr_htrie_t *ht, void const *data);

typedef uint32_t (*fr_htrie_num_elements_t)(fr_htrie_t *ht);


struct fr_htrie_s {
	void *ctx;

	fr_htrie_find_t		find;
	fr_htrie_insert_t	insert;
	fr_htrie_replace_t	replace;
	fr_htrie_remove_t	remove;
	fr_htrie_delete_t	delete;
	fr_htrie_num_elements_t	num_elements;

};

typedef enum {
	FR_HTRIE_HASH,
	FR_HTRIE_RB,
	FR_HTRIE_TRIE,
} fr_htrie_type_t;

fr_htrie_t *fr_htrie_alloc(TALLOC_CTX *ctx,
			    fr_htrie_type_t type,
			    fr_hash_t hash_node,
			    fr_cmp_t cmp_node,
			    fr_trie_key_t get_key,
			    fr_free_t free_node);

static void *fr_htrie_find(fr_htrie_t *ht, void const *data) CC_HINT(nonnull);

static inline void *fr_htrie_find(fr_htrie_t *ht, void const *data)
{
	return ht->find(ht->ctx, data);
}

static int fr_htrie_insert(fr_htrie_t *ht, void const *data) CC_HINT(nonnull);

static inline int fr_htrie_insert(fr_htrie_t *ht, void const *data)
{
	return ht->insert(ht->ctx, data);
}

static int fr_htrie_delete(fr_htrie_t *ht, void const *data) CC_HINT(nonnull);

static inline int fr_htrie_delete(fr_htrie_t *ht, void const *data)
{
	return ht->delete(ht->ctx, data);
}

static int fr_htrie_replace(fr_htrie_t *ht, void const *data) CC_HINT(nonnull);

static inline int fr_htrie_replace(fr_htrie_t *ht, void const *data)
{
	return ht->replace(ht->ctx, data);
}

static int fr_htrie_num_elements(fr_htrie_t *ht) CC_HINT(nonnull);

static inline int fr_htrie_num_elements(fr_htrie_t *ht)
{
	return ht->num_elements(ht->ctx);
}

#ifdef __cplusplus
}
#endif
