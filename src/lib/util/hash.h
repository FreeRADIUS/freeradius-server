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

/** Structures and prototypes for resizable hash tables
 *
 * @file src/lib/util/hash.h
 *
 * @copyright 2005,2006 The FreeRADIUS server project
 */
RCSIDH(hash_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/misc.h>

#include <stddef.h>
#include <stdint.h>

typedef struct fr_hash_entry_s fr_hash_entry_t;
typedef	uint32_t (*fr_hash_t)(void const *);

/** Stores the state of the current iteration operation
 *
 */
typedef struct {
	uint32_t		bucket;
	fr_hash_entry_t		*node;
} fr_hash_iter_t;

/*
 *	Fast hash, which isn't too bad.  Don't use for cryptography,
 *	just for hashing internal data.
 */
uint32_t fr_hash(void const *, size_t);
uint32_t fr_hash_update(void const *data, size_t size, uint32_t hash);
uint32_t fr_hash_string(char const *p);
uint32_t fr_hash_case_string(char const *p);

typedef struct fr_hash_table_s fr_hash_table_t;
typedef int (*fr_hash_table_walk_t)(void *data, void *uctx);

fr_hash_table_t *fr_hash_table_alloc(TALLOC_CTX *ctx,
				     fr_hash_t hash_node,
				     fr_cmp_t cmp_node,
				     fr_free_t free_node) CC_HINT(nonnull(2,3));

void		*fr_hash_table_find(fr_hash_table_t *ht, void const *data) CC_HINT(nonnull);

void		*fr_hash_table_find_by_key(fr_hash_table_t *ht, uint32_t key, void const *data) CC_HINT(nonnull);

bool		fr_hash_table_insert(fr_hash_table_t *ht, void const *data) CC_HINT(nonnull);

int		fr_hash_table_replace(void **old, fr_hash_table_t *ht, void const *data) CC_HINT(nonnull(2,3));

void		*fr_hash_table_remove(fr_hash_table_t *ht, void const *data) CC_HINT(nonnull);

bool		fr_hash_table_delete(fr_hash_table_t *ht, void const *data) CC_HINT(nonnull);

uint32_t	fr_hash_table_num_elements(fr_hash_table_t *ht) CC_HINT(nonnull);

void		*fr_hash_table_iter_next(fr_hash_table_t *ht, fr_hash_iter_t *iter) CC_HINT(nonnull);

void		*fr_hash_table_iter_init(fr_hash_table_t *ht, fr_hash_iter_t *iter) CC_HINT(nonnull);

int		fr_hash_table_flatten(TALLOC_CTX *ctx, void **out[], fr_hash_table_t *ht) CC_HINT(nonnull(2,3));

void		fr_hash_table_fill(fr_hash_table_t *ht) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
