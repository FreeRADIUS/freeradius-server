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
 * @copyright 2005,2006  The FreeRADIUS server project
 */
RCSIDH(hash_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>

#include <stddef.h>
#include <stdint.h>
#include <talloc.h>

/*
 *	Fast hash, which isn't too bad.  Don't use for cryptography,
 *	just for hashing internal data.
 */
uint32_t fr_hash(void const *, size_t);
uint32_t fr_hash_update(void const *data, size_t size, uint32_t hash);
uint32_t fr_hash_string(char const *p);

typedef struct fr_hash_table_t fr_hash_table_t;
typedef void (*fr_hash_table_free_t)(void *);
typedef uint32_t (*fr_hash_table_hash_t)(void const *);
typedef int (*fr_hash_table_cmp_t)(void const *, void const *);
typedef int (*fr_hash_table_walk_t)(void * /* ctx */, void * /* data */);

fr_hash_table_t *fr_hash_table_create(TALLOC_CTX *ctx,
				      fr_hash_table_hash_t hashNode,
				      fr_hash_table_cmp_t cmpNode,
				      fr_hash_table_free_t freeNode);
void		fr_hash_table_free(fr_hash_table_t *ht);
int		fr_hash_table_insert(fr_hash_table_t *ht, void const *data);
int		fr_hash_table_delete(fr_hash_table_t *ht, void const *data);
void		*fr_hash_table_yank(fr_hash_table_t *ht, void const *data);
int		fr_hash_table_replace(fr_hash_table_t *ht, void const *data);
void		*fr_hash_table_finddata(fr_hash_table_t *ht, void const *data);
int		fr_hash_table_num_elements(fr_hash_table_t *ht);
int		fr_hash_table_walk(fr_hash_table_t *ht,
				     fr_hash_table_walk_t callback,
				     void *ctx);

#ifdef __cplusplus
}
#endif
