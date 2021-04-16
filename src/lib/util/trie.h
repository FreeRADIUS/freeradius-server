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

/** Path-compressed prefix tries
 *
 * @file src/lib/util/trie.h
 *
 * @copyright 2017 Alan DeKok (aland@freeradius.org)
 */
RCSIDH(trie_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/build.h>
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/talloc.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct fr_trie_s fr_trie_t;

/** Walk over a trie
 *
 */
typedef int (*fr_trie_walk_t)(uint8_t const *key, size_t keylen, void *data, void *uctx);

/* Get a key from data.
 *
 * @param[in,out] out - set to a small buffer on input.  If the callback has more data
 *		  than is available here, the callback can update "out" to point elsewhere
 * @param[in,out] outlen The number of bits available in the initial buffer.  On output,
 *		  the number of bits available in the key
 * @param[in] data the data which contains the key
 * @return
 *	- <0 on error
 *	- 0 on success
 */
typedef int (*fr_trie_key_t)(uint8_t **out, size_t *outlen, void const *data);

#define fr_trie_alloc(_ctx) _fr_trie_alloc(_ctx, NULL, NULL)

#define fr_trie_generic_alloc(_ctx, _get_key, _free_data) _fr_trie_alloc(_ctx, _get_key, _free_data)

fr_trie_t	*_fr_trie_alloc(TALLOC_CTX *ctx, fr_trie_key_t get_key, fr_free_t free_node);
int		fr_trie_insert_by_key(fr_trie_t *ft, void const *key, size_t keylen, void const *data) CC_HINT(nonnull);

void		*fr_trie_lookup_by_key(fr_trie_t const *ft, void const *key, size_t keylen) CC_HINT(nonnull);
void		*fr_trie_match_by_key(fr_trie_t const *ft, void const *key, size_t keylen) CC_HINT(nonnull);
void		*fr_trie_remove_by_key(fr_trie_t *ft, void const *key, size_t keylen) CC_HINT(nonnull);

int		fr_trie_walk(fr_trie_t *ft, void *ctx, fr_trie_walk_t callback) CC_HINT(nonnull(1,3));

/*
 *	Data oriented API.
 */
void		*fr_trie_find(fr_trie_t *ft, void const *data) CC_HINT(nonnull);

bool		fr_trie_insert(fr_trie_t *ft, void const *data) CC_HINT(nonnull);

int		fr_trie_replace(fr_trie_t *ft, void const *data) CC_HINT(nonnull);

void		*fr_trie_remove(fr_trie_t *ft, void const *data) CC_HINT(nonnull);

bool		fr_trie_delete(fr_trie_t *ft, void const *data) CC_HINT(nonnull);

uint64_t	fr_trie_num_elements(fr_trie_t *ft) CC_HINT(nonnull); /* always returns 0 */

#ifdef __cplusplus
}
#endif
