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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <talloc.h>

typedef struct fr_trie_s fr_trie_t;
typedef int (*fr_trie_walk_t)(void *ctx, uint8_t const *key, size_t keylen, void *data);

fr_trie_t	*fr_trie_alloc(TALLOC_CTX *ctx);
int		fr_trie_insert(fr_trie_t *ft, void const *key, size_t keylen, void const *data) CC_HINT(nonnull);
void		*fr_trie_lookup(fr_trie_t const *ft, void const *key, size_t keylen) CC_HINT(nonnull);
void		*fr_trie_match(fr_trie_t const *ft, void const *key, size_t keylen) CC_HINT(nonnull);
void		*fr_trie_remove(fr_trie_t *ft, void const *key, size_t keylen) CC_HINT(nonnull);
int		fr_trie_walk(fr_trie_t *ft, void *ctx, fr_trie_walk_t callback) CC_HINT(nonnull(1,3));

#ifdef __cplusplus
}
#endif
