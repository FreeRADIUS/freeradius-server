/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** hash / rb / patricia trees
 *
 * @file src/lib/util/htrie.c
 *
 * @copyright 2021 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/htrie.h>

#define FUNC(_prefix, _op) ._op = (fr_htrie_ ##_op ## _t) fr_##_prefix##_## _op

static fr_htrie_funcs_t const default_funcs[] = {
	[FR_HTRIE_HASH] = {
		FUNC(hash_table, find),
		FUNC(hash_table, insert),
		FUNC(hash_table, replace),
		FUNC(hash_table, remove),
		FUNC(hash_table, delete),
		FUNC(hash_table, num_elements)
	},
	[FR_HTRIE_RB] = {
		FUNC(rb, find),
		FUNC(rb, insert),
		FUNC(rb, replace),
		FUNC(rb, remove),
		FUNC(rb, delete),
		FUNC(rb, num_elements)
	},
	[FR_HTRIE_TRIE] = {
		FUNC(trie, find),
		FUNC(trie, insert),
		FUNC(trie, replace),
		FUNC(trie, remove),
		FUNC(trie, delete),
		FUNC(trie, num_elements)
	}
};

/** An abstraction over our internal hashes, rb trees, and prefix tries
 *
 * This is useful where the data type being inserted into the tree
 * is used controlled, and so we need to pick the most efficient structure
 * for a given data type dynamically at runtime.
 *
 * @param[in] ctx		to bind the htrie's lifetime to.
 * @param[in] type		One of:
 *				- FR_HTRIE_HASH
 *				- FR_HTRIE_RB
 *				- FR_HTRIE_TRIE
 * @param[in] hash_data		Used by FR_HTRIE_HASH to convert the
 *				data into a 32bit integer used for binning.
 * @param[in] cmp_data		Used to determine exact matched.
 * @param[in] get_key		Used by the prefix trie to extract a key
 *				from the data.
 * @param[in] free_data		The callback used to free the data if it is
 *				deleted or replaced. May be NULL in which
 *				case data will not be freed for these operations.
 * @return
 *	- A new htrie on success.
 *	- NULL on failure, either missing functions or a memory allocation error.
 */
fr_htrie_t *fr_htrie_alloc(TALLOC_CTX *ctx,
			   fr_htrie_type_t type,
			   fr_hash_t hash_data,
			   fr_cmp_t cmp_data,
			   fr_trie_key_t get_key,
			   fr_free_t free_data)
{
	fr_htrie_t *ht;

	ht = talloc_zero(ctx, fr_htrie_t);
	if (unlikely(!ht)) {
		fr_strerror_const("Failed allocating fr_htrie_t");
		return NULL;
	}

	switch (type) {
	case FR_HTRIE_HASH:
		if (!hash_data || !cmp_data) {
			fr_strerror_const("hash_data and cmp_data must not be NULL for FR_HTRIE_HASH");
			return NULL;
		}

		ht->store = fr_hash_table_alloc(ht, hash_data, cmp_data, free_data);
		if (unlikely(!ht->store)) {
		error:
			talloc_free(ht);
			return NULL;
		}
		ht->funcs = default_funcs[type];
		return ht;

	case FR_HTRIE_RB:
		if (!cmp_data) {
			fr_strerror_const("cmp_data must not be NULL for FR_HTRIE_RB");
			return NULL;
		}

		ht->store = fr_rb_alloc(ht, cmp_data, free_data);
		if (unlikely(!ht->store)) goto error;
		ht->funcs = default_funcs[type];
		return ht;

	case FR_HTRIE_TRIE:
		if (!get_key) {
			fr_strerror_const("get_key must not be NULL for FR_HTRIE_TRIE");
			return NULL;
		}

		ht->store = fr_trie_alloc(ht, get_key, free_data);
		if (unlikely(!ht->store)) goto error;
		ht->funcs = default_funcs[type];
		return ht;

	default:
		return NULL;
	}
}
