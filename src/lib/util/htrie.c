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

fr_htrie_t *fr_htrie_alloc(TALLOC_CTX *ctx,
			   fr_htrie_type_t type,
			   fr_hash_t hash_node,
			   fr_cmp_t cmp_node,
			   fr_trie_key_t get_key,
			   fr_free_t free_node)
{
	fr_htrie_t *trie;

	trie = talloc_zero(ctx, fr_htrie_t);
	if (!trie) return NULL;

	switch (type) {
	case FR_HTRIE_HASH:
		if (!hash_node || !cmp_node) return NULL;

		trie->ctx = fr_hash_table_alloc(trie, hash_node, cmp_node, free_node);
		if (!trie->ctx) {
			talloc_free(trie);
			return NULL;
		}

#undef DEF
#define DEF(_x) trie->_x = (fr_htrie_ ##_x ## _t) fr_hash_table_ ## _x
		DEF(find);
		DEF(insert);
		DEF(replace);
		DEF(remove);
		DEF(delete);
		DEF(num_elements);
		break;

	case FR_HTRIE_RB:
		if (!cmp_node) return NULL;

		trie->ctx = fr_rb_alloc(trie, cmp_node, free_node, 0);
		if (!trie->ctx) {
			talloc_free(trie);
			return NULL;
		}

#undef DEF
#define DEF(_x) trie->_x = (fr_htrie_ ##_x ## _t) fr_rb_ ## _x
		DEF(find);
		DEF(insert);
		DEF(replace);
		DEF(remove);
		DEF(delete);
		DEF(num_elements);
		break;

	case FR_HTRIE_TRIE:
		if (!get_key) return NULL;

		trie->ctx = fr_trie_alloc(trie, get_key, free_node);
		if (!trie->ctx) {
			talloc_free(trie);
			return NULL;
		}

#undef DEF
#define DEF(_x) trie->_x = (fr_htrie_ ##_x ## _t) fr_trie_ ## _x
		DEF(find);
		DEF(insert);
		DEF(replace);
		DEF(remove);
		DEF(delete);
		DEF(num_elements);
		break;

	default:
		return NULL;
	}

	return trie;
}
