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

/**
 * $Id$
 * @file serialize.c
 * @brief Serialize and deserialise cache entries.
 *
 * @author Arran Cudbard-Bell
 * @copyright 2014 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2014 The FreeRADIUS server project
 */
RCSID("$Id$")

#include "rlm_cache.h"
#include "serialize.h"

/** Serialize a cache entry as a humanly readable string
 *
 * @param ctx to alloc new string in. Should be a talloc pool a little bigger
 *	than the maximum serialized size of the entry.
 * @param out Where to write pointer to serialized cache entry.
 * @param c Cache entry to serialize.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cache_serialize(TALLOC_CTX *ctx, char **out, rlm_cache_entry_t const *c)
{
	TALLOC_CTX	*value_pool = NULL;
	char		attr[256];	/* Attr name buffer */
	vp_map_t	*map;

	char		*to_store = NULL;

	to_store = talloc_typed_asprintf(ctx, "&Cache-Expires = %" PRIu64 "\n&Cache-Created = %" PRIu64 "\n",
				   (uint64_t)c->expires, (uint64_t)c->created);
	if (!to_store) return -1;

	/*
	 *	It's valid to have an empty cache entry (save allocing the pairs pool)
	 */
	if (!c->maps) goto finish;

	value_pool = talloc_pool(ctx, 512);
	if (!value_pool) {
	error:
		talloc_free(to_store);
		talloc_free(value_pool);
		return -1;
	}

	for (map = c->maps; map; map = map->next) {
		char	*value;
		size_t	len;

		len = tmpl_snprint(attr, sizeof(attr), map->lhs);
		if (is_truncated(len, sizeof(attr))) {
			fr_strerror_printf("Serialized attribute too long.  Must be < " STRINGIFY(sizeof(attr)) " "
					   "bytes, got %zu bytes", len);
			goto error;
		}

		value = fr_value_box_asprint(value_pool, &map->rhs->tmpl_value, '\'');
		if (!value) goto error;

		to_store = talloc_asprintf_append_buffer(to_store, "%s %s %s\n", attr,
							 fr_table_str_by_value(fr_tokens_table, map->op, "<INVALID>"),
							 value);
		if (!to_store) goto error;
	}
finish:
	talloc_free(value_pool);
	*out = to_store;

	return 0;
}

/** Converts a serialized cache entry back into a structure
 *
 * @param[in] c		Cache entry to populate (should already be allocated)
 * @param[in] dict	to use for unqualified attributes.
 * @param[in] in	String representation of cache entry.
 * @param[in] inlen	Length of string. May be < 0 in which case strlen will be
 *			used to calculate the length of the string.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int cache_deserialize(rlm_cache_entry_t *c, fr_dict_t const *dict, char *in, ssize_t inlen)
{
	vp_map_t	**last = &c->maps;
	char		*p, *q;

	if (inlen < 0) inlen = strlen(in);

	p = in;

	while (((size_t)(p - in)) < (size_t)inlen) {
		vp_map_t	*map = NULL;
		vp_tmpl_rules_t parse_rules = {
					.dict_def = dict
				};

		q = strchr(p, '\n');
		if (!q) break;	/* List should also be terminated with a \n */
		*q = '\0';

		if (map_afrom_attr_str(c, &map, p, &parse_rules, &parse_rules) < 0) {
			fr_strerror_printf("Failed parsing pair: %s", p);
		error:
			talloc_free(map);
			return -1;
		}

		if (!tmpl_is_attr(map->lhs)) {
			fr_strerror_printf("Pair left hand side \"%s\" parsed as %s, needed attribute.  "
					   "Check local dictionaries", map->lhs->name,
					   fr_table_str_by_value(tmpl_type_table, map->lhs->type, "<INVALID>"));
			goto error;
		}

		if (!tmpl_is_unparsed(map->rhs)) {
			fr_strerror_printf("Pair right hand side \"%s\" parsed as %s, needed literal.  "
					   "Check serialized data quoting", map->rhs->name,
					   fr_table_str_by_value(tmpl_type_table, map->rhs->type, "<INVALID>"));
			goto error;
		}

		/*
		 *	Convert literal to a type appropriate for the VP.
		 */
		if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) goto error;

		/*
		 *	Pull out the special attributes, and set the
		 *	relevant cache entry fields.
		 */
		if (fr_dict_attr_is_top_level(map->lhs->tmpl_da)) switch (map->lhs->tmpl_da->attr) {
		case FR_CACHE_CREATED:
			c->created = map->rhs->tmpl_value.vb_date;
			talloc_free(map);
			goto next;

		case FR_CACHE_EXPIRES:
			c->expires = map->rhs->tmpl_value.vb_date;
			talloc_free(map);
			goto next;

		default:
			break;
		}

		/* It's not a special attribute, add it to the map list */
		*last = map;
		last = &(*last)->next;

	next:
		p = q + 1;
	}

	return 0;
}
