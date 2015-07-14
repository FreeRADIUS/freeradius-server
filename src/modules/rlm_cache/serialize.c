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
 * @copyright 2014 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
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
 * @return 0 on success else -1.
 */
int cache_serialize(TALLOC_CTX *ctx, char **out, rlm_cache_entry_t *c)
{
	TALLOC_CTX *pairs = NULL;

	vp_cursor_t cursor;
	VALUE_PAIR *vp;

	char *to_store = NULL, *pair;

	to_store = talloc_asprintf(ctx, "&Cache-Expires = %" PRIu64 "\n&Cache-Created = %" PRIu64 "\n",
				   (uint64_t)c->expires, (uint64_t)c->created);
	if (!to_store) goto error;

	/*
	 *	It's valid to have an empty cache entry (save allocing the
	 *	pairs pool)
	 */
	if (!c->control && !c->packet && !c->reply) goto finish;

	/*
	 *  In the majority of cases using these pools reduces the number of mallocs
	 *  to two, except in the case where the total serialized pairs length is
	 *  greater than the pairs pool, or the total serialized string is greater
	 *  than the store pool.
	 */
	pairs = talloc_pool(ctx, 512);
	if (!pairs) {
	error:
		talloc_free(pairs);
		return -1;
	}

	if (c->control) {
		for (vp = fr_cursor_init(&cursor, &c->control);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&control:%s\n", pair);
			if (!to_store) goto error;
		}
	}

	if (c->packet) {
		for (vp = fr_cursor_init(&cursor, &c->packet);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&%s\n", pair);
			if (!to_store) goto error;
		}
	}

	if (c->reply) {
		for (vp = fr_cursor_init(&cursor, &c->reply);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&reply:%s\n", pair);
			if (!to_store) goto error;
		}
	}

	if (c->state) {
		for (vp = fr_cursor_init(&cursor, &c->state);
		     vp;
		     vp = fr_cursor_next(&cursor)) {
			pair = vp_aprints(pairs, vp, '\'');
			if (!pair) goto error;

			to_store = talloc_asprintf_append_buffer(to_store, "&session-state:%s\n", pair);
			if (!to_store) goto error;
		}
	}

finish:
	talloc_free(pairs);
	*out = to_store;

	return 0;
}

/** Converts a serialized cache entry back into a structure
 *
 * @param c Cache entry to populate (should already be allocated)
 * @param in String representation of cache entry.
 * @param inlen Length of string. May be < 0 in which case strlen will be
 *	used to calculate the length of the string.
 * @return 0 on success, -1 on error.
 */
int cache_deserialize(rlm_cache_entry_t *c, char *in, ssize_t inlen)
{
	vp_cursor_t packet, control, reply, state;

	TALLOC_CTX *store = NULL;
	char *p, *q;

	store = talloc_pool(c, 1024);
	if (!store) return -1;

	if (inlen < 0) inlen = strlen(in);

	fr_cursor_init(&packet, &c->packet);
	fr_cursor_init(&control, &c->control);
	fr_cursor_init(&reply, &c->reply);
	fr_cursor_init(&state, &c->state);

	p = in;

	while (((size_t)(p - in)) < (size_t)inlen) {
		vp_map_t *map = NULL;
		VALUE_PAIR *vp = NULL;
		ssize_t len;

		q = strchr(p, '\n');
		if (!q) break;	/* List should also be terminated with a \n */
		*q = '\0';

		if (map_afrom_attr_str(store, &map, p,
				       REQUEST_CURRENT, PAIR_LIST_REQUEST,
				       REQUEST_CURRENT, PAIR_LIST_REQUEST) < 0) {
			fr_strerror_printf("Failed parsing pair: %s", p);
			goto error;
		}

		if (map->lhs->type != TMPL_TYPE_ATTR) {
			fr_strerror_printf("Pair left hand side \"%s\" parsed as %s, needed attribute.  "
					   "Check local dictionaries", map->lhs->name,
					   fr_int2str(tmpl_names, map->lhs->type, "<INVALID>"));
			goto error;
		}

		if (map->rhs->type != TMPL_TYPE_LITERAL) {
			fr_strerror_printf("Pair right hand side \"%s\" parsed as %s, needed literal.  "
					   "Check serialized data quoting", map->rhs->name,
					   fr_int2str(tmpl_names, map->rhs->type, "<INVALID>"));
			goto error;
		}

		/*
		 *	Convert literal to a type appropriate for the VP.
		 */
		if (tmpl_cast_in_place(map->rhs, map->lhs->tmpl_da->type, map->lhs->tmpl_da) < 0) goto error;

		vp = fr_pair_afrom_da(c, map->lhs->tmpl_da);
		len = value_data_copy(vp, &vp->data, map->rhs->tmpl_data_type,
				      &map->rhs->tmpl_data_value, map->rhs->tmpl_data_length);
		if (len < 0) goto error;
		vp->vp_length = len;

		/*
		 *	Pull out the special attributes, and set the
		 *	relevant cache entry fields.
		 */
		if (vp->da->vendor == 0) switch (vp->da->attr) {
		case PW_CACHE_CREATED:
			c->created = vp->vp_date;
			talloc_free(vp);
			goto next;

		case PW_CACHE_EXPIRES:
			c->expires = vp->vp_date;
			talloc_free(vp);
			goto next;

		default:
			break;
		}

		switch (map->lhs->tmpl_list) {
		case PAIR_LIST_REQUEST:
			fr_cursor_insert(&packet, vp);
			break;

		case PAIR_LIST_CONTROL:
			fr_cursor_insert(&control, vp);
			break;

		case PAIR_LIST_REPLY:
			fr_cursor_insert(&reply, vp);
			break;

		case PAIR_LIST_STATE:
			fr_cursor_insert(&state, vp);
			break;

		default:
			fr_strerror_printf("Invalid cache list for pair: %s", p);
		error:
			talloc_free(vp);
			talloc_free(map);
			return -1;
		}
	next:
		p = q + 1;
		talloc_free(map);
	}

	return 0;
}
