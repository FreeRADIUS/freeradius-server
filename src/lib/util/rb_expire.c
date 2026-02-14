/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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

/** Red/black expiry tree implementation
 *
 * @file src/lib/util/rb_expire.c
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/util/rb_expire.h>

/** Attempt to find current data in the tree, if it does not exist insert it
 *
 *  Any used node will be inserted into the tail of the expire list,
 *  and will expire at "now + expire->lifetime".
 *
 * @param[in] expire	to search/insert into.
 * @param[in] data	to find.
 * @param[in] now	the current time
 * @return
 *	- true if data was inserted.
 *	- false if we can't insert it.
 */
bool fr_rb_expire_insert(fr_rb_expire_t *expire, void *data, fr_time_t now)
{
	fr_dlist_t *entry = fr_dlist_item_to_entry(expire->head.offset, data);
	fr_rb_expire_node_t *re = (fr_rb_expire_node_t *) (((uintptr_t) entry) - offsetof(fr_rb_expire_node_t, entry));

	fr_assert(!fr_rb_node_inline_in_tree(&re->node));

	if (!fr_rb_insert(&expire->tree, data)) {
		return false;
	}

	fr_dlist_insert_tail(&expire->head, data);

	re->when = fr_time_add_time_delta(now, expire->lifetime);

	return true;
}

void fr_rb_expire_update(fr_rb_expire_t *expire, void *data, fr_time_t now)
{
	fr_dlist_t *entry = fr_dlist_item_to_entry(expire->head.offset, data);
	fr_rb_expire_node_t *re = (fr_rb_expire_node_t *) (((uintptr_t) entry) - offsetof(fr_rb_expire_node_t, entry));

	fr_assert(fr_rb_node_inline_in_tree(&re->node));

	fr_dlist_remove(&expire->head, data);

	fr_dlist_insert_tail(&expire->head, data);
	re->when = fr_time_add_time_delta(now, expire->lifetime);

#if 0
	/*
	 *	Expire old entries.
	 */
	fr_dlist_foreach(&expire->head, fr_rb_expire_node_t, old) {{
		re = (fr_rb_expire_node_t *) (((uintptr_t) old) - offsetof(fr_rb_expire_node_t, entry));

		if (old->when > now) break;

		fr_dlist_remove(&expire->head, &old->entry);

		fr_rb_delete(&expire->tree, re);
	}
#endif
}
