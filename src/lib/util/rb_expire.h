#pragma once
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

/** RB trees with expiry timers
 *
 * @file src/lib/util/rb_expire.h
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(fr_rb_expire_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/dlist.h>

typedef struct {
	fr_rb_tree_t	tree;
	fr_dlist_head_t	head;
	fr_time_delta_t	lifetime;
	fr_time_t	last_expiry;
} fr_rb_expire_t;

/** dlist for expiring old entries
 *
 *  This structure should be inside of the
 */
typedef struct {
	fr_rb_node_t	node;
	fr_dlist_t	entry;
	fr_time_t	when;
} fr_rb_expire_node_t;

#define fr_rb_expire_inline_talloc_init(_expire, _type, _field, _data_cmp, _data_free, _lifetime) \
	do { \
		fr_rb_inline_talloc_init(&(_expire)->tree, _type, _field.node, _data_cmp, _data_free); \
		fr_dlist_init(&(_expire)->head, _type, _field.entry); \
		(_expire)->lifetime = _lifetime; \
		(_expire)->last_expiry = fr_time(); \
 	} while (0)

bool		fr_rb_expire_insert(fr_rb_expire_t *expire, void *data, fr_time_t now) CC_HINT(nonnull);

void		fr_rb_expire_update(fr_rb_expire_t *expire, void *data, fr_time_t now) CC_HINT(nonnull);

#ifdef __cplusplus
}
#endif
