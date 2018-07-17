#pragma once
/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, cursor 2 of the
 *   License as published by the Free Software Foundation.
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
 *
 * @file lib/util/cursor.h
 * @brief Generic linked list cursor.
 *
 * @copyright 2016  The FreeRADIUS server project
 */
RCSIDH(pair_cursor_h, "$Id$")

#include <freeradius-devel/util/pair.h>

VALUE_PAIR	*fr_pair_cursor_init(vp_cursor_t *cursor, VALUE_PAIR * const *node);
void		fr_pair_cursor_copy(vp_cursor_t *out, vp_cursor_t *in);
VALUE_PAIR	*fr_pair_cursor_head(vp_cursor_t *cursor);
VALUE_PAIR	*fr_pair_cursor_tail(vp_cursor_t *cursor);
void		fr_pair_cursor_end(vp_cursor_t *cursor);
VALUE_PAIR	*fr_pair_cursor_next_by_num(vp_cursor_t *cursor, unsigned int vendor, unsigned int attr, int8_t tag);

VALUE_PAIR	*fr_pair_cursor_next_by_da(vp_cursor_t *cursor, fr_dict_attr_t const *da, int8_t tag)
		CC_HINT(nonnull);

VALUE_PAIR	*fr_pair_cursor_next_by_child_num(vp_cursor_t *cursor,
					     fr_dict_attr_t const *parent, unsigned int attr,
					     int8_t tag);

VALUE_PAIR	*fr_pair_cursor_next_by_ancestor(vp_cursor_t *cursor, fr_dict_attr_t const *ancestor, int8_t tag)
		CC_HINT(nonnull);

VALUE_PAIR	*fr_pair_cursor_next(vp_cursor_t *cursor);
VALUE_PAIR	*fr_pair_cursor_next_peek(vp_cursor_t *cursor);
VALUE_PAIR	*fr_pair_cursor_current(vp_cursor_t *cursor);
void		fr_pair_cursor_prepend(vp_cursor_t *cursor, VALUE_PAIR *vp);
void		fr_pair_cursor_append(vp_cursor_t *cursor, VALUE_PAIR *vp);
void		fr_pair_cursor_merge(vp_cursor_t *cursor, VALUE_PAIR *vp);
VALUE_PAIR	*fr_pair_cursor_remove(vp_cursor_t *cursor);
VALUE_PAIR	*fr_pair_cursor_replace(vp_cursor_t *cursor, VALUE_PAIR *new);
void		fr_pair_cursor_free(vp_cursor_t *cursor);
