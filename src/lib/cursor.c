/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 if the
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
 * @file cursor.c
 * @brief Functions to iterate over collections of VALUE_PAIRs
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/libradius.h>

/** Setup a cursor to iterate over attribute pairs
 *
 * @param cursor Where to initialise the cursor (uses existing structure).
 * @param node to start from.
 */
VALUE_PAIR *_fr_cursor_init(vp_cursor_t *cursor, VALUE_PAIR const * const *node)
{
	memset(cursor, 0, sizeof(*cursor));

	if (!node || !cursor) {
		return NULL;
	}

	/*
	 *  Useful check to see if uninitialised memory is pointed
	 *  to by node
	 */
#ifndef NDEBUG
	if (*node) VERIFY_VP(*node);
#endif
	memcpy(&cursor->first, &node, sizeof(cursor->first));
	cursor->current = *cursor->first;

	if (cursor->current) {
		VERIFY_VP(cursor->current);
		cursor->next = cursor->current->next;
	}

	return cursor->current;
}

void fr_cursor_copy(vp_cursor_t *out, vp_cursor_t *in)
{
	memcpy(out, in, sizeof(*out));
}

VALUE_PAIR *fr_cursor_first(vp_cursor_t *cursor)
{
	cursor->current = *cursor->first;

	if (cursor->current) {
		VERIFY_VP(cursor->current);
		cursor->next = cursor->current->next;
		if (cursor->next) VERIFY_VP(cursor->next);
		cursor->found = NULL;
	}

	return cursor->current;
}

/** Return the last pair in the list
 *
 */
VALUE_PAIR *fr_cursor_last(vp_cursor_t *cursor)
{
	if (!*cursor->first) return NULL;

	/* Need to start at the start */
	if (!cursor->current) {
		fr_cursor_first(cursor);
	}

	/* Wind to the end */
	while (cursor->next) {
		fr_cursor_next(cursor);
	}

	return fr_cursor_current(cursor);
}

/** Iterate over attributes of a given type in the pairlist
 *
 *
 */
VALUE_PAIR *fr_cursor_next_by_num(vp_cursor_t *cursor, unsigned int attr, unsigned int vendor, int8_t tag)
{
	VALUE_PAIR *i;

	i = pairfind(!cursor->found ? cursor->current : cursor->found->next, attr, vendor, tag);
	if (!i) {
		cursor->next = NULL;
		cursor->current = NULL;

		return NULL;
	}

	cursor->next = i->next;
	cursor->current = i;
	cursor->found = i;

	return i;
}

/** Iterate over attributes of a given DA in the pairlist
 *
 *
 */
VALUE_PAIR *fr_cursor_next_by_da(vp_cursor_t *cursor, DICT_ATTR const *da, int8_t tag)
{
	VALUE_PAIR *i;

	i = pairfind_da(!cursor->found ? cursor->current : cursor->found->next, da, tag);
	if (!i) {
		cursor->next = NULL;
		cursor->current = NULL;

		return NULL;
	}

	cursor->next = i->next;
	cursor->current = i;
	cursor->found = i;

	return i;
}

/** Retrieve the next VALUE_PAIR
 *
 *
 */
VALUE_PAIR *fr_cursor_next(vp_cursor_t *cursor)
{
	cursor->current = cursor->next;
	if (cursor->current) {
		VERIFY_VP(cursor->current);

		/*
		 *	Set this now in case 'current' gets freed before
		 *	fr_cursor_next is called again.
		 */
		cursor->next = cursor->current->next;

		/*
		 *	Next call to fr_cursor_next_by_num will start from the current
		 *	position in the list, not the last found instance.
		 */
		cursor->found = NULL;
	}

	return cursor->current;
}

/** Return what's coming next without advancing the cursor
 *
 */
VALUE_PAIR *fr_cursor_next_peek(vp_cursor_t *cursor)
{
	return cursor->next;
}

VALUE_PAIR *fr_cursor_current(vp_cursor_t *cursor)
{
	if (cursor->current) {
		VERIFY_VP(cursor->current);
	}

	return cursor->current;
}

/** Insert a single VP
 *
 * @todo don't use with pairdelete
 */
void fr_cursor_insert(vp_cursor_t *cursor, VALUE_PAIR *add)
{
	VALUE_PAIR *i;

	if (!add) {
		return;
	}

	VERIFY_VP(add);

	/*
	 *	Only allow one VP to by inserted at a time
	 */
	add->next = NULL;

	/*
	 *	Cursor was initialised with a pointer to a NULL value_pair
	 */
	if (!*cursor->first) {
		*cursor->first = add;
		cursor->current = add;

		return;
	}

	/*
	 *	We don't yet know where the last VALUE_PAIR is
	 *
	 *	Assume current is closer to the end of the list and use that if available.
	 */
	if (!cursor->last) {
		cursor->last = cursor->current ? cursor->current : *cursor->first;
	}

	VERIFY_VP(cursor->last);

	/*
	 *	Something outside of the cursor added another VALUE_PAIR
	 */
	if (cursor->last->next) {
		for (i = cursor->last; i; i = i->next) {
			VERIFY_VP(i);
			cursor->last = i;
		}
	}

	/*
	 *	Either current was never set, or something iterated to the end of the
	 *	attribute list.
	 */
	if (!cursor->current) {
		cursor->current = add;
	}

	/*
	 *	If there's no next cursor, and the pair we just inserted has additional
	 *	linked pairs, we need to set next to be the next VP in the list.
	 */
	if (!cursor->next) {
		cursor->next = add->next;
	}

	cursor->last->next = add;
}

/** Merges two sets of VPs
 *
 * The list represented by cursor will hold the union of cursor and
 * add lists.
 *
 * @param cursor to insert VALUE_PAIRs with
 * @param add one or more VALUE_PAIRs.
 */
void fr_cursor_merge(vp_cursor_t *cursor, VALUE_PAIR *add)
{
	vp_cursor_t from;
	VALUE_PAIR *vp;

	for (vp = fr_cursor_init(&from, &add);
	     vp;
	     vp = fr_cursor_next(&from)) {
	 	fr_cursor_insert(cursor, vp);
	}
}

/** Remove the current pair
 *
 * @todo this is really inefficient and should be fixed...
 *
 * @param cursor to remove the current pair from.
 * @return NULL on error, else the VALUE_PAIR we just removed.
 */
VALUE_PAIR *fr_cursor_remove(vp_cursor_t *cursor)
{
	VALUE_PAIR *vp, **last;

	vp = fr_cursor_current(cursor);
	if (!vp) {
		return NULL;
	}

	last = cursor->first;
	while (*last != vp) {
		last = &(*last)->next;
	}

	fr_cursor_next(cursor);   /* Advance the cursor past the one were about to delete */

	*last = vp->next;
	vp->next = NULL;

	/* Fixup cursor->found if we removed the VP it was referring to */
	if (vp == cursor->found) cursor->found = *last;

	return vp;
}

/** Replace the current pair
 *
 * @todo this is really inefficient and should be fixed...
 *
 * @param cursor to replace the current pair in.
 * @param new VALUE_PAIR to insert.
 * @return NULL on error, else the VALUE_PAIR we just replaced.
 */
VALUE_PAIR *fr_cursor_replace(vp_cursor_t *cursor, VALUE_PAIR *new)
{
	VALUE_PAIR *vp, **last;

	vp = fr_cursor_current(cursor);
	if (!vp) {
		*cursor->first = new;
		return NULL;
	}

	last = cursor->first;
	while (*last != vp) {
	    last = &(*last)->next;
	}

	fr_cursor_next(cursor);   /* Advance the cursor past the one were about to replace */

	*last = new;
	new->next = vp->next;
	vp->next = NULL;

	return vp;
}
