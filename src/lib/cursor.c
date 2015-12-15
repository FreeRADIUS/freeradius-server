/*
 *   This program is is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License, version 2 of the
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
 * @file cursor.c
 * @brief Functions to iterate over collections of VALUE_PAIRs
 *
 * @note Do not modify collections of VALUE_PAIRs pointed to be a cursor
 *	 with none fr_cursor_* functions, during the lifetime of that cursor.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013-2015 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */

#include <freeradius-devel/libradius.h>

/** Internal function to update cursor state
 *
 * @param cursor to operate on.
 * @param vp to set current and found positions to.
 * @return value passed in as vp.
 */
inline static VALUE_PAIR *fr_cursor_update(vp_cursor_t *cursor, VALUE_PAIR *vp)
{
	if (!vp) {
		cursor->next = NULL;
		cursor->current = NULL;

		return NULL;
	}

	cursor->next = vp->next;
	cursor->current = vp;
	cursor->found = vp;

	return vp;
}

/** Setup a cursor to iterate over attribute pairs
 *
 * @param cursor Where to initialise the cursor (uses existing structure).
 * @param const_vp to start from.
 * @return the attribute pointed to by vp.
 */
VALUE_PAIR *fr_cursor_init(vp_cursor_t *cursor, VALUE_PAIR * const *const_vp)
{
	VALUE_PAIR **vp;

	if (!const_vp || !cursor) {
		return NULL;
	}

	memset(cursor, 0, sizeof(*cursor));

	memcpy(&vp, &const_vp, sizeof(vp)); /* stupid const hacks */

	/*
	 *  Useful check to see if uninitialised memory is pointed
	 *  to by vp
	 */
#ifndef NDEBUG
	if (*vp) VERIFY_VP(*vp);
#endif
	memcpy(&cursor->first, &vp, sizeof(cursor->first));
	cursor->current = *cursor->first;

	if (cursor->current) {
		VERIFY_VP(cursor->current);
		cursor->next = cursor->current->next;
	}

	return cursor->current;
}

/** Copy a cursor
 *
 * @param in Cursor to copy.
 * @param out Where to copy the cursor to.
 */
void fr_cursor_copy(vp_cursor_t *out, vp_cursor_t *in)
{
	memcpy(out, in, sizeof(*out));
}

/** Rewind cursor to the start of the list
 *
 * @param cursor to operate on.
 * @return the VALUE_PAIR at the start of the list.
 */
VALUE_PAIR *fr_cursor_first(vp_cursor_t *cursor)
{
	if (!cursor->first) return NULL;

	cursor->current = *cursor->first;

	if (cursor->current) {
		VERIFY_VP(cursor->current);
		cursor->next = cursor->current->next;
		if (cursor->next) VERIFY_VP(cursor->next);
		cursor->found = NULL;
	}

	return cursor->current;
}

/** Wind cursor to the last pair in the list
 *
 * @param cursor to operate on.
 * @return the VALUE_PAIR at the end of the list.
 */
VALUE_PAIR *fr_cursor_last(vp_cursor_t *cursor)
{
	if (!cursor->first || !*cursor->first) return NULL;

	/* Need to start at the start */
	if (!cursor->current) fr_cursor_first(cursor);

	/* Wind to the end */
	while (cursor->next) fr_cursor_next(cursor);

	return cursor->current;
}

/** Iterate over a collection of VALUE_PAIRs of a given type in the pairlist
 *
 * Find the next attribute of a given type. If no fr_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @param cursor to operate on.
 * @param attr number to match.
 * @param vendor number to match (0 for none vendor attribute).
 * @param tag to match. Either a tag number or TAG_ANY to match any tagged or
 *	  untagged attribute, TAG_NONE to match attributes without tags.
 * @return the next matching VALUE_PAIR, or NULL if no VALUE_PAIRs match.
 */
VALUE_PAIR *fr_cursor_next_by_num(vp_cursor_t *cursor, unsigned int attr, unsigned int vendor, int8_t tag)
{
	VALUE_PAIR *i;

	if (!cursor->first) return NULL;

	for (i = !cursor->found ? cursor->current : cursor->found->next;
	     i != NULL;
	     i = i->next) {
		VERIFY_VP(i);
		if ((i->da->attr == attr) && (i->da->vendor == vendor) &&
		    (!i->da->flags.has_tag || TAG_EQ(tag, i->tag))) {
			break;
		}
	}

	return fr_cursor_update(cursor, i);
}

/** Iterate over attributes of a given DA in the pairlist
 *
 * Find the next attribute of a given type. If no fr_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @note DICT_ATTR pointers are compared, not the attribute numbers and vendors.
 *
 * @param cursor to operate on.
 * @param da to match.
 * @param tag to match. Either a tag number or TAG_ANY to match any tagged or
 *	  untagged attribute, TAG_NONE to match attributes without tags.
 * @return the next matching VALUE_PAIR, or NULL if no VALUE_PAIRs match.
 */
VALUE_PAIR *fr_cursor_next_by_da(vp_cursor_t *cursor, DICT_ATTR const *da, int8_t tag)
{
	VALUE_PAIR *i;

	if (!cursor->first) return NULL;

	for (i = !cursor->found ? cursor->current : cursor->found->next;
	     i != NULL;
	     i = i->next) {
		VERIFY_VP(i);
		if ((i->da == da) &&
		    (!i->da->flags.has_tag || TAG_EQ(tag, i->tag))) {
			break;
		}
	}

	return fr_cursor_update(cursor, i);
}

/** Advanced the cursor to the next VALUE_PAIR
 *
 * @param cursor to operate on.
 * @return the next VALUE_PAIR, or NULL if no more VALUE_PAIRS in the collection.
 */
VALUE_PAIR *fr_cursor_next(vp_cursor_t *cursor)
{
	if (!cursor->first) return NULL;

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

/** Return the next VALUE_PAIR without advancing the cursor
 *
 * @param cursor to operate on.
 * @return the next VALUE_PAIR, or NULL if no more VALUE_PAIRS in the collection.
 */
VALUE_PAIR *fr_cursor_next_peek(vp_cursor_t *cursor)
{
	return cursor->next;
}

/** Return the VALUE_PAIR the cursor current points to
 *
 * @param cursor to operate on.
 * @return the VALUE_PAIR the cursor currently points to.
 */
VALUE_PAIR *fr_cursor_current(vp_cursor_t *cursor)
{
	if (cursor->current) VERIFY_VP(cursor->current);

	return cursor->current;
}

/** Insert a single VALUE_PAIR at the end of the list
 *
 * @note Will not advance cursor position to new attribute, but will set cursor
 *	 to this attribute, if it's the first one in the list.
 *
 * Insert a VALUE_PAIR at the end of the list.
 *
 * @param cursor to operate on.
 * @param vp to insert.
 */
void fr_cursor_insert(vp_cursor_t *cursor, VALUE_PAIR *vp)
{
	VALUE_PAIR *i;

	if (!fr_assert(cursor->first)) return;	/* cursor must have been initialised */

	if (!vp) return;

	VERIFY_VP(vp);

	/*
	 *	Only allow one VP to by inserted at a time
	 */
	vp->next = NULL;

	/*
	 *	Cursor was initialised with a pointer to a NULL value_pair
	 */
	if (!*cursor->first) {
		*cursor->first = vp;
		cursor->current = vp;

		return;
	}

	/*
	 *	We don't yet know where the last VALUE_PAIR is
	 *
	 *	Assume current is closer to the end of the list and
	 *	use that if available.
	 */
	if (!cursor->last) cursor->last = cursor->current ? cursor->current : *cursor->first;

	VERIFY_VP(cursor->last);

	/*
	 *	Wind last to the end of the list.
	 */
	if (cursor->last->next) {
		for (i = cursor->last; i; i = i->next) {
			VERIFY_VP(i);
			cursor->last = i;
		}
	}

	/*
	 *	Either current was never set, or something iterated to the
	 *	end of the attribute list. In both cases the newly inserted
	 *	VALUE_PAIR should be set as the current VALUE_PAIR.
	 */
	if (!cursor->current) cursor->current = vp;

	/*
	 *	Add the VALUE_PAIR to the end of the list
	 */
	cursor->last->next = vp;
	cursor->last = vp;	/* Wind it forward a little more */

	/*
	 *	If the next pointer was NULL, and the VALUE_PAIR
	 *	just added has a next pointer value, set the cursor's next
	 *	pointer to the VALUE_PAIR's next pointer.
	 */
	if (!cursor->next) cursor->next = cursor->current->next;
}

/** Merges multiple VALUE_PAIR into the cursor
 *
 * Add multiple VALUE_PAIR from add to cursor.
 *
 * @param cursor to insert VALUE_PAIRs with
 * @param add one or more VALUE_PAIRs (may be NULL, which results in noop).
 */
void fr_cursor_merge(vp_cursor_t *cursor, VALUE_PAIR *add)
{
	vp_cursor_t from;
	VALUE_PAIR *vp;

	if (!add) return;

	if (!fr_assert(cursor->first)) return;	/* cursor must have been initialised */

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
 * The current VP will be set to the one before the VP being removed,
 * this is so the commonly used check and remove loop (below) works
 * as expected.
 @code {.c}
   for (vp = fr_cursor_init(&cursor, head);
        vp;
        vp = fr_cursor_next(&cursor) {
        if (<condition>) {
            vp = fr_cursor_remove(&cursor);
            talloc_free(vp);
        }
   }
 @endcode
 *
 * @param cursor to remove the current pair from.
 * @return NULL on error, else the VALUE_PAIR that was just removed.
 */
VALUE_PAIR *fr_cursor_remove(vp_cursor_t *cursor)
{
	VALUE_PAIR *vp, *before;

	if (!fr_assert(cursor->first)) return NULL;	/* cursor must have been initialised */

	vp = cursor->current;
	if (!vp) return NULL;

	/*
	 *	Where VP is head of the list
	 */
	if (*(cursor->first) == vp) {
		*(cursor->first) = vp->next;
		cursor->current = vp->next;
		cursor->next = vp->next ? vp->next->next : NULL;
		before = NULL;
		goto fixup;
	}

	/*
	 *	Where VP is not head of the list
	 */
	before = *(cursor->first);
	if (!before) return NULL;

	/*
	 *	Find the VP immediately preceding the one being removed
	 */
	while (before->next != vp) before = before->next;

	cursor->next = before->next = vp->next;	/* close the gap */
	cursor->current = before;		/* current jumps back one, but this is usually desirable */

fixup:
	vp->next = NULL;			/* limit scope of fr_pair_list_free() */

	/*
	 *	Fixup cursor->found if we removed the VP it was referring to,
	 *	and point to the previous one.
	 */
	if (vp == cursor->found) cursor->found = before;

	/*
	 *	Fixup cursor->last if we removed the VP it was referring to
	 */
	if (vp == cursor->last) cursor->last = cursor->current;
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

	if (!fr_assert(cursor->first)) return NULL;	/* cursor must have been initialised */

	vp = cursor->current;
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
