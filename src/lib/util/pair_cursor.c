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

/** Functions to iterate over collections of fr_pair_ts
 *
 * @note Do not modify collections of fr_pair_ts pointed to by a cursor
 *	 with none fr_pair_cursor_* functions, during the lifetime of that cursor.
 *
 * @file src/lib/util/pair_cursor.c
 *
 * @author Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2015 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2013-2015 The FreeRADIUS Server Project.
 */
#include <freeradius-devel/missing.h>
#include <freeradius-devel/util/pair_cursor.h>

/** Internal function to update cursor state
 *
 * @param cursor to operate on.
 * @param vp to set current and found positions to.
 * @return value passed in as #fr_pair_t.
 */
inline static fr_pair_t *fr_pair_cursor_update(vp_cursor_t *cursor, fr_pair_t *vp)
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
fr_pair_t *fr_pair_cursor_init(vp_cursor_t *cursor, fr_pair_t * const *const_vp)
{
	fr_pair_t **vp;

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
	if (*vp) VP_VERIFY(*vp);
#endif
	memcpy(&cursor->first, &vp, sizeof(cursor->first));
	cursor->current = *cursor->first;

	if (cursor->current) {
		VP_VERIFY(cursor->current);
		cursor->next = cursor->current->next;
	}

	return cursor->current;
}

/** Copy a cursor
 *
 * @param in Cursor to copy.
 * @param out Where to copy the cursor to.
 */
void fr_pair_cursor_copy(vp_cursor_t *out, vp_cursor_t *in)
{
	memcpy(out, in, sizeof(*out));
}

/** Rewind cursor to the start of the list
 *
 * @param cursor to operate on.
 * @return #fr_pair_t at the start of the list.
 */
fr_pair_t *fr_pair_cursor_head(vp_cursor_t *cursor)
{
	if (!cursor->first) return NULL;

	cursor->current = *cursor->first;

	if (cursor->current) {
		VP_VERIFY(cursor->current);
		cursor->next = cursor->current->next;
		if (cursor->next) VP_VERIFY(cursor->next);
		cursor->found = NULL;
	}

	return cursor->current;
}

/** Wind cursor to the last pair in the list
 *
 * @param cursor to operate on.
 * @return #fr_pair_t at the end of the list.
 */
fr_pair_t *fr_pair_cursor_tail(vp_cursor_t *cursor)
{
	if (!cursor->first || !*cursor->first) return NULL;

	/* Need to start at the start */
	if (!cursor->current) fr_pair_cursor_head(cursor);

	/* Wind to the end */
	while (cursor->next) fr_pair_cursor_next(cursor);

	return cursor->current;
}

/** Moves cursor past the last attribute to the end
 *
 * Primarily useful for setting up the cursor for freeing attributes added
 * during the execution of a function, which later errors out, requiring only
 * the attribute(s) that it added to be freed and the attributes already
 * present in the list to remain untouched.
 *
 @code {.c}
   int my_cursor_insert_func(vp_cursor_t *cursor)
   {
   	fr_pair_cursor_end(cursor);

   	fr_pair_cursor_append(cursor, fr_pair_alloc_by_num(NULL, 0, FR_MESSAGE_AUTHENTICATOR));

   	if (bad_thing) {
   		fr_pair_cursor_free(cursor);
   		return -1;
   	}

   	return 0;
   }
 @endcode
 *
 * @param cursor to operate on.
 */
void fr_pair_cursor_end(vp_cursor_t *cursor)
{
	if (!cursor->first || !*cursor->first) return;

	/* Already at the end */
	if (!cursor->current && cursor->last && !cursor->last->next) return;

	/* Need to start at the start */
	if (!cursor->current) fr_pair_cursor_head(cursor);

	/* Wind to the end */
	while (cursor->next) fr_pair_cursor_next(cursor);

	/* One more time to move us off the end*/
	fr_pair_cursor_next(cursor);

	return;
}

/** Iterate over a collection of fr_pair_ts of a given type in the pairlist
 *
 * Find the next attribute of a given type. If no fr_pair_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_pair_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @param cursor to operate on.
 * @param attr number to match.
 * @param vendor number to match (0 for none vendor attribute).
 * @return
 *	- The next matching #fr_pair_t.
 *	- NULL if no #fr_pair_t (s) match.
 */
fr_pair_t *fr_pair_cursor_next_by_num(vp_cursor_t *cursor, unsigned int vendor, unsigned int attr)
{
	fr_pair_t *i;

	if (!cursor->first) return NULL;

	if (!vendor) {
		/*
		 *	Find top-level attributes.
		 */
		for (i = cursor->found ? cursor->found->next : cursor->current;
		     i != NULL;
		     i = i->next) {
			VP_VERIFY(i);
			if (fr_dict_attr_is_top_level(i->da) && (i->da->attr == attr)) break;
		}
	} else {
		for (i = cursor->found ? cursor->found->next : cursor->current;
		     i != NULL;
		     i = i->next) {
			VP_VERIFY(i);
			if ((i->da->parent->type == FR_TYPE_VENDOR) &&
			    (i->da->attr == attr) && (fr_dict_vendor_num_by_da(i->da) == vendor)) break;
		}
	}

	return fr_pair_cursor_update(cursor, i);
}

/** Iterate over a collection of fr_pair_ts of a given type in the pairlist
 *
 * Find the next attribute of a given type. If no fr_pair_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_pair_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @note If the attribute specified by attr is not a child of the parent, NULL will be returned.
 *
 * @param cursor	to operate on.
 * @param parent	to search for attr in.
 * @param attr		number to match.
 * @return
 *	- The next matching #fr_pair_t.
	- NULL if no #fr_pair_t (s) match (or attr doesn't exist).
 */
fr_pair_t *fr_pair_cursor_next_by_child_num(vp_cursor_t *cursor,
					fr_dict_attr_t const *parent, unsigned int attr)
{
	fr_dict_attr_t const *da;
	fr_pair_t *i;

	if (!cursor->first) return NULL;

	da = fr_dict_attr_child_by_num(parent, attr);
	if (!da) return NULL;

	for (i = cursor->found ? cursor->found->next : cursor->current;
	     i != NULL;
	     i = i->next) {
		VP_VERIFY(i);
		if (i->da == da) break;
	}

	return fr_pair_cursor_update(cursor, i);
}

/** Iterate over attributes of a given DA in the pairlist
 *
 * Find the next attribute of a given type. If no fr_pair_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_pair_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @note fr_dict_attr_t pointers are compared, not the attribute numbers and vendors.
 *
 * @param cursor to operate on.
 * @param da to match.
 * @return
 *	- Next matching #fr_pair_t.
 *	- NULL if no #fr_pair_t (s) match.
 */
fr_pair_t *fr_pair_cursor_next_by_da(vp_cursor_t *cursor, fr_dict_attr_t const *da)
{
	fr_pair_t *i;

	if (!cursor->first) return NULL;

	for (i = cursor->found ? cursor->found->next : cursor->current;
	     i != NULL;
	     i = i->next) {
		VP_VERIFY(i);
		if (i->da == da) break;
	}

	return fr_pair_cursor_update(cursor, i);
}

/** Iterate over attributes with a given ancestor
 *
 * Find the next attribute of a given type. If no fr_pair_cursor_next_by_* function
 * has been called on a cursor before, or the previous call returned
 * NULL, the search will start with the current attribute. Subsequent calls to
 * fr_pair_cursor_next_by_* functions will start the search from the previously
 * matched attribute.
 *
 * @param cursor to operate on.
 * @param ancestor attribute to match on.
 * @return
 *	- Next matching #fr_pair_t.
 *	- NULL if no #fr_pair_t (s) match.
 */
fr_pair_t *fr_pair_cursor_next_by_ancestor(vp_cursor_t *cursor, fr_dict_attr_t const *ancestor)
{
	fr_pair_t *i;

	if (!cursor->first) return NULL;

	for (i = cursor->found ? cursor->found->next : cursor->current;
	     i != NULL;
	     i = i->next) {
		VP_VERIFY(i);
		if (fr_dict_attr_common_parent(ancestor, i->da, true)) break;
	}

	return fr_pair_cursor_update(cursor, i);
}

/** Advanced the cursor to the next fr_pair_t
 *
 * @param cursor to operate on.
 * @return
 *	- Next #fr_pair_t.
 *	- NULL if no more #fr_pair_t in the collection.
 */
fr_pair_t *fr_pair_cursor_next(vp_cursor_t *cursor)
{
	if (!cursor->first) return NULL;

	cursor->current = cursor->next;
	if (cursor->current) {
		VP_VERIFY(cursor->current);

		/*
		 *	Set this now in case 'current' gets freed before
		 *	fr_pair_cursor_next is called again.
		 */
		cursor->next = cursor->current->next;

		/*
		 *	Next call to fr_pair_cursor_next_by_num will start from the current
		 *	position in the list, not the last found instance.
		 */
		cursor->found = NULL;
	}

	return cursor->current;
}

/** Return the next fr_pair_t without advancing the cursor
 *
 * @param cursor to operate on.
 * @return
 *	- Next #fr_pair_t.
 *	- NULL if no more #fr_pair_t are in the collection.
 */
fr_pair_t *fr_pair_cursor_next_peek(vp_cursor_t *cursor)
{
	return cursor->next;
}

/** Return the fr_pair_t the cursor current points to
 *
 * @param cursor to operate on.
 * @return the #fr_pair_t the cursor currently points to.
 */
fr_pair_t *fr_pair_cursor_current(vp_cursor_t *cursor)
{
	if (cursor->current) VP_VERIFY(cursor->current);

	return cursor->current;
}

/** Insert a single fr_pair_t at the start of the list
 *
 * @note Will not advance cursor position to new attribute, but will set cursor
 *	 to this attribute, if it's the first one in the list.
 *
 * Insert a fr_pair_t at the start of the list.
 *
 * @param cursor to operate on.
 * @param vp to insert.
 */
void fr_pair_cursor_prepend(vp_cursor_t *cursor, fr_pair_t *vp)
{
	if (!fr_cond_assert(cursor->first)) return;	/* cursor must have been initialised */

	if (!vp) return;

	VP_VERIFY(vp);
	LIST_VERIFY(*(cursor->first));

	/*
	 *	Only allow one VP to by inserted at a time
	 */
	vp->next = NULL;

	/*
	 *	Cursor was initialised with a pointer to a NULL value_pair
	 */
	if (!*(cursor->first)) {
		*cursor->first = vp;
		cursor->current = vp;

		return;
	}

	/*
	 *	Append to the head of the list
	 */
	vp->next = *cursor->first;
	*cursor->first = vp;

	/*
	 *	Either current was never set, or something iterated to the
	 *	end of the attribute list. In both cases the newly inserted
	 *	fr_pair_t should be set as the current fr_pair_t.
	 */
	if (!cursor->current) cursor->current = vp;

	/*
	 *	If the next pointer was NULL, and the fr_pair_t
	 *	just added has a next pointer value, set the cursor's next
	 *	pointer to the fr_pair_t's next pointer.
	 */
	if (!cursor->next) cursor->next = cursor->current->next;

	LIST_VERIFY(*(cursor->first));
}

/** Insert a single fr_pair_t at the end of the list
 *
 * @note Will not advance cursor position to new attribute, but will set cursor
 *	 to this attribute, if it's the first one in the list.
 *
 * Insert a fr_pair_t at the end of the list.
 *
 * @param cursor to operate on.
 * @param vp to insert.
 */
void fr_pair_cursor_append(vp_cursor_t *cursor, fr_pair_t *vp)
{
	fr_pair_t *i;

	if (!fr_cond_assert(cursor->first)) return;	/* cursor must have been initialised */

	if (!vp) return;

	VP_VERIFY(vp);
	LIST_VERIFY(*(cursor->first));

	/*
	 *	Only allow one VP to by inserted at a time
	 */
	vp->next = NULL;

	/*
	 *	Cursor was initialised with a pointer to a NULL value_pair
	 */
	if (!*(cursor->first)) {
		*cursor->first = vp;
		cursor->current = vp;

		return;
	}

	/*
	 *	We don't yet know where the last fr_pair_t is
	 *
	 *	Assume current is closer to the end of the list and
	 *	use that if available.
	 */
	if (!cursor->last) cursor->last = cursor->current ? cursor->current : *cursor->first;

	VP_VERIFY(cursor->last);

	/*
	 *	Wind last to the end of the list.
	 */
	if (cursor->last->next) {
		for (i = cursor->last; i; i = i->next) {
			VP_VERIFY(i);
			cursor->last = i;
		}
	}

	/*
	 *	Either current was never set, or something iterated to the
	 *	end of the attribute list. In both cases the newly inserted
	 *	fr_pair_t should be set as the current fr_pair_t.
	 */
	if (!cursor->current) cursor->current = vp;

	/*
	 *	Add the fr_pair_t to the end of the list
	 */
	cursor->last->next = vp;
	cursor->last = vp;	/* Wind it forward a little more */

	/*
	 *	If the next pointer was NULL, and the fr_pair_t
	 *	just added has a next pointer value, set the cursor's next
	 *	pointer to the fr_pair_t's next pointer.
	 */
	if (!cursor->next) cursor->next = cursor->current->next;

	LIST_VERIFY(*(cursor->first));
}

/** Merges multiple fr_pair_t into the cursor
 *
 * Add multiple fr_pair_t from add to cursor.
 *
 * @param cursor to insert fr_pair_ts with
 * @param add one or more fr_pair_ts (may be NULL, which results in noop).
 */
void fr_pair_cursor_merge(vp_cursor_t *cursor, fr_pair_t *add)
{
	vp_cursor_t from;
	fr_pair_t *vp;

	if (!add) return;

	if (!fr_cond_assert(cursor->first)) return;	/* cursor must have been initialised */

	for (vp = fr_pair_cursor_init(&from, &add);
	     vp;
	     vp = fr_pair_cursor_next(&from)) {
	 	fr_pair_cursor_append(cursor, vp);
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
   for (vp = fr_pair_cursor_init(&cursor, head);
        vp;
        vp = fr_pair_cursor_next(&cursor) {
        if (<condition>) {
            vp = fr_pair_cursor_remove(&cursor);
            talloc_free(vp);
        }
   }
 @endcode
 *
 * @param cursor to remove the current pair from.
 * @return
 *	- #fr_pair_t we just replaced.
 *	- NULL on error.
 */
fr_pair_t *fr_pair_cursor_remove(vp_cursor_t *cursor)
{
	fr_pair_t *vp, *before;

	if (!fr_cond_assert(cursor->first)) return NULL;	/* cursor must have been initialised */

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
 * @param new #fr_pair_t to insert.
 * @return
 *	- #fr_pair_t we just replaced.
 *	- NULL on error.
 */
fr_pair_t *fr_pair_cursor_replace(vp_cursor_t *cursor, fr_pair_t *new)
{
	fr_pair_t *vp, **last;

	if (!fr_cond_assert(cursor->first)) return NULL;	/* cursor must have been initialised */

	LIST_VERIFY(*(cursor->first));

	vp = cursor->current;
	if (!vp) {
		*cursor->first = new;
		return NULL;
	}

	last = cursor->first;
	while (*last != vp) {
	    last = &(*last)->next;
	}

	fr_pair_cursor_next(cursor);   /* Advance the cursor past the one were about to replace */

	*last = new;
	new->next = vp->next;
	vp->next = NULL;

	LIST_VERIFY(*(cursor->first));

	return vp;
}

/** Free the current pair and all pairs after it
 *
 * @note Use fr_pair_cursor_remove and talloc_free to free single pairs.
 *
 * Will move the cursor back one, then free the current pair and all
 * fr_pair_ts after it.
 *
 * Usually used in conjunction with #fr_pair_cursor_end and #fr_pair_cursor_append.
 *
 * @param cursor to free pairs in.
 */
void fr_pair_cursor_free(vp_cursor_t *cursor)
{
	fr_pair_t *vp, *before;
	bool found = false, last = false;

	if (!*(cursor->first)) return;	/* noop */

	/*
	 *	Fast path if the cursor has been rewound to the start
	 */
	if (cursor->current == *(cursor->first)) {
		cursor->current = NULL;
		cursor->next = NULL;
		cursor->found = NULL;
		cursor->last = NULL;
		fr_pair_list_free(cursor->first);
	}

	vp = cursor->current;
	if (!vp) return;

	/*
	 *	Where VP is not head of the list
	 */
	before = *(cursor->first);
	if (!before) return;

	/*
	 *	Find the VP immediately preceding the one being removed
	 */
	while (before->next != vp) {
		if (before == cursor->found) found = true;
		if (before == cursor->last) last = true;
		before = before->next;
	}

	fr_pair_list_free(&before->next);

	cursor->current = before;		/* current jumps back one, but this is usually desirable */
	cursor->next = NULL;			/* we just truncated the list, there is no next... */

	/*
	 *	Fixup found and last pointers
	 */
	if (!found) cursor->found = cursor->current;
	if (!last) cursor->last = cursor->current;
}

/** Recurse into a child of type #FR_TYPE_GROUP
 *
 * @param ctx	  talloc ctx for child cursor.  Can be freed with `talloc_free()`
 * @param cursor  the parent cursor.  The current VP *must* be of #FR_TYPE_GROUP
 */
vp_cursor_t *fr_pair_cursor_recurse_child(TALLOC_CTX *ctx, vp_cursor_t *cursor)
{
	vp_cursor_t *child;

	if (!cursor->current) return NULL;

	if (cursor->current->da->type != FR_TYPE_GROUP) return NULL;

	child = talloc_zero(ctx, vp_cursor_t);
	if (!child) return NULL;

	(void) fr_pair_cursor_init(child, (fr_pair_t * const *) &cursor->current->vp_group);

	return child;
}
