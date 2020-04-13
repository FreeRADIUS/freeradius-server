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

/**
 * $Id$
 *
 * @file src/lib/server/pairmove.c
 * @brief Old style mapping code
 *
 * @copyright 2007 The FreeRADIUS server project
 * @copyright 2007 Alan DeKok (aland@deployingradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/server/pairmove.h>

#include <freeradius-devel/protocol/radius/rfc2865.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>

#include <ctype.h>

/*
 *	The fr_pair_list_move() function in src/lib/valuepair.c does all sorts of
 *	extra magic that we don't want here.
 *
 *	FIXME: integrate this with the code calling it, so that we
 *	only fr_pair_list_copy() those attributes that we're really going to
 *	use.
 */
void radius_pairmove(REQUEST *request, VALUE_PAIR **to, VALUE_PAIR *from, bool do_xlat)
{
	int		i, j, count, from_count, to_count, tailto;
	fr_cursor_t	cursor;
	VALUE_PAIR	*vp, *next, **last;
	VALUE_PAIR	**from_list, **to_list;
	VALUE_PAIR	*append, **append_tail;
	VALUE_PAIR 	*to_copy = NULL;
	bool		*edited = NULL;
	TALLOC_CTX	*ctx;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  This also makes it easier to
	 *	insert and remove attributes.
	 *
	 *	It also means that the operators apply ONLY to the
	 *	attributes in the original list.  With the previous
	 *	implementation of fr_pair_list_move(), adding two attributes
	 *	via "+=" and then "=" would mean that the second one
	 *	wasn't added, because of the existence of the first
	 *	one in the "to" list.  This implementation doesn't
	 *	have that bug.
	 *
	 *	Also, the previous implementation did NOT implement
	 *	"-=" correctly.  If two of the same attributes existed
	 *	in the "to" list, and you tried to subtract something
	 *	matching the *second* value, then the fr_pair_delete_by_da()
	 *	function was called, and the *all* attributes of that
	 *	number were deleted.  With this implementation, only
	 *	the matching attributes are deleted.
	 */
	count = 0;
	for (vp = fr_cursor_init(&cursor, &from); vp; vp = fr_cursor_next(&cursor)) count++;
	from_list = talloc_array(request, VALUE_PAIR *, count);

	for (vp = fr_cursor_init(&cursor, to); vp; vp = fr_cursor_next(&cursor)) count++;
	to_list = talloc_array(request, VALUE_PAIR *, count);

	append = NULL;
	append_tail = &append;

	/*
	 *	Move the lists to the arrays, and break the list
	 *	chains.
	 */
	from_count = 0;
	for (vp = from; vp != NULL; vp = next) {
		next = vp->next;
		from_list[from_count++] = vp;
		vp->next = NULL;
	}

	to_count = 0;
	ctx = talloc_parent(*to);
	MEM(fr_pair_list_copy(ctx, &to_copy, *to) >= 0);
	for (vp = to_copy; vp != NULL; vp = next) {
		next = vp->next;
		to_list[to_count++] = vp;
		vp->next = NULL;
	}
	tailto = to_count;
	edited = talloc_zero_array(request, bool, to_count);

	RDEBUG4("::: FROM %d TO %d MAX %d", from_count, to_count, count);

	/*
	 *	Now that we have the lists initialized, start working
	 *	over them.
	 */
	for (i = 0; i < from_count; i++) {
		int found;

		RDEBUG4("::: Examining %s", from_list[i]->da->name);

		if (do_xlat) xlat_eval_pair(request, from_list[i]);

		/*
		 *	Attribute should be appended, OR the "to" list
		 *	is empty, and we're supposed to replace or
		 *	"add if not existing".
		 */
		if (from_list[i]->op == T_OP_ADD) goto do_append;

		found = false;
		for (j = 0; j < to_count; j++) {
			if (edited[j] || !to_list[j] || !from_list[i]) continue;

			/*
			 *	Attributes aren't the same, skip them.
			 */
			if (from_list[i]->da != to_list[j]->da) {
				continue;
			}

			/*
			 *	We don't use a "switch" statement here
			 *	because we want to break out of the
			 *	"for" loop over 'j' in most cases.
			 */

			/*
			 *	Over-write the FIRST instance of the
			 *	matching attribute name.  We free the
			 *	one in the "to" list, and move over
			 *	the one in the "from" list.
			 */
			if (from_list[i]->op == T_OP_SET) {
				RDEBUG4("::: OVERWRITING %s FROM %d TO %d",
				       to_list[j]->da->name, i, j);
				fr_pair_list_free(&to_list[j]);
				to_list[j] = from_list[i];
				from_list[i] = NULL;
				edited[j] = true;
				break;
			}

			/*
			 *	Add the attribute only if it does not
			 *	exist... but it exists, so we stop
			 *	looking.
			 */
			if (from_list[i]->op == T_OP_EQ) {
				found = true;
				break;
			}

			/*
			 *	Delete every attribute, independent
			 *	of its value.
			 */
			if (from_list[i]->op == T_OP_CMP_FALSE) {
				goto delete;
			}

			/*
			 *	Delete all matching attributes from
			 *	"to"
			 */
			if ((from_list[i]->op == T_OP_SUB) ||
			    (from_list[i]->op == T_OP_CMP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE)) {
				int rcode;
				int old_op = from_list[i]->op;

				/*
				 *	Check for equality.
				 */
				from_list[i]->op = T_OP_CMP_EQ;

				/*
				 *	If equal, delete the one in
				 *	the "to" list.
				 */
				rcode = paircmp_pairs(NULL, from_list[i],
							   to_list[j]);
				/*
				 *	We may want to do more
				 *	subtractions, so we re-set the
				 *	operator back to it's original
				 *	value.
				 */
				from_list[i]->op = old_op;

				switch (old_op) {
				case T_OP_CMP_EQ:
					if (rcode != 0) goto delete;
					break;

				case T_OP_SUB:
					if (rcode == 0) {
					delete:
						RDEBUG4("::: DELETING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = NULL;
					}
					break;

					/*
					 *	Enforce <=.  If it's
					 *	>, replace it.
					 */
				case T_OP_LE:
					if (rcode > 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = true;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_list[i]->da->name, i, j);
						fr_pair_list_free(&to_list[j]);
						to_list[j] = from_list[i];
						from_list[i] = NULL;
						edited[j] = true;
					}
					break;
				}

				continue;
			}

			fr_assert(0 == 1); /* panic! */
		}

		/*
		 *	We were asked to add it if it didn't exist,
		 *	and it doesn't exist.  Move it over to the
		 *	tail of the "to" list, UNLESS it was already
		 *	moved by another operator.
		 */
		if (!found && from_list[i]) {
			if ((from_list[i]->op == T_OP_EQ) ||
			    (from_list[i]->op == T_OP_LE) ||
			    (from_list[i]->op == T_OP_GE) ||
			    (from_list[i]->op == T_OP_SET)) {
			do_append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_list[i]->da->name, i, tailto);
				*append_tail = from_list[i];
				from_list[i]->op = T_OP_EQ;
				from_list[i] = NULL;
				append_tail = &(*append_tail)->next;
			}
		}
	}

	/*
	 *	Delete attributes in the "from" list.
	 */
	for (i = 0; i < from_count; i++) {
		if (!from_list[i]) continue;

		fr_pair_list_free(&from_list[i]);
	}
	talloc_free(from_list);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Re-chain the "to" list.
	 */
	fr_pair_list_free(to);
	last = to;

	for (i = 0; i < tailto; i++) {
		if (!to_list[i]) continue;

		vp = to_list[i];
		RDEBUG4("::: to[%d] = %s", i, vp->da->name);

		/*
		 *	Mash the operator to a simple '='.  The
		 *	operators in the "to" list aren't used for
		 *	anything.  BUT they're used in the "detail"
		 *	file and debug output, where we don't want to
		 *	see the operators.
		 */
		vp->op = T_OP_EQ;

		*last = vp;
		last = &(*last)->next;
	}

	/*
	 *	And finally add in the attributes we're appending to
	 *	the tail of the "to" list.
	 */
	*last = append;

	fr_assert(request->packet != NULL);

	talloc_free(to_list);
	talloc_free(edited);
}
