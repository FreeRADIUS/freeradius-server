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
void radius_pairmove(request_t *request, fr_pair_list_t *to, fr_pair_list_t *from, bool do_xlat)
{
	int		i, j, count, to_count, tailto;
	fr_pair_t	*from_vp, *next_from, *to_vp, *next_to = NULL;
	fr_pair_list_t	append;
	bool		*edited = NULL;
	bool		*deleted = NULL;

	/*
	 *	Set up arrays for editing, to remove some of the
	 *	O(N^2) dependencies.  These record which elements in
	 *	the "to" list have been either edited or marked for
	 *	deletion.
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

	fr_pair_list_init(&append);

	to_count = fr_dlist_num_elements(&to->head);
	tailto = to_count;
	edited = talloc_zero_array(request, bool, to_count);
	deleted = talloc_zero_array(request, bool, to_count);

	count = to_count + fr_dlist_num_elements(&from->head);

	RDEBUG4("::: FROM %ld TO %d MAX %d", fr_dlist_num_elements(&from->head), to_count, count);

	/*
	 *	Now that we have the lists initialized, start working
	 *	over them.
	 */
	for (i = 0, from_vp = fr_pair_list_head(from); from_vp; i++, from_vp = next_from) {
		int found;
		/* Find the next from pair before any manipulation happens */
		next_from = fr_pair_list_next(from, from_vp);

		RDEBUG4("::: Examining %s", from_vp->da->name);

		if (do_xlat) xlat_eval_pair(request, from_vp);

		/*
		 *	Attribute should be appended, OR the "to" list
		 *	is empty, and we're supposed to replace or
		 *	"add if not existing".
		 */
		if (from_vp->op == T_OP_ADD) goto do_append;

		found = false;
		j = 0;
		for (to_vp = fr_pair_list_head(to); to_vp; to_vp = next_to, j++) {
			next_to = fr_pair_list_next(to, to_vp);
			if (edited[j] || deleted[j] || !from_vp) continue;

			/*
			 *	Attributes aren't the same, skip them.
			 */
			if (from_vp->da != to_vp->da) {
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
			if (from_vp->op == T_OP_SET) {
				fr_pair_t *vp;
				RDEBUG4("::: OVERWRITING %s FROM %d TO %d",
				       to_vp->da->name, i, j);
				vp = fr_dlist_replace(&to->head, to_vp, from_vp);
				talloc_free(vp);
				edited[j] = true;
				break;
			}

			/*
			 *	Add the attribute only if it does not
			 *	exist... but it exists, so we stop
			 *	looking.
			 */
			if (from_vp->op == T_OP_EQ) {
				found = true;
				break;
			}

			/*
			 *	Delete every attribute, independent
			 *	of its value.
			 */
			if (from_vp->op == T_OP_CMP_FALSE) {
				goto delete;
			}

			/*
			 *	Delete all matching attributes from
			 *	"to"
			 */
			if ((from_vp->op == T_OP_SUB) ||
			    (from_vp->op == T_OP_CMP_EQ) ||
			    (from_vp->op == T_OP_LE) ||
			    (from_vp->op == T_OP_GE)) {
				int rcode;
				int old_op = from_vp->op;
				printf("Should get in here\n");
				/*
				 *	Check for equality.
				 */
				from_vp->op = T_OP_CMP_EQ;

				/*
				 *	If equal, delete the one in
				 *	the "to" list.
				 */
				rcode = paircmp_pairs(NULL, from_vp,
							   to_vp);
				/*
				 *	We may want to do more
				 *	subtractions, so we re-set the
				 *	operator back to it's original
				 *	value.
				 */
				from_vp->op = old_op;

				switch (old_op) {
				case T_OP_CMP_EQ:
					if (rcode != 0) goto delete;
					break;

				case T_OP_SUB:
					if (rcode == 0) {
					delete:
						RDEBUG4("::: DELETING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
						/*
						 *	Mark that this will be deleted
						 */
						deleted[j] = true;
					}
					break;

					/*
					 *	Enforce <=.  If it's
					 *	>, replace it.
					 */
				case T_OP_LE:
					if (rcode > 0) {
						fr_pair_t *vp;
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
						vp = fr_dlist_replace(&to->head, to_vp, from_vp);
						talloc_free(vp);
						edited[j] = true;
					}
					break;

				case T_OP_GE:
					if (rcode < 0) {
						fr_pair_t *vp;
						RDEBUG4("::: REPLACING %s FROM %d TO %d",
						       from_vp->da->name, i, j);
						vp = fr_dlist_replace(&to->head, to_vp, from_vp);
						talloc_free(vp);
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
		if (!found && from_vp) {
			if ((from_vp->op == T_OP_EQ) ||
			    (from_vp->op == T_OP_LE) ||
			    (from_vp->op == T_OP_GE) ||
			    (from_vp->op == T_OP_SET)) {
			do_append:
				RDEBUG4("::: APPENDING %s FROM %d TO %d",
				       from_vp->da->name, i, tailto++);
				fr_pair_remove(from, from_vp);
				fr_pair_add(&append, from_vp);
				from_vp->op = T_OP_EQ;
			}
		}
	}

	/*
	 *	Delete remaining attributes in the "from" list.
	 */
	fr_pair_list_free(from);

	RDEBUG4("::: TO in %d out %d", to_count, tailto);

	/*
	 *	Delete any "to" items marked for deletion
	 */

	i = 0;
	for (to_vp = fr_pair_list_head(to); to_vp; to_vp = next_to, i++) {
		next_to = fr_pair_list_next(to, to_vp);

		if (deleted[i]) {
			fr_pair_remove(to, to_vp);
			continue;
		}

		RDEBUG4("::: to[%d] = %s", i, to_vp->da->name);

		/*
		 *	Mash the operator to a simple '='.  The
		 *	operators in the "to" list aren't used for
		 *	anything.  BUT they're used in the "detail"
		 *	file and debug output, where we don't want to
		 *	see the operators.
		 */
		to_vp->op = T_OP_EQ;
	}

	/*
	 *	And finally add in the attributes we're appending to
	 *	the tail of the "to" list.
	 */
	fr_tmp_pair_list_move(to, &append);

	fr_assert(request->packet != NULL);

	talloc_free(edited);
	talloc_free(deleted);
}
