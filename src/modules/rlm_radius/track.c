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
 * @file rlm_radius/track.c
 * @brief Tracking RADUS client packets
 *
 * @copyright 2017 Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/rbtree.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/server/rad_assert.h>

#include "track.h"
#include "rlm_radius.h"

/** Create an radius_track_t
 *
 * @param ctx the talloc ctx
 * @return
 *	- NULL on error
 *	- radius_track_t on success
 */
radius_track_t *radius_track_alloc(TALLOC_CTX *ctx)
{
	int i;
	radius_track_t *tt;

	MEM(tt = talloc_zero(ctx, radius_track_t));

	fr_dlist_init(&tt->free_list, radius_track_entry_t, entry);

	for (i = 0; i < 256; i++) {
		tt->id[i].id = i;
		fr_dlist_insert_tail(&tt->free_list, &tt->id[i]);
	}

	tt->next_id = fr_rand() & 0xff;

	return tt;
}


/** Compare two radius_track_entry_t
 *
 */
static int te_cmp(void const *one, void const *two)
{
	radius_track_entry_t const *a = one;
	radius_track_entry_t const *b = two;

	return memcmp(a->vector, b->vector, sizeof(a->vector));
}

#ifndef NDEBUG
/** Allocate a tracking entry.
 *
 * @param[in] tt		The radius_track_t tracking table.
 * @param[in] request		The request which will send the proxied packet.
 * @param[in] code		Of the outbound request.
 * @param[in] rctx		The context to associate with the request
 * @param[in] file		The allocation was made in.
 * @param[in] line		The allocation was made on.
 * @return
 *	- NULL on error
 *	- radius_track_entry_t on success
 */
radius_track_entry_t *_radius_track_entry_reserve(radius_track_t *tt, REQUEST *request, uint8_t code, void *rctx,
						  char const *file, int line)
#else
radius_track_entry_t *radius_track_entry_reserve(radius_track_t *tt, REQUEST *request, uint8_t code, void *rctx)
#endif
{
	radius_track_entry_t *te;

retry:
	te = fr_dlist_head(&tt->free_list);
	if (te) {
		rad_assert(te->request == NULL);

		/*
		 *	Mark it as used, and remove it from the free list.
		 */
		fr_dlist_remove(&tt->free_list, te);

		/*
		 *	We've transitioned from "use it", to "oops,
		 *	don't use it".  Ensure that we only return IDs
		 *	which are in the static array.
		 */
		if (!tt->use_authenticator &&
		    (te != &tt->id[te->id])) {
			talloc_free(te);
			goto retry;
		}

		goto done;
	}

	/*
	 *	There are no free entries, and we can't use the
	 *	Request Authenticator.  Oh well...
	 */
	if (!tt->use_authenticator) {
		fr_strerror_printf("No free entries");
		return NULL;
	}

	/*
	 *	Get a new ID.  It's value doesn't matter at this
	 *	point.
	 */
	tt->next_id++;
	tt->next_id &= 0xff;

	/*
	 *	If needed, allocate a subtree.
	 */
	if (!tt->subtree[tt->next_id]) {
		MEM(tt->subtree[tt->next_id] = rbtree_talloc_create(tt, te_cmp, radius_track_entry_t,
								    NULL, RBTREE_FLAG_NONE));
	}

	/*
	 *	Allocate a new one, and insert it into the appropriate subtree.
	 */
	te = talloc_zero(tt, radius_track_entry_t);
	te->id = tt->next_id;

done:


	te->tt = tt;
	te->request = request;
	te->rctx = rctx;
	te->code = code;
#ifndef NDEBUG
	te->operation = te->tt->operation++;
	te->file = file;
	te->line = line;
#endif
	/*
	 *	te->id is already allocated
	 */
	tt->num_requests++;
	return te;
}

#ifndef NDEBUG
/** Release a tracking entry
 *
 * @param[in,out] te_to_free		The #radius_track_entry_t allocated via #radius_track_entry_reserve.
 * @param[in] file			Allocation was released in.
 * @param[in] line			Allocation was released on.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int _radius_track_entry_release(radius_track_entry_t **te_to_free, char const *file, int line)
#else
int radius_track_entry_release(radius_track_entry_t **te_to_free)
#endif
{
	radius_track_entry_t	*te = *te_to_free;
	radius_track_t		*tt = talloc_get_type_abort(te->tt, radius_track_t);	/* Make sure table is still valid */

#ifndef NDEBUG
	te->operation = te->tt->operation++;
	te->file = file;
	te->line = line;
#endif

	te->request = NULL;

	rad_assert(tt->num_requests > 0);
	tt->num_requests--;

	/*
	 *	We're freeing a static ID, just go do that...
	 */
	if (te == &tt->id[te->id]) {
		/*
		 *	This entry MAY be in a subtree.  If so, delete
		 *	it.
		 */
		if (tt->subtree[te->id]) (void) rbtree_deletebydata(tt->subtree[te->id], te);

		goto done;
	}

	/*
	 *	At this point, it MUST be talloc'd.
	 */
	(void) talloc_get_type_abort(te, radius_track_entry_t);

	/*
	 *	Delete it from the tracking subtree.
	 */
	rad_assert(tt->subtree[te->id] != NULL);
	(void) rbtree_deletebydata(tt->subtree[te->id], te);

	/*
	 *	Try to free memory if the system gets idle.  If the
	 *	system is busy, we will try to keep entries in the
	 *	free list.  If the system becomes completely idle, we
	 *	will clear the free list.
	 */
	if (fr_dlist_num_elements(&tt->free_list) > tt->num_requests) {
		talloc_free(te);
		*te_to_free = NULL;
		return 0;
	}

	/*
	 *	Otherwise put it back on the free list.
	 */
done:
	fr_dlist_insert_tail(&tt->free_list, te);

	*te_to_free = NULL;

	return 0;
}

/** Update a tracking entry with the authentication vector
 *
 * @param te		The radius_track_entry_t, via radius_track_entry_reserve()
 * @param vector	The authentication vector for the packet we're sending
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int radius_track_entry_update(radius_track_entry_t *te, uint8_t const *vector)
{
	radius_track_t *tt = te->tt;

	rad_assert(tt);

	/*
	 *	The authentication vector may have changed.
	 */
	if (tt->subtree[te->id]) (void) rbtree_deletebydata(tt->subtree[te->id], te);

	memcpy(te->vector, vector, sizeof(te->vector));

	/*
	 *	If we're not using the Request Authenticator, the
	 *	tracking entry must be in the static array.
	 *
	 *	@todo - gracefully handle fallback if the server screws up.
	 */
	if (!tt->use_authenticator) {
		rad_assert(te == &tt->id[te->id]);
		return 0;
	}

	/*
	 *	Insert it into the tree of authenticators
	 *
	 *	We do this even if it was allocated from the static
	 *	array.  That way if the server responds with
	 *	Original-Request-Authenticator, we can easily find it.
	 */
	if (!rbtree_insert(tt->subtree[te->id], te)) return -1;

	return 0;
}

/** Find a tracking entry from a request authenticator
 *
 * @param tt		The radius_track_t tracking table
 * @param packet_id    	The ID from the RADIUS header
 * @param vector	The Request Authenticator (may be NULL)
 * @return
 *	- NULL on "not found"
 *	- radius_track_entry_t on success
 */
radius_track_entry_t *radius_track_entry_find(radius_track_t *tt, uint8_t packet_id, uint8_t const *vector)
{
	radius_track_entry_t my_te, *te;

	(void) talloc_get_type_abort(tt, radius_track_t);

	/*
	 *	Just use the static array.
	 */
	if (!tt->use_authenticator || !vector) {
		te = &tt->id[packet_id];

		/*
		 *	Not in use, die.
		 */
		if (!te->request) return NULL;

		/*
		 *	Ignore the Request Authenticator, as the
		 *	caller doesn't have it.
		 */
		return te;
	}

	/*
	 *	The entry MAY be in the subtree!
	 */
	memcpy(&my_te.vector, vector, sizeof(my_te.vector));

	te = rbtree_finddata(tt->subtree[packet_id], &my_te);

	/*
	 *	Not found, the packet MAY have been allocated in the
	 *	old-style method prior to negotiation of
	 *	Original-Request-Identifier.
	 */
	if (!te) {
		te = &tt->id[packet_id];

		/*
		 *	Not in use, die.
		 */
		if (!te->request) return NULL;

		// @todo - add a "generation" count for packets, so we can skip this after all outstanding packets
		// are using the new method.  Hmm... probably just a timer "last sent packet with old-style"
		// and then compare it to te->start

		/*
		 *	We have the vector, so we need to check it.
		 */
		if (memcmp(te->vector, vector, sizeof(te->vector)) != 0) {
			return NULL;
		}

		return te;
	}

	(void) talloc_get_type_abort(te, radius_track_entry_t);
	rad_assert(te->request != NULL);

	return te;
}


/** Use Request Authenticator (or not) as an Identifier
 *
 * @param tt		The radius_track_t tracking table
 * @param flag		Whether or not to use it.
 */
void radius_track_use_authenticator(radius_track_t *tt, bool flag)
{
	(void) talloc_get_type_abort(tt, radius_track_t);

	tt->use_authenticator = flag;
}

#ifndef NDEBUG
/** Print out the state of every tracking entry
 *
 */
void radius_track_state_log(radius_track_t *tt)
{
	size_t i;

	for (i = 0; i < NUM_ELEMENTS(tt->id); i++) {
		radius_track_entry_t	*entry;

		entry = &tt->id[i];

		if (entry->request) {
			INFO("[%zu] %"PRIu64 " - Allocated at %s:%u to request %p (%s), rctx %p",
			     i, entry->operation,
			     entry->file, entry->line, entry->request, entry->request->name, entry->rctx);
		} else {
			INFO("[%zu] %"PRIu64 " - Freed at %s:%u",
			     i, entry->operation, entry->file, entry->line);
		}
	}
}
#endif
