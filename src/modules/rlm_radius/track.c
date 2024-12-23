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
 * @copyright 2017 Network RADIUS SAS
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/debug.h>

#include "track.h"

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
#ifndef NDEBUG
		tt->id[i].file = __FILE__;
		tt->id[i].line = __LINE__;
#endif
		fr_dlist_insert_tail(&tt->free_list, &tt->id[i]);
	}

	return tt;
}


/** Ensures the entry is released when the ctx passed to radius_track_entry_reserve is freed
 *
 * @param[in] te_p		Entry to release.
 * @return 0
 */
static int _radius_track_entry_release_on_free(radius_track_entry_t ***te_p)
{
	radius_track_entry_release(*te_p);

	return 0;
}

/** Allocate a tracking entry.
 *
 * @param[in] file		The allocation was made in.
 * @param[in] line		The allocation was made on.
 * @param[out] te_out		Where the tracking entry should be written.
 *				If ctx is not-null, then this pointer must
 *				remain valid for the lifetime of the ctx.
 * @param[in] ctx		If not-null, the tracking entry release will
 *				be bound to the lifetime of the talloc chunk.
 * @param[in] tt		The radius_track_t tracking table.
 * @param[in] request		The request which will send the proxied packet.
 * @param[in] code		Of the outbound request.
 * @param[in] uctx		The context to associate with the request
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
#ifndef NDEBUG
int _radius_track_entry_reserve(char const *file, int line,
#else
int radius_track_entry_reserve(
#endif
				radius_track_entry_t **te_out,
				TALLOC_CTX *ctx, radius_track_t *tt, request_t *request, uint8_t code, void *uctx)
{
	radius_track_entry_t *te;

	if (!fr_cond_assert_msg(!*te_out, "Expected tracking entry to be NULL")) return -1;

retry:
	te = fr_dlist_head(&tt->free_list);
	if (te) {
		fr_assert(te->request == NULL);

		/*
		 *	Mark it as used, and remove it from the free list.
		 */
		fr_dlist_remove(&tt->free_list, te);

		/*
		 *	We've transitioned from "use it", to "oops,
		 *	don't use it".  Ensure that we only return IDs
		 *	which are in the static array.
		 */
		if (te != &tt->id[te->id]) {
			talloc_free(te);
			goto retry;
		}

		goto done;
	}

	/*
	 *	There are no free entries, and we can't use the
	 *	Request Authenticator.  Oh well...
	 */
	fr_strerror_const("No free entries");
	return -1;

done:
	te->tt = tt;
	te->request = request;
	te->uctx = uctx;
	te->code = code;
#ifndef NDEBUG
	te->operation = te->tt->operation++;
	te->file = file;
	te->line = line;
#endif
	if (ctx) {
		te->binding = talloc_zero(ctx, radius_track_entry_t **);
		talloc_set_destructor(te->binding, _radius_track_entry_release_on_free);
		*(te->binding) = te_out;
	}

	/*
	 *	te->id is already allocated
	 */
	tt->num_requests++;

	*te_out = te;

	return 0;
}

/** Release a tracking entry
 *
 * @param[in] file			Allocation was released in.
 * @param[in] line			Allocation was released on.
 * @param[in,out] te_to_free		The #radius_track_entry_t allocated via #radius_track_entry_reserve.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
#ifndef NDEBUG
int _radius_track_entry_release(char const *file, int line,
#else
int radius_track_entry_release(
#endif
				radius_track_entry_t **te_to_free)
{
	radius_track_entry_t	*te = *te_to_free;
	radius_track_t		*tt;

	if (!te) return 0;

	tt = talloc_get_type_abort(te->tt, radius_track_t);	/* Make sure table is still valid */

	if (te->binding) {
		talloc_set_destructor(te->binding, NULL);	/* Disarm the destructor */
		talloc_free(te->binding);
	}

#ifndef NDEBUG
	te->operation = te->tt->operation++;
	te->file = file;
	te->line = line;
#endif

	te->request = NULL;

	fr_assert(tt->num_requests > 0);
	tt->num_requests--;

	/*
	 *	We're freeing a static ID, just go do that...
	 */
	fr_assert(te == &tt->id[te->id]);

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
#ifndef NDEBUG
	radius_track_t *tt = te->tt;
#endif

	fr_assert(tt);

	memcpy(te->vector, vector, sizeof(te->vector));

	/*
	 *	If we're not using the Request Authenticator, the
	 *	tracking entry must be in the static array.
	 *
	 *	@todo - gracefully handle fallback if the server screws up.
	 */
	fr_assert(te == &tt->id[te->id]);
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
	radius_track_entry_t *te;

	(void) talloc_get_type_abort(tt, radius_track_t);

	/*
	 *	Just use the static array.
	 */
	te = &tt->id[packet_id];

	/*
	 *	Not in use, die.
	 */
	if (!te->request) return NULL;

	if (!vector) return te;

	/*
	 *	Protocol-Error and Original-Packet-Vector <sigh>
	 *
	 *	This should arguably have been Original-Packet-Code, but we are stupid.
	 *
	 *	@todo - Allow for multiple ID arrays, one for each packet code.  Or, just switch to using
	 *	src/protocols/radius/id.[ch].
	 */
	if (memcmp(te->vector, vector, sizeof(te->vector)) != 0) return NULL;

	/*
	 *	Ignore the Request Authenticator, as the
	 *	caller doesn't have it.
	 */
	return te;
}


#ifndef NDEBUG
/** Print out the state of every tracking entry
 *
 * @param[in] log	destination.
 * @param[in] log_type	Type of log message.
 * @param[in] file	this function was called in.
 * @param[in] line	this function was called on.
 * @param[in] tt	Table to print.
 * @param[in] extra	Callback function for printing extra detail.
 */
void radius_track_state_log(fr_log_t const *log, fr_log_type_t log_type, char const *file, int line,
			    radius_track_t *tt, radius_track_log_extra_t extra)
{
	size_t i;

	for (i = 0; i < NUM_ELEMENTS(tt->id); i++) {
		radius_track_entry_t	*entry;

		entry = &tt->id[i];

		if (entry->request) {
			fr_log(log, log_type, file, line,
			       "[%zu] %"PRIu64 " - Allocated at %s:%u to request %p (%s), uctx %p",
			       i, entry->operation,
			       entry->file, entry->line, entry->request, entry->request->name, entry->uctx);
		} else {
			fr_log(log, log_type, file, line,
			       "[%zu] %"PRIu64 " - Freed at %s:%u",
			       i, entry->operation, entry->file, entry->line);
		}

		if (extra) extra(log, log_type, file, line, entry);
	}
}
#endif
