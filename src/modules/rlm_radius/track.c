/*
 *   This program is free software; you can redistribute it and/or modify
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
#include <freeradius-devel/io/application.h>

#include "track.h"

/*
 *	Order by epoch first, then by token.
 */
static fr_cmp_ret_t _token_cmp(void const *one, void const *two)
{
	fr_cmp_ret_t ret;
	radius_track_entry_t const *a = one, *b = two;

	ret = CMP(a->epoch, b->epoch);
	if (ret != 0) return ret;

	return CMP(a->token, b->token);
}

/** Create an radius_track_t
 *
 * @param ctx the talloc ctx
 * @return
 *	- NULL on error
 *	- radius_track_t on success
 */
radius_track_t *radius_track_alloc(TALLOC_CTX *ctx, bool radius_1_1)
{
	int i;
	radius_track_t *tt;

	MEM(tt = talloc_zero(ctx, radius_track_t));

	fr_dlist_init(&tt->free_list, radius_track_entry_t, entry);

	if (radius_1_1) {
		(void) fr_rb_inline_init(&tt->tree, radius_track_entry_t, node, _token_cmp, NULL);
		tt->radius_1_1 = true;
		tt->current = fr_rand();

	} else {
		for (i = 0; i < 256; i++) {
			tt->id[i].id = i;
#ifndef NDEBUG
			tt->id[i].file = __FILE__;
			tt->id[i].line = __LINE__;
#endif
			fr_dlist_insert_tail(&tt->free_list, &tt->id[i]);
		}
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
	/*
	 *	This function is a talloc destructor for the binding.  We therefore zero out the te->binding
	 *	in the entry before calling radius_track_entry_release().  Otherwise it will try to
	 *	talloc_free() the binding, even though we're already in the process of freeing it.
	 */
	(**te_p)->binding = NULL;

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
	if (!te) {
		if (!tt->radius_1_1) {
			fr_strerror_const("No free entries");
			return -1;
		}

		/*
		 *	Just allocate a new one.
		 */
		MEM(te = talloc_zero(tt, radius_track_entry_t));
#ifndef NDEBUG
		te->file = __FILE__;
		te->line = __LINE__;
#endif
	} else {
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
		if (!tt->radius_1_1 && (te != &tt->id[te->id])) {
			talloc_free(te);
			goto retry;
		}
	}

	/*
	 *	RADIUS/1.1 doesn't store the entries in the id[] array.
	 */
	if (tt->radius_1_1) {
		te->token = tt->current++;
		te->epoch = tt->epoch;

		if (!tt->current) tt->epoch++;

		/*
		 *	Insert it into the tracking tree.
		 */
		if (!fr_cond_assert(fr_rb_insert(&tt->tree, te) == 0)) {
			te->request = NULL;
			fr_dlist_insert_tail(&tt->free_list, te);
			return -1;
		}
	}

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
		MEM(te->binding = talloc_zero(ctx, radius_track_entry_t **));
		talloc_set_destructor(te->binding, _radius_track_entry_release_on_free);
		*(te->binding) = te_out;
	}

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
		TALLOC_FREE(te->binding);
	}

#ifndef NDEBUG
	te->operation = te->tt->operation++;
	te->file = file;
	te->line = line;
#endif

	te->request = NULL;
	*te_to_free = NULL;

	fr_assert(tt->num_requests > 0);
	tt->num_requests--;

	/*
	 *	For RADIUS/1.1, remove Token nodes from the tree.
	 */
	if (tt->radius_1_1) {
		(void) fr_rb_remove_by_inline_node(&tt->tree, &te->node);

		if (fr_dlist_num_elements(&tt->free_list) > 1000) {
			talloc_free(te);
			return 0;
		}
	} else {
		fr_assert(te == &tt->id[te->id]);
	}

	fr_dlist_insert_tail(&tt->free_list, te);

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

	fr_assert(tt);

	if (tt->radius_1_1) return 0; /* don't over-write the vector! */

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

/** Find a tracking entry from a Token
 *
 *  The tree decides whether a Token matches an entry.  Before the lookup, a check of the Token against
 *  the range from the oldest to the newest outstanding entry discards most Tokens which do not match.
 *  The subtraction wraps when the counter wraps, so the check stays correct.
 *
 * @param tt		The radius_track_t tracking table, in Token mode.
 * @param token		The Token from the RADIUS/1.1 header.
 * @return
 *	- NULL on "not found"
 *	- radius_track_entry_t on success
 */
static radius_track_entry_t *radius_track_entry_find_token(radius_track_t *tt, uint32_t token)
{
	radius_track_entry_t	*te;

	(void) talloc_get_type_abort(tt, radius_track_t);

	fr_assert(tt->radius_1_1);

	/*
	 *	Nearly all of the time, the packet is in the current epoch.
	 */
	if (fr_rb_find((void **) &te, &tt->tree,
		       &(radius_track_entry_t)  { .epoch = tt->epoch, .token = token }) < 0) {
	fail:
		fr_strerror_printf("Token %u", token);
		return NULL;
	}
	if (te) return te;

	if (!tt->epoch) return NULL; /* still in the initial epoch, we can't do much */

	/*
	 *	Find the entry from the previous epoch, in the rare
	 *	case that the epoch rolls over.
	 */
	if (fr_rb_find((void **) &te, &tt->tree,
		       &(radius_track_entry_t)  { .epoch = tt->epoch - 1, .token = token }) < 0) goto fail;
	if (!te) goto fail;

	return te;
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

	if (tt->radius_1_1) return radius_track_entry_find_token(tt, fr_nbo_to_uint32(vector));

	/*
	 *	Just use the static array.
	 */
	te = &tt->id[packet_id];

	/*
	 *	Not in use, die.
	 */
	if (!te->request) {
		fr_strerror_printf("ID %u", packet_id);
		return NULL;
	}

	/*
	 *	Don't match on the Response vector, it's only used for RADIUS/1.1
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
			       "[%zu] %"PRIu64 " - Allocated at %s:%d to request %p (%s), uctx %p",
			       i, entry->operation,
			       entry->file, entry->line, entry->request, entry->request->name, entry->uctx);
		} else {
			fr_log(log, log_type, file, line,
			       "[%zu] %"PRIu64 " - Freed at %s:%d",
			       i, entry->operation, entry->file, entry->line);
		}

		if (extra) extra(log, log_type, file, line, entry);
	}
}
#endif
