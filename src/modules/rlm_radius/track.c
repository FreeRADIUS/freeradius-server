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
 * @copyright 2017  Network RADIUS SARL
 */
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rbtree.h>
#include <freeradius-devel/io/application.h>
#include <freeradius-devel/rad_assert.h>

#include "track.h"
#include "rlm_radius.h"

/** Free an rlm_radius_id_t
 *
 */
static int rr_track_free(rlm_radius_id_t *id)
{
	int i;

	for (i = 0; i < 256; i++) {
		if (!id->id[i].request) continue;

		/*
		 *	The timers are parented from the request, so
		 *	we have to manually free them here.
		 */
		talloc_const_free(id->id[i].ev);
	}

	return 0;
}


/** Create an rlm_radius_id_t
 *
 * @param ctx the talloc ctx
 * @return
 *	- NULL on error
 *	- rlm_radius_id_t on success
 */
rlm_radius_id_t *rr_track_create(TALLOC_CTX *ctx)
{
	int i;
	rlm_radius_id_t *id;

	id = talloc_zero(ctx, rlm_radius_id_t);
	if (!id) return NULL;

	FR_DLIST_INIT(id->free_list);

	for (i = 0; i < 256; i++) {
		id->id[i].id = i;
		fr_dlist_insert_tail(&id->free_list, &id->id[i].entry);
		id->num_free++;
	}

	talloc_set_destructor(id, rr_track_free);

	id->next_id = fr_rand() & 0xff;

	return id;
}


/** Compare two rlm_radius_request_t
 *
 */
static int rr_cmp(void const *one, void const *two)
{
	rlm_radius_request_t const *a = one;
	rlm_radius_request_t const *b = two;

	return memcmp(a->vector, b->vector, sizeof(a->vector));
}

/** Allocate a tracking entry.
 *
 * @param[in] id		The rlm_radius_id_t tracking table.
 * @param[in] request		The request which will send the proxied packet.
 * @param[in] code		Of the outbound request.
 * @param[in] link		the structure linking REQUEST to rlm_radius thread instance
 * @return
 *	- NULL on error
 *	- rlm_radius_request_t on success
 */
rlm_radius_request_t *rr_track_alloc(rlm_radius_id_t *id, REQUEST *request, int code, rlm_radius_link_t *link)
{
	fr_dlist_t *entry;
	rlm_radius_request_t *rr;

retry:
	entry = FR_DLIST_FIRST(id->free_list);
	if (entry) {
		rad_assert(id->num_free > 0);

		rr = fr_ptr_to_type(rlm_radius_request_t, entry, entry);

		rad_assert(rr->request == NULL);

		/*
		 *	Mark it as used, and remove it from the free list.
		 */
		fr_dlist_remove(&rr->entry);
		id->num_free--;

		/*
		 *	We've transitioned from "use it", to "oops,
		 *	don't use it".  Ensure that we only return IDs
		 *	which are in the static array.
		 */
		if (!id->use_authenticator &&
		    (rr != &id->id[rr->id])) {
			talloc_free(rr);
			goto retry;
		}

		goto done;
	}

	/*
	 *	There are no free entries, and we can't use the
	 *	Request Authenticator.  Oh well...
	 */
	if (!id->use_authenticator) return NULL;

	/*
	 *	Get a new ID.  It's value doesn't matter at this
	 *	point.
	 */
	id->next_id++;
	id->next_id &= 0xff;

	/*
	 *	If needed, allocate a subtree.
	 */
	if (!id->subtree[id->next_id]) {
		id->subtree[id->next_id] = rbtree_create(id, rr_cmp, NULL, RBTREE_FLAG_NONE);
		if (!id->subtree[id->next_id]) return NULL;
	}

	/*
	 *	Allocate a new one, and insert it into the appropriate subtree.
	 */
	rr = talloc_zero(id, rlm_radius_request_t);
	FR_DLIST_INIT(rr->entry);
	rr->id = id->next_id;

done:
	rr->link = link;
	rr->code = code;
	rr->request = request;
	id->num_requests++;
	return rr;
}

/** Update a tracking entry with the authentication vector
 *
 * @param id		The rlm_radius_id_t tracking table
 * @param rr		The rlm_radius_request_t, via rr_track_alloc()
 * @param vector	The authentication vector for the packet we're sending
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int rr_track_update(rlm_radius_id_t *id, rlm_radius_request_t *rr, uint8_t *vector)
{
	memcpy(rr->vector, vector, sizeof(rr->vector));

	/*
	 *	If we're not using the Request Authenticator, the
	 *	tracking entry must be in the static array.
	 *
	 *	@todo - gracefully handle fallback if the server screws up.
	 */
	if (!id->use_authenticator) {
		rad_assert(rr == &id->id[rr->id]);
		return 0;
	}

	/*
	 *	Insert it into the tree of authenticators
	 *
	 *	We do this even if it was allocated from the static
	 *	array.  That way if the server responds with
	 *	Original-Request-Authenticator, we can easily find it.
	 */
	if (!rbtree_insert(id->subtree[rr->id], rr)) {
		return -1;
	}

	return 0;
}


/** Delete a tracking entry
 *
 * @param id		The rlm_radius_id_t tracking table
 * @param rr		The rlm_radius_request_t, via rr_track_alloc()
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int rr_track_delete(rlm_radius_id_t *id, rlm_radius_request_t *rr)
{
	(void) talloc_get_type_abort(id, rlm_radius_id_t);

	rr->request = NULL;
	if (rr->ev) talloc_const_free(rr->ev);

	rad_assert(id->num_requests > 0);
	id->num_requests--;

	/*
	 *	We're freeing a static ID, just go do that...
	 */
	if (rr == &id->id[rr->id]) {
		/*
		 *	This entry MAY be in a subtree.  If so, delete
		 *	it.
		 */
		if (id->subtree[rr->id]) (void) rbtree_deletebydata(id->subtree[rr->id], rr);

		goto done;
	}

	/*
	 *	At this point, it MUST be talloc'd.
	 */
	(void) talloc_get_type_abort(rr, rlm_radius_request_t);

	/*
	 *	Delete it from the tracking subtree.
	 */
	rad_assert(id->subtree[rr->id] != NULL);
	(void) rbtree_deletebydata(id->subtree[rr->id], rr);

	/*
	 *	Try to free memory if the system gets idle.  If the
	 *	system is busy, we will try to keep entries in the
	 *	free list.  If the system becomes completely idle, we
	 *	will clear the free list.
	 */
	if (id->num_free > id->num_requests) {
		talloc_free(rr);
		return 0;
	}

	/*
	 *	Otherwise put it back on the free list.
	 */
done:
	fr_dlist_insert_tail(&id->free_list, &rr->entry);
	id->num_free++;

	return 0;
}


/** Find a tracking entry from a request authenticator
 *
 * @param id		The rlm_radius_id_t tracking table
 * @param packet_id    	The ID from the RADIUS header
 * @param vector	The Request Authenticator (may be NULL)
 * @return
 *	- NULL on "not found"
 *	- rlm_radius_request_t on success
 */
rlm_radius_request_t *rr_track_find(rlm_radius_id_t *id, int packet_id, uint8_t *vector)
{
	rlm_radius_request_t my_rr, *rr;

	(void) talloc_get_type_abort(id, rlm_radius_id_t);

	/*
	 *	Screw you guys, I'm going home!
	 */
	if (packet_id > 255) return NULL;

	/*
	 *	Just use the static array.
	 */
	if (!id->use_authenticator || !vector) {
		rr = &id->id[packet_id];

		/*
		 *	Not in use, die.
		 */
		if (!rr->request) return NULL;

		/*
		 *	Ignore the Request Authenticator, as the
		 *	caller doesn't have it.
		 */
		return rr;
	}

	/*
	 *	The entry MAY be in the subtree!
	 */
	memcpy(&my_rr.vector, vector, sizeof(my_rr.vector));

	rr = rbtree_finddata(id->subtree[packet_id], &my_rr);

	/*
	 *	Not found, the packet MAY have been allocated in the
	 *	old-style method prior to negotiation of
	 *	Original-Request-Identifier.
	 */
	if (!rr) {
		rr = &id->id[packet_id];

		/*
		 *	Not in use, die.
		 */
		if (!rr->request) return NULL;

		// @todo - add a "generation" count for packets, so we can skip this after all outstanding packets
		// are using the new method.  Hmm... probably just a timer "last sent packet with old-style"
		// and then compare it to rr->start

		/*
		 *	We have the vector, so we need to check it.
		 */
		if (memcmp(rr->vector, vector, sizeof(rr->vector)) != 0) {
			return NULL;
		}

		return rr;
	}

	(void) talloc_get_type_abort(rr, rlm_radius_request_t);
	rad_assert(rr->request != NULL);

	return rr;
}


/** Use Request Authenticator (or not) as an Identifier
 *
 * @param id		The rlm_radius_id_t tracking table
 * @param flag		Whether or not to use it.
 */
void rr_track_use_authenticator(rlm_radius_id_t *id, bool flag)
{
	(void) talloc_get_type_abort(id, rlm_radius_id_t);

	id->use_authenticator = flag;
}

int rr_track_retry(UNUSED rlm_radius_id_t *id, rlm_radius_request_t *rr, fr_event_list_t *el,
		   fr_event_callback_t callback, void *uctx, rlm_radius_retry_t *retry,
		   struct timeval *now)
{
	uint32_t delay, frac;
	struct timeval next;

	/*
	 *	Get when we SHOULD have woken up, which might not be
	 *	the same as 'now'.
	 */
	next = rr->start;
	next.tv_usec += rr->rt;

	/*
	 *	Increment retransmission counter
	 */
	rr->count++;

	/*
	 *	We retried too many times.  Fail.
	 */
	if (retry->mrc && (rr->count > retry->mrc)) {
		return 0;
	}

	/*
	 *	Cap delay at MRD
	 */
	if (retry->mrd) {
		struct timeval end;

		end = rr->start;
		end.tv_sec += retry->mrd;

		if (timercmp(now, &end, >=)) {
			return 0;
		}
	}

	/*
	 *	RFC 5080 Section 2.2.1
	 *
	 *	RT = 2*RTprev + RAND*RTprev
	 *	   = 1.9 * RTprev + rand(0,.2) * RTprev
	 *	   = 1.9 * RTprev + rand(0,1) * (RTprev / 5)
	 */
	delay = fr_rand();
	delay ^= (delay >> 16);
	delay &= 0xffff;
	frac = rr->rt / 5;
	delay = ((frac >> 16) * delay) + (((frac & 0xffff) * delay) >> 16);

	delay += (2 * rr->rt) - (rr->rt / 10);

	/*
	 *	Cap delay at MRT
	 */
	if (retry->mrt && (delay > (retry->mrt * USEC))) {
		int mrt_usec = retry->mrt * USEC;

		/*
		 *	delay = MRT + RAND * MRT
		 *	      = 0.9 MRT + rand(0,.2)  * MRT
		 */
		delay = fr_rand();
		delay ^= (delay >> 15);
		delay &= 0x1ffff;
		delay = ((mrt_usec >> 16) * delay) + (((mrt_usec & 0xffff) * delay) >> 16);
		delay += mrt_usec - (mrt_usec / 10);
	}

	/*
	 *	And finally set the retransmission timer.
	 */
	rr->rt = delay;

	/*
	 *	Get the next delay time.
	 */
	next.tv_usec += rr->rt;
	next.tv_sec += (next.tv_usec / USEC);
	next.tv_usec %= USEC;

	if (fr_event_timer_insert(rr->request, el, &rr->ev, &next, callback, uctx) < 0) {
		return -1;
	}

	return 0;
}


int rr_track_start(UNUSED rlm_radius_id_t *id, rlm_radius_request_t *rr, fr_event_list_t *el,
		   fr_event_callback_t callback, void *uctx, rlm_radius_retry_t *retry)
{
	struct timeval next;

	rr->count = 1;
	rr->rt = retry->irt * USEC; /* rt is in usec */

	next = rr->start;
	next.tv_usec += rr->rt;
	next.tv_sec += (next.tv_usec / USEC);
	next.tv_usec %= USEC;

	if (fr_event_timer_insert(rr->request, el, &rr->ev, &next, callback, uctx) < 0) {
		return -1;
	}

	return 0;
}
