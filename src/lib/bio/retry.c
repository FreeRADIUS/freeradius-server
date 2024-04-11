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
 * @file lib/bio/retry.c
 * @brief Binary IO abstractions for retrying packets.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/buf.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/dlist.h>

#define _BIO_RETRY_PRIVATE
#include <freeradius-devel/bio/retry.h>

typedef struct fr_bio_retry_list_s	fr_bio_retry_list_t;
typedef struct fr_bio_retry_s	fr_bio_retry_t;

/*
 *	Define type-safe wrappers for head and entry definitions.
 */
FR_DLIST_TYPES(fr_bio_retry_list)

struct fr_bio_retry_entry_s {
	void		*uctx;
	void		*packet_ctx;
	fr_bio_retry_rewrite_t rewrite;		//!< per-packet rewrite callback

	union {
		fr_rb_node_t	node;		//!< for the timers
		FR_DLIST_ENTRY(fr_bio_retry_list) entry; //!< for the free list
	};

	fr_bio_retry_t	*my;			//!< so we can get to it from the event timer callback
	fr_retry_t	retry;			//!< retry timers and counters

	uint8_t const	*buffer;
	size_t		size;	

	bool		cancelled;		//!< was this item cancelled?
};

FR_DLIST_FUNCS(fr_bio_retry_list, fr_bio_retry_entry_t, entry)

struct fr_bio_retry_s {
	FR_BIO_COMMON;

	fr_event_list_t		*el;
	fr_rb_tree_t		rb;

	fr_retry_config_t	retry_config;

	ssize_t			error;

	fr_event_timer_t const	*ev;

	/*
	 *	The "first" entry is cached here so that we can detect when it changes.  The insert / delete
	 *	code can just do its work without worrying about timers.  And then when the tree manipulation
	 *	is done, call the fr_bio_retry_reset_timer() function to reset (or not) the timer.
	 */
	fr_bio_retry_entry_t	*first;		//!< for timers

	/*
	 *	Cache a partial write when IO is blocked.
	 *
	 *	When the IO is blocked, the timer "ev" event AND the "first" entry MUST be set to NULL.
	 *	There's no point in running retry timers when we can't send packets due to IO blockage.  And
	 *	since there's no timer, there's no need to track which entry is first.
	 */
	fr_bio_retry_entry_t	*partial;	//!< for partial writes

	fr_bio_retry_sent_t	sent;
	fr_bio_retry_rewrite_t	rewrite;
	fr_bio_retry_response_t	response;
	fr_bio_retry_release_t	release;

	fr_bio_buf_t		buffer;

	FR_DLIST_HEAD(fr_bio_retry_list) free;
};

static void fr_bio_retry_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx);
static ssize_t fr_bio_retry_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);
static ssize_t fr_bio_retry_blocked(fr_bio_retry_t *my, fr_bio_retry_entry_t *item, ssize_t rcode);

/** Reset the timer after changing the rb tree.
 *
 */
static int fr_bio_retry_reset_timer(fr_bio_retry_t *my)
{
	fr_bio_retry_entry_t *first;

	/*
	 *	Nothing to do, don't set any timers.
	 */
	first = fr_rb_first(&my->rb);
	if (!first) {
	cancel_timer:
		talloc_const_free(my->ev);
		my->first = NULL;
		return 0;
	}

	/*
	 *	We're partially writing a response.  Don't bother with the timer, and delete any existing
	 *	timer.  It will be reset when the partial entry is placed back into the queue.
	 */
	if (first == my->partial) goto cancel_timer;

	/*
	 *	The timer is already set correctly, we're done.
	 */
	if (first == my->first) return 0;

	/*
	 *	Update the timer.  This should never fail.
	 */
	if (fr_event_timer_at(my, my->el, &my->ev, first->retry.next, fr_bio_retry_timer, my) < 0) return -1;

	my->first = first;
	return 0;
}

/** Release an entry back to the free list.
 *
 */
static void fr_bio_retry_release(fr_bio_retry_t *my, fr_bio_retry_entry_t *item, fr_bio_retry_release_reason_t reason)
{
	/*
	 *	Tell the caller that we've released it before doing anything else.  That way we can safely
	 *	modify anything we want.
	 */
	my->release((fr_bio_t *) my, item, reason);

	/*
	 *	We've partially written this item.  Don't bother changing it's position in any of the lists,
	 *	as it's in progress.
	 */
	if (my->partial == item) {
		item->cancelled = true;
		return;
	}

	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

	/*
	 *	We're deleting the timer entry.  Go reset the timer.
	 */
	if (my->first == item) {
		my->first = NULL;
		(void) fr_bio_retry_reset_timer(my);
	}

#ifndef NDEBUG
	item->buffer = NULL;
#endif
	item->uctx = NULL;
	item->packet_ctx = NULL;

	fr_assert(my->first != item);
	fr_bio_retry_list_insert_head(&my->free, item);
}

/** Write one item.
 *
 * @return
 *	- <0 on error
 *	- 0 for "can't write any more"
 *	- 1 for "wrote a packet"
 */
static int fr_bio_retry_write_item(fr_bio_retry_t *my, fr_bio_retry_entry_t *item, fr_time_t now)
{
	ssize_t rcode;
	fr_retry_state_t state;

	fr_assert(!my->partial);

	/*
	 *	Are we there yet?
	 *
	 *	Release it, indicating whether or not we successfully got a reply.
	 */
	state = fr_retry_next(&item->retry, now);
	if (state != FR_RETRY_CONTINUE) {
		fr_bio_retry_release(my, item, (fr_bio_retry_release_reason_t) (item->retry.replies > 0));
		return 1;
	}

	/*
	 *	Write out the packet.  On failure release this item.
	 *
	 *	If there's an error, we hope that the next "real" write will find the error, and do any
	 *	necessary cleanups.  Note that we can't call bio shutdown here, as the bio is controlled by the
	 *	application, and not by us.
	 */
	if (item->rewrite) {
		rcode = item->rewrite(&my->bio, item, item->buffer, item->size);
	} else {
		rcode = my->rewrite(&my->bio, item, item->buffer, item->size);
	}
	if (rcode < 0) {
		if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return 0;

		fr_bio_retry_release(my, item, FR_BIO_RETRY_WRITE_ERROR);
		return rcode;
	}

	/*
	 *	We didn't write the whole packet, we're blocked.
	 */
	if ((size_t) rcode < item->size) {
		if (fr_bio_retry_blocked(my, item, rcode) < 0) return fr_bio_error(GENERIC); /* oom */

		return 0;
	}

	/*
	 *	We wrote the whole packet.  Remove it from the tree, which is done _without_ doing calls to
	 *	cmp(), so we it's OK for us to rewrite item->retry.next.
	 */
	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

	/*
	 *	We have more things to do, insert the entry back into the tree, and update the timer.
	 */
	(void) fr_rb_insert(&my->rb, item);

	return 1;
}

/*
 *	Check for the "next next" retry.  If that's still in the past,
 *	then skip it.  But _don't_ update retry.count, as we don't
 *	send packets.  Instead, just enforce MRD, etc.
 */
static int fr_bio_retry_write_delayed(fr_bio_retry_t *my, fr_time_t now)
{
	fr_bio_retry_entry_t *item;

	/*
	 *	We can't be in this function if there's a partial packet.  We must be in
	 *	fr_bio_retry_write_partial().
	 */
	fr_assert(!my->partial);

	while ((item = fr_rb_first(&my->rb)) != NULL) {
		int rcode;

		/*
		 *	This item needs to be sent in the future, we're done.
		 */
		if (fr_time_cmp(now, item->retry.next) > 0) break;

		/*
		 *	Write one item, and don't update timers.
		 */
		rcode = fr_bio_retry_write_item(my, item, now);
		if (rcode <= 0) return rcode;
	}

	/*
	 *	Now that we've written multiple items, reset the timer.
	 *
	 *	We do this at the end of the loop so that we don't update it for each item in the loop.
	 *
	 *	@todo - set generic write error?
	 */
	(void) fr_bio_retry_reset_timer(my);

	return 0;
}


/** There's a partial packet written.  Write all of that one first, before writing another packet.
 *
 *  The packet can either be cancelled, or IO blocked.  In either case, we must write the full packet before
 *  going on to the next one, OR retrying another packet.
 */
static ssize_t fr_bio_retry_write_partial(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	size_t used;
	ssize_t rcode;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;
	fr_bio_retry_entry_t *item = my->partial;

	fr_assert(!my->first);
	fr_assert(!my->ev);
	fr_assert(my->partial != NULL);
	fr_assert(my->buffer.start);

	used = fr_bio_buf_used(&my->buffer);
	fr_assert(used > 0);

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->write(next, NULL, my->buffer.read, used);
	if (rcode <= 0) return rcode;

	my->buffer.read += rcode;

	/*
	 *	Still data in the buffer.  We still can't send more packets or do retries.
	 */
	if (fr_bio_buf_used(&my->buffer) > 0) return 0;

	/*
	 *	We're done.  Reset the buffer and clean up our cached partial packet.
	 */
	fr_bio_buf_reset(&my->buffer);
	my->partial = NULL;

	/*
	 *	The item was cancelled.  It's still in the tree, so we remove it, and reset its fields.
	 *	We then insert it into the free list.
	 *
	 *	If it's not cancelled, then we leave it in the tree, and run its timers s normal.
	 */
	if (item->cancelled) {
		(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

#ifndef NDEBUG
		item->buffer = NULL;
#endif
		item->uctx = NULL;
		item->packet_ctx = NULL;

		fr_bio_retry_list_insert_head(&my->free, item);
	}

	/*
	 *	Walk through the list to see if we need to retry writes and jump ahead with packets.
	 *
	 *	Note that the retried packets are sent _before_ the new one.  If the caller doesn't want this
	 *	behavior, he can cancel the old ones.
	 *
	 *	@todo - have a way to prioritize packets?  i.e. to insert a packet at the _head_ of the list,
	 *	and write it _now_, as with Status-Server.
	 */
	item = fr_rb_first(&my->rb);
	if (item) {
		fr_time_t now = fr_time();

		/*
		 *	We're supposed to send the next retry now.  i.e. the socket has been blocked for a
		 *	long time.
		 */
		if (fr_time_cmp(now, item->retry.next) <= 0) {
			rcode = fr_bio_retry_write_delayed(my, now);
			if (rcode < 0) return rcode;
		}

		/*
		 *	We now have an active socket but no timers, so we set up the timers.
		 */
		(void) fr_bio_retry_reset_timer(my);
	}

	/*
	 *	Try to write the packet which we were given.
	 */
	my->bio.write = fr_bio_retry_write;
	return fr_bio_retry_write(bio, packet_ctx, buffer, size);
}

/** The write is blocked.
 *
 *  We couldn't write out the entire packet, the bio is blocked.  Don't write anything else until we become
 *  unblocked!
 *
 *  And free the timer.  There's no point in trying to write things if the socket is blocked.
 */
static ssize_t fr_bio_retry_blocked(fr_bio_retry_t *my, fr_bio_retry_entry_t *item, ssize_t rcode)
{
	fr_assert(!my->partial);
	fr_assert(rcode > 0);

	/*
	 *	(re)-alloc the buffer for partial writes.
	 */
	if (!my->buffer.start ||
	    (item->size > fr_bio_buf_size(&my->buffer))) {
		if (fr_bio_buf_alloc(my, &my->buffer, item->size)) return -1;
	}

	fr_assert(fr_bio_buf_used(&my->buffer) == 0);
	fr_assert(my->buffer.read == my->buffer.start);

	fr_bio_buf_write(&my->buffer, item->buffer + rcode, item->size - rcode);

	my->partial = item;

	/*
	 *	There's no timer, as the write is blocked, so we can't retry.
	 */
	talloc_const_free(my->ev);
	my->first = NULL;

	my->bio.write = fr_bio_retry_write_partial;

	/*
	 *	We leave the entry in the timer tree so that the expiry timer will get hit.
	 *
	 *	And then return the size of the partial data we wrote.
	 */
	return rcode;
}


/**  Resend a packet.
 *
 *  This function should be called by the rewrite() callback, after (possibly) re-encoding the packet.
 *
 *  @param bio		the binary IO handler
 *  @param item		the retry context from #fr_bio_retry_sent_t
 *  @param buffer	raw data for the packet.  May be NULL, in which case the previous packet is retried
 *  @param size		size of the raw data
 *  @return
 *	- <0 on error
 *	- 0 for "wrote no data"
 *	- >0 for "wrote data".
 */
ssize_t fr_bio_retry_rewrite(fr_bio_t *bio, fr_bio_retry_entry_t *item, const void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;

	/*
	 *	The caller may (accidentally or intentionally) call this function when there's a partial
	 *	packet.  The intention for rewrite() is that it is only called from timers, and those only run
	 *	when the socket isn't blocked.  But the caller might not pay attention to those issues.
	 */
	if (my->partial) return 0;
	
	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	The caller should pass NULL for "use the previous packet".
	 */
	if (buffer) {
		item->buffer = buffer;
		item->size = size;
	}

	/*
	 *	Write out the packet, if everything is OK, return.
	 *
	 *	Note that we don't update any timers if the write succeeded.  That is handled by the caller.
	 */
	rcode = next->write(next, item->packet_ctx, item->buffer, item->size);
	if ((size_t) rcode == size) return rcode;

	/*
	 *	Can't write anything, be sad.
	 */
	if (rcode == 0) return 0;

	/*
	 *	There's an error writing the packet.  Release it, and move the item to the free list.
	 *
	 *	Note that we don't bother resetting the timer.  There's no point in changing the timer when
	 *	the bio is likely dead.
	 */
	if (rcode < 0) {
		if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return 0;

		fr_bio_retry_release(my, item, FR_BIO_RETRY_WRITE_ERROR);
		return rcode;
	}

	/*
	 *	We had previously written the packet, so save the re-sent one, too.
	 */
	return fr_bio_retry_blocked(my, item, rcode);
}

/** A previous timer write had a fatal error, so we forbid further writes.
 *
 */
static ssize_t fr_bio_retry_write_fatal(fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);

	return my->error;
}

/** Run a timer event.  Usually to write out another packet.
 *
 */
static void fr_bio_retry_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	ssize_t rcode;
	fr_bio_retry_t *my = talloc_get_type_abort(uctx, fr_bio_retry_t);
	fr_bio_retry_entry_t *item;

	/*
	 *	For the timer to be running, there must be a "first" entry which causes the timer to fire.
	 *
	 *	There must also be no partially written entry.  If the IO is blocked, then all timers are
	 *	suspended.
	 */
	fr_assert(my->first != NULL);
	fr_assert(my->partial == NULL);

	item = my->first;

	/*
	 *	Retry one item.
	 */
	rcode = fr_bio_retry_write_item(my, item, now);
	if (rcode < 0) {
		fr_assert(rcode != fr_bio_error(IO_WOULD_BLOCK)); /* should return 0 instead! */

		my->error = rcode;
		my->bio.write = fr_bio_retry_write_fatal;
		return;
	}

	/*
	 *	Partial write - no timers get set.
	 */
	if (rcode == 0) return;

	/*
	 *	We successfull wrote this item.  Reset the timer to the next one, which is likely to be a
	 *	different one from the item we just updated.
	 */
	(void) fr_bio_retry_reset_timer(my);
}

/** Write a request, and see if we have a reply.
 *
 */
static ssize_t fr_bio_retry_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_retry_entry_t *item;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;

	fr_assert(!my->partial);

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);
	
	/*
	 *	The caller is trying to flush partial data.  But we don't have any partial data, so just call
	 *	the next bio to flush it.
	 */
	if (!buffer) {
		return next->write(next, packet_ctx, NULL, size);
	}

	/*
	 *	Catch the corner case where the max number of saved packets is exceeded.
	 */
	if (fr_bio_retry_list_num_elements(&my->free) == 0) {
		item = fr_rb_last(&my->rb);

		fr_assert(item != NULL);

		if (!item->retry.replies) return fr_bio_error(BUFFER_FULL);

		if (fr_bio_retry_entry_cancel(bio, item) < 0) return fr_bio_error(BUFFER_FULL);

		/*
		 *	We now have a free item, so we can use it.
		 */
		fr_assert(fr_bio_retry_list_num_elements(&my->free) > 0);
	}

	/*
	 *	Write out the packet.  If there's an error, OR we wrote nothing, return.
	 *
	 *	Note that we don't mark the socket as blocked if the next bio didn't write anything.  We want
	 *	the caller to know that the write didn't succeed, and the caller takes care of managing the
	 *	current packet.  So there's no need for us to do that.
	 */
	rcode = next->write(next, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

	/*
	 *	Initialize the retry timers after writing the packet.
	 */
	item = fr_bio_retry_list_pop_head(&my->free);
	fr_assert(item != NULL);

	fr_assert(item->my == my);
	item->retry.config = NULL;
	item->retry.start = fr_time();
	item->packet_ctx = packet_ctx;
	item->buffer = buffer;
	item->size = size;

	/*
	 *	Tell the application that we've saved the packet.  The "item" pointer allows the application
	 *	to cancel this packet if necessary.
	 */
	my->sent(bio, packet_ctx, buffer, size, item);

	if (!item->retry.config) {
		fr_retry_init(&item->retry, item->retry.start, &my->retry_config);
	}

	/*
	 *	This should never fail.
	 */
	if (!fr_rb_insert(&my->rb, item)) {
		fr_assert(my->first != item);
		fr_bio_retry_list_insert_head(&my->free, item);
		return size;
	}

	/*
	 *	We only wrote part of the packet, remember to write the rest of it.
	 */
	if ((size_t) rcode < size) {
		return fr_bio_retry_blocked(my, item, rcode);
	}

	/*
	 *	We've just inserted this packet into the timer tree, so it can't be used as the current timer.
	 *	Once we've inserted it, we update the timer.
	 */
	fr_assert(my->first != item);

	/*
	 *	If we can't set the timer, then release this item.
	 */
	if (fr_bio_retry_reset_timer(my) < 0) {
		fr_strerror_const("Failed adding timer for packet");

		fr_bio_retry_release(my, item, FR_BIO_RETRY_CANCELLED);
		return fr_bio_error(GENERIC);
	}

	return size;
}

static ssize_t fr_bio_retry_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_retry_entry_t *item;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Read the packet.  If error or nothing, return immediately.
	 */
	rcode = next->read(next, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

	/*
	 *	Not a valid response to a request, OR a duplicate response to a request: don't return it to
	 *	the caller.
	 *
	 *	But if it is a duplicate response, update the counters and do cleanups as necessary.
	 */
	item = NULL;
	if (!my->response(bio, &item, packet_ctx, buffer, size)) {
		if (!item) return 0;

		item->retry.replies++;
		if (item->retry.replies < item->retry.count) return 0;

		/*
		 *	We have a reply, so we can't possibly be partially writing the request
		 */
		fr_assert(item != my->partial);

		/*
		 *	We've received all of the responses, we can clean up the packet.
		 */
		fr_bio_retry_release(my, item, FR_BIO_RETRY_DONE);
		return 0;
	}

	fr_assert(item != NULL);
	fr_assert(item->retry.replies == 0);
	fr_assert(item != my->partial);
       
	/*
	 *	We have a new reply.  If we've received all of the replies (i.e. one), OR we don't have a
	 *	maximum lifetime for this request, then release it immediately.
	 */
	item->retry.replies++;
	if ((item->retry.replies >= item->retry.count) || !fr_time_delta_ispos(my->retry_config.mrd)) {
		fr_bio_retry_release(my, item, FR_BIO_RETRY_DONE);
		return rcode;
	}

	/*
	 *	There are more replies pending.  Wait passively for more replies, and clean up the item
	 *	when the timer has expired.
	 */
	item->retry.next = fr_time_add_time_delta(item->retry.start, my->retry_config.mrd);

	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
	(void) fr_rb_insert(&my->rb, item);
	(void) fr_bio_retry_reset_timer(my);

	return rcode;
}

static int8_t _entry_cmp(void const *one, void const *two)
{
	fr_bio_retry_entry_t const *a = one;
	fr_bio_retry_entry_t const *b = two;

	fr_assert(a->buffer);
	fr_assert(b->buffer);

	return fr_time_cmp(a->retry.next, b->retry.next);
}

/** Cancel one item.
 *
 *  If "item" is NULL, the last entry in the timer tree is cancelled.
 *
 *  @param bio		the binary IO handler
 *  @param item		the retry context from #fr_bio_retry_sent_t
 *  @return
 *	- <0 error
 *	- 0 - didn't cancel
 *	- 1 - did cancel
 */
int fr_bio_retry_entry_cancel(fr_bio_t *bio, fr_bio_retry_entry_t *item)
{
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);

	/*
	 *	No item passed, try to cancel the oldest one.
	 */
	if (!item) {
		item = fr_rb_last(&my->rb);
		if (!item) return 0;

		/*
		 *	This item hasn't had a response, we can't cancel it.
		 */
		if (!item->retry.replies) return 0;
	}

	/*
	 *	If the caller has cached a previously finished item, then that's a fatal error.
	 */
	fr_assert(item->buffer != NULL);

	fr_bio_retry_release(my, item, (item->retry.replies > 0) ? FR_BIO_RETRY_DONE : FR_BIO_RETRY_CANCELLED);

	return 1;
}

/**  Set a per-packet retry config 
 *
 *  This function should be called from the #fr_bio_retry_sent_t callback to set a unique retry timer for this
 *  packet.  If no retry configuration is set, then the main one from the alloc() function is used.
 */
int fr_bio_retry_entry_start(UNUSED fr_bio_t *bio, fr_bio_retry_entry_t *item, fr_retry_config_t const *cfg)
{
	fr_assert(item->buffer != NULL);

	if (item->retry.config) return -1;

	fr_assert(fr_time_delta_unwrap(cfg->irt) != 0);

	fr_retry_init(&item->retry, item->retry.start, cfg);

	return 0;
}

/**  Allow the callbacks / application to know when things are being retried.
 *
 *  This is not initialized util _after_ fr_bio_retry_entry_start() has been called.
 */
const fr_retry_t *fr_bio_retry_entry_info(UNUSED fr_bio_t *bio, fr_bio_retry_entry_t *item)
{
	fr_assert(item->buffer != NULL);

	if (!item->retry.config) return NULL;

	return &item->retry;
}


/**  Cancel all outstanding packets.
 *
 */
static int fr_bio_retry_destructor(fr_bio_retry_t *my)
{
	fr_rb_iter_inorder_t iter;
	fr_bio_retry_entry_t *item;

	talloc_const_free(my->ev);

	/*
	 *	Cancel all outgoing packets.  Don't bother updating the tree or the free list, as all of the
	 *	entries will be deleted when the memory is freed.
	 */
	while ((item = fr_rb_iter_init_inorder(&iter, &my->rb)) != NULL) {
		my->release((fr_bio_t *) my, item, FR_BIO_RETRY_CANCELLED);
	}

	my->first = NULL;

	return 0;
}

/**  Allocate a #fr_bio_retry_t
 *
 */
fr_bio_t *fr_bio_retry_alloc(TALLOC_CTX *ctx, size_t max_saved,
			     fr_bio_retry_sent_t sent,
			     fr_bio_retry_response_t response,
			     fr_bio_retry_rewrite_t rewrite,
			     fr_bio_retry_release_t release,
			     fr_bio_retry_config_t const *cfg,
			     fr_bio_t *next)
{
	size_t i;
	fr_bio_retry_t *my;
	fr_bio_retry_entry_t *items;

	fr_assert(cfg->el);

	/*
	 *	Limit to reasonable values.
	 */
	if (!max_saved) return NULL;
	if (max_saved > 65536) return NULL;

	my = talloc_zero(ctx, fr_bio_retry_t);
	if (!my) return NULL;

	/*
	 *	Allocate everything up front, to get better locality of reference, less memory fragmentation,
	 *	and better reuse of data structures.
	 */
	items = talloc_array(my, fr_bio_retry_entry_t, max_saved);
	if (!items) return NULL;

	/*
	 *	Insert the entries into the free list in order.
	 */
	fr_bio_retry_list_init(&my->free);
	for (i = 0; i < max_saved; i++) {
		items[i].my = my;
		fr_bio_retry_list_insert_tail(&my->free, &items[i]);
	}

	(void) fr_rb_inline_init(&my->rb, fr_bio_retry_entry_t, node, _entry_cmp, NULL);

	my->sent = sent;
	if (!rewrite) {
		my->rewrite = fr_bio_retry_rewrite;
	} else {
		my->rewrite = rewrite;
	}
	my->response = response;
	my->release = release;

	my->el = cfg->el;
	my->retry_config = cfg->retry_config;

	my->bio.write = fr_bio_retry_write;
	my->bio.read = fr_bio_retry_read;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor(my, fr_bio_retry_destructor);

	return (fr_bio_t *) my;
}
