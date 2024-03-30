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
	void		*packet_ctx
;	fr_bio_retry_rewrite_t rewrite;		//!< per-packet rewrite callback

	union {
		fr_rb_node_t	node;		//!< for the timers
		FR_DLIST_ENTRY(fr_bio_retry_list) entry; //!< for the free list
	};

	fr_bio_retry_t	*my;			//!< so we can get to it from the event timer callback
	fr_retry_t	retry;			//!< retry timers and counters

	uint8_t const	*buffer;
	size_t		size;	
	size_t		partial;		//!< for partial writes :(

	bool		have_reply;		//!< did we see any reply?
};

FR_DLIST_FUNCS(fr_bio_retry_list, fr_bio_retry_entry_t, entry)

struct fr_bio_retry_s {
	FR_BIO_COMMON;

	fr_event_list_t		*el;
	fr_rb_tree_t		rb;

	fr_retry_config_t	retry_config;

	fr_event_timer_t const	*ev;

	fr_bio_retry_entry_t	*first;		//!< for timers
	fr_bio_retry_entry_t	*partial;	//!< for partial writes

	fr_bio_retry_sent_t	sent;
	fr_bio_retry_rewrite_t	rewrite;
	fr_bio_retry_response_t	response;
	fr_bio_retry_release_t	release;

	fr_bio_buf_t		cancelled;

	bool			blocked;

	FR_DLIST_HEAD(fr_bio_retry_list) free;
};

static void fr_bio_retry_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx);
static ssize_t fr_bio_retry_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);


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
		fr_assert(!my->ev);
		my->first = NULL;
		return 0;
	}

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
	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

	/*
	 *	We're deleting the timer entry.  Go reset the timer.
	 */
	if (my->first == item) {
		my->first = NULL;
		(void) fr_bio_retry_reset_timer(my);
	}

	my->release((fr_bio_t *) my, item, reason);

#ifndef NDEBUG
	item->buffer = NULL;
#endif

	fr_bio_retry_list_insert_head(&my->free, item);
}

/** There's a partial *cancelled* packet written.  Write all of that one first, before writing another packet.
 *
 */
static ssize_t fr_bio_retry_write_cancelled(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	size_t used;
	ssize_t rcode;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;

	fr_assert(!my->partial);
	fr_assert(my->cancelled.start);

	used = fr_bio_buf_used(&my->cancelled);
	fr_assert(used > 0);

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->write(next, NULL, my->cancelled.read, used);
	if (rcode <= 0) return rcode;

	my->cancelled.read += rcode;

	if (fr_bio_buf_used(&my->cancelled) == 0) {
		my->blocked = false;
		my->bio.write = fr_bio_retry_write;

		return fr_bio_retry_write(bio, packet_ctx, buffer, size);
	}

	/*
	 *	We didn't write any of the saved partial packet, so we can't write out the current one,
	 *	either.
	 */
	return 0;
}

/** There's a partial packet written.  Write all of that one first, before writing another packet.
 *
 */
static ssize_t fr_bio_retry_write_partial(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_retry_t *my = talloc_get_type_abort(bio, fr_bio_retry_t);
	fr_bio_t *next;
	fr_bio_retry_entry_t *item;
	uint8_t const *packet;
	
	fr_assert(my->partial);
	item = my->partial;
	packet = item->buffer;

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->write(next, NULL, packet + item->partial, item->size - item->partial);
	if (rcode < 0) {
		my->partial = NULL;
		my->blocked = false;
		fr_bio_retry_release(my, item, FR_BIO_RETRY_WRITE_ERROR);
		return rcode;
	}

	/*
	 *	We didn't finish writing the partial packet, so we can't write the current one, either.
	 */
	item->partial += rcode;
	if (item->partial < item->size) return 0;

	/*
	 *	We finally wrote all of this packet.  Clean up the partial tracking items, and go write the
	 *	packet we were given.
	 */
	item->partial = 0;
	my->partial = NULL;
	my->blocked = false;

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
	fr_assert(!item->partial);

	item->partial = (size_t) rcode;
	my->blocked = true;
	my->partial = item;
	talloc_const_free(my->ev);
	my->bio.write = fr_bio_retry_write_partial;

	return rcode;
}


/**  Resend a packet.
 *
 *  This function should be called by the rewrite() callback, after (possibly) re-encoding the packet.
 *
 *  @param bio		the binary IO handler
 *  @param item		the retry context from #fr_bio_retry_save_t
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

	fr_assert(!my->partial);
	
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
	 *	There's an error writing the packet.  Release it, and move the item to the free list.
	 *
	 *	Note that we don't bother resetting the timer, here.  There's no point in running a timer when
	 *	the bio is likely dead.
	 */
	if (rcode < 0) {
		fr_bio_retry_release(my, item, FR_BIO_RETRY_WRITE_ERROR);
		return rcode;
	}

	/*
	 *	We had previously written the packet, so save the re-sent one, too.
	 */
	return fr_bio_retry_blocked(my, item, rcode);
}


static void fr_bio_retry_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	ssize_t rcode;
	fr_bio_retry_entry_t *item = uctx; /* NOT individually talloc'd */
	fr_bio_retry_t *my = talloc_get_type_abort(item->my, fr_bio_retry_t);
	fr_retry_state_t state;
	fr_bio_t *next;

	fr_assert(item == my->first);
	my->first = NULL;

	/*
	 *	Are we there yet?
	 *
	 *	Release it, indicating whether or not we successfully got a reply.
	 */
	state = fr_retry_next(&item->retry, now);
	if (state != FR_RETRY_CONTINUE) {
		fr_bio_retry_release(my, item, (fr_bio_retry_release_reason_t) item->have_reply);
		return;
	}

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Write out the packet.  On failure release this item.
	 *
	 *	If there's an error, we hope that the next "real" write will find the error, and do any
	 *	necessary cleanups.  Note that we can't call bio shutdown here, as the bio is controlled by the
	 *	application, and not by us.
	 */
	if (item->rewrite) {
		rcode = item->rewrite(next, item, item->buffer, item->size);
	} else {
		rcode = my->rewrite(next, item, item->buffer, item->size);
	}
	if (rcode < 0) {
		fr_bio_retry_release(my, item, FR_BIO_RETRY_WRITE_ERROR);
		return;
	}

	/*
	 *	We wrote the whole packet.  Update the various timers and return.
	 */
	if ((size_t) rcode == item->size) {
		/*
		 *	Remove it from the tree, which is done _without_ doing calls to cmp(), so we it's OK
		 *	for us to rewrite item->retry.next.
		 */
		(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

		/*
		 *	We have more things to do, insert the entry back into the tree, and update the timer.
		 */
		(void) fr_rb_insert(&my->rb, item);

		/*
		 *	We're not done, reset the timer to the next one, which is likely to be a different one from
		 *	the item we just updated.	 
		 */
		(void) fr_bio_retry_reset_timer(my);

		return;
	}
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
		if (!item) return fr_bio_error(BUFFER_FULL);

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

	item->retry.config = NULL;
	item->retry.start = fr_time();
	item->packet_ctx = packet_ctx;
	item->buffer = buffer;
	item->size = size;
	item->partial = 0;
	item->have_reply = false;

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

	if (!fr_bio_retry_reset_timer(my)) {
		(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
		fr_bio_retry_list_insert_head(&my->free, item);
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
		 *	We've received all of the responses, we can clean up the packet.
		 */
		fr_bio_retry_release(my, item, FR_BIO_RETRY_DONE);
		return 0;
	}
	fr_assert(item != NULL);
	fr_assert(item->retry.replies == 0);
       
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
 *  @param item		the retry context from #fr_bio_retry_save_t
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

	fr_assert(item->buffer != NULL);

	/*
	 *	If we've written a partial packet, jump through a bunch of hoops to cache the partial packet
	 *	data.  This lets the application cancel any pending packet, while still making sure that we
	 *	don't break packet boundaries.
	 */
	if (my->partial == item) {
		if (item->partial > 0) {
			size_t size;

			size = item->size - item->partial;

			if (!my->cancelled.start) {
				if (fr_bio_buf_alloc(my, &my->cancelled, size)) return -1;

			} else if (size > fr_bio_buf_size(&my->cancelled)) {
				if (fr_bio_buf_alloc(my, &my->cancelled, size)) return -1;
			}

			fr_assert(fr_bio_buf_used(&my->cancelled) == 0);
			fr_assert(my->cancelled.read == my->cancelled.start);

			fr_bio_buf_write(&my->cancelled, item->buffer + item->partial, size);

			my->bio.write = fr_bio_retry_write_cancelled;
		} else {
			my->bio.write = fr_bio_retry_write;
		}

		my->partial = NULL;
	}

	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
	if (my->first == item) my->first = NULL;

	fr_bio_retry_release(my, item, item->have_reply ? FR_BIO_RETRY_DONE : FR_BIO_RETRY_CANCELLED);
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
