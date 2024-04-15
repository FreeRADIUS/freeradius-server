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
 * @file lib/bio/dedup.c
 * @brief Binary IO abstractions for deduping packets.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/buf.h>
#include <freeradius-devel/util/rb.h>
#include <freeradius-devel/util/dlist.h>

#define _BIO_DEDUP_PRIVATE
#include <freeradius-devel/bio/dedup.h>

typedef struct fr_bio_dedup_list_s	fr_bio_dedup_list_t;
typedef struct fr_bio_dedup_s	fr_bio_dedup_t;

/*
 *	There is substanstial similarity between this code and the
 *	"retry" bio.  Any fixes which are done here should be checked
 *	there, and vice versa.
 */

/*
 *	Define type-safe wrappers for head and entry definitions.
 */
FR_DLIST_TYPES(fr_bio_dedup_list)

struct fr_bio_dedup_entry_s {
	void		*uctx;
	void		*packet_ctx;
	uint8_t		*packet;	       	//!< cached packet data for finding duplicates
	size_t		packet_size;		//!< size of the cached packet data
	uint8_t		*reply;			//!< reply cached by the application
	size_t		reply_size;		//!< size of the cached reply

	union {
		struct {
			fr_rb_node_t	node;		//!< for the expiry timers
		};
		FR_DLIST_ENTRY(fr_bio_dedup_list) entry; //!< for the free list
	};

	fr_bio_dedup_t	*my;			//!< so we can get to it from the event timer callback

	fr_time_t	expires;		//!< when this entry expires
	bool		cancelled;		//!< was this item cancelled?
};

FR_DLIST_FUNCS(fr_bio_dedup_list, fr_bio_dedup_entry_t, entry)

struct fr_bio_dedup_s {
	FR_BIO_COMMON;

	fr_event_list_t		*el;
	fr_rb_tree_t		rb;		//!< expire list

	fr_bio_dedup_config_t	config;

	fr_event_timer_t const	*ev;

	/*
	 *	The "first" entry is cached here so that we can detect when it changes.  The insert / delete
	 *	code can just do its work without worrying about timers.  And then when the tree manipulation
	 *	is done, call the fr_bio_dedup_reset_timer() function to reset (or not) the timer.
	 *
	 *	The timer is set for is when the first packet expires.
	 */
	fr_bio_dedup_entry_t	*first;

	/*
	 *	Cache a partial write when IO is blocked.
	 *
	 *	When the IO is blocked, we can still expire old entries, unlike the "retry" BIOs.  This is
	 *	because we're not resending packets, we're just cleaning up *sent* packets when they expire.
	 */
	fr_bio_dedup_entry_t	*partial;

	fr_bio_dedup_receive_t	receive;	//!< called when we receive a potentially new packet
	fr_bio_dedup_release_t	release;	//!< called to release a packet

	fr_bio_dedup_get_item_t	get_item;	//!< turn a packet_ctx into a #fr_bio_dedup_entry_t

	fr_bio_buf_t		buffer;

	FR_DLIST_HEAD(fr_bio_dedup_list) free;
};

static void fr_bio_dedup_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx);
static ssize_t fr_bio_dedup_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);
static ssize_t fr_bio_dedup_blocked(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, ssize_t rcode);
static void fr_bio_dedup_release(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, fr_bio_dedup_release_reason_t reason);

/**  Resend a reply when we receive a duplicate request.
 *
 *  This function should be called by the respond() callback to re-send a duplicate reply.
 *
 *  It can also be called by the application when it first has a response to the request.
 *
 *  @param bio		the binary IO handler
 *  @param item		the dedup context from #fr_bio_dedup_sent_t
 *  @return
 *	- <0 on error
 *	- 0 for "wrote no data"
 *	- >0 for "wrote data".
 */
ssize_t fr_bio_dedup_respond(fr_bio_t *bio, fr_bio_dedup_entry_t *item)
{
	ssize_t rcode;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);
	fr_bio_t *next;

	if (!item->reply || !item->reply_size) return 0;
	
	/*
	 *	We read a duplicate packet and wish to reply, but the writes may be blocked.
	 *
	 *	If so, we just tell the caller that we can't write anything.
	 */
	if (my->partial) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Write out the packet, if everything is OK, return.
	 *
	 *	Note that we don't update any timers if the write succeeded.  That is handled by the caller.
	 */
	rcode = next->write(next, item->packet_ctx, item->reply, item->reply_size);
	if ((size_t) rcode == item->reply_size) return rcode;

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
		if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return rcode;

		fr_bio_dedup_release(my, item, FR_BIO_DEDUP_WRITE_ERROR);
		return rcode;
	}

	/*
	 *	We are writing item->reply, and that's blocked.  Save the partial packet for later.
	 */
	return fr_bio_dedup_blocked(my, item, rcode);
}

/** Reset the timer after changing the rb tree.
 *
 */
static int fr_bio_dedup_reset_timer(fr_bio_dedup_t *my)
{
	fr_bio_dedup_entry_t *first;

	/*
	 *	Nothing to do, don't set any timers.
	 */
	first = fr_rb_first(&my->rb);
	if (!first) {
		talloc_const_free(my->ev);
		my->ev = NULL;
		my->first = NULL;
		return 0;
	}

	/*
	 *	We don't care about partially written packets.  The timer remains set even when we have a
	 *	partial outgoing packet, because we can expire entries which aren't partially written.
	 *
	 *	However, the partially written packet MUST NOT be in the expiry tree.
	 */
	fr_assert(first != my->partial);

	/*
	 *	The timer is already set correctly, we're done.
	 */
	if (first == my->first) return 0;

	/*
	 *	Update the timer.  This should never fail.
	 */
	if (fr_event_timer_at(my, my->el, &my->ev, first->expires, fr_bio_dedup_timer, my) < 0) return -1;

	my->first = first;
	return 0;
}

/** Release an entry back to the free list.
 *
 */
static void fr_bio_dedup_release(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, fr_bio_dedup_release_reason_t reason)
{
	my->release((fr_bio_t *) my, item, reason);

	/*
	 *	Partially written items aren't in the expiry tree.
	 */
	if (my->partial != item) (void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

	/*
	 *	We're deleting the timer entry.  Go reset the timer.
	 */
	if (my->first == item) {
		my->first = NULL;
		(void) fr_bio_dedup_reset_timer(my);
	}

	/*
	 *	We've partially written this item. Mark it as cancelled, and remove it from the expiry tree.
	 *	This lets us expiry other entries, even if this one is blocked.
	 *
	 *	Don't return this item to the free list until such time as it's fully written out.
	 */
	item->cancelled = (my->partial == item);
	if (item->cancelled) return;

#ifndef NDEBUG
	item->packet = NULL;
#endif
	item->uctx = NULL;
	item->packet_ctx = NULL;

	fr_assert(my->first != item);
	fr_bio_dedup_list_insert_head(&my->free, item);
}

/** Save partially written data to our local buffer.
 *
 */
static int fr_bio_dedup_buffer_save(fr_bio_dedup_t *my, uint8_t const *buffer, size_t size, ssize_t rcode)
{
	/*
	 *	(re)-alloc the buffer for partial writes.
	 */
	if (!my->buffer.start ||
	    (size > fr_bio_buf_size(&my->buffer))) {
		if (fr_bio_buf_alloc(my, &my->buffer, size) < 0) return -1;
	}

	fr_assert(fr_bio_buf_used(&my->buffer) == 0);
	fr_assert(my->buffer.read == my->buffer.start);

	fr_bio_buf_write(&my->buffer, buffer + rcode, size - rcode);

	return 0;
}

/** Write data from our local buffer to the next bio.
 *
 */
static ssize_t fr_bio_dedup_buffer_write(fr_bio_dedup_t *my)
{
	size_t used;
	ssize_t rcode;
	fr_bio_t *next;

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
	 *	Still data in the buffer.  We can't send more packets until we finish writing this one.
	 */
	if (fr_bio_buf_used(&my->buffer) > 0) return 0;

	/*
	 *	We're done.  Reset the buffer and clean up our cached partial packet.
	 */
	fr_bio_buf_reset(&my->buffer);

	return rcode;
}

/** There's a partial packet written.  Write all of that one first, before writing another packet.
 *
 *  The packet can either be cancelled, or IO blocked.  In either case, we must write this packet before
 *  we can write another one.
 */
static ssize_t fr_bio_dedup_write_partial(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);
	fr_bio_dedup_entry_t *item = my->partial;

	fr_assert(my->partial != NULL);
	fr_assert(my->buffer.start);

	rcode = fr_bio_dedup_buffer_write(my);
	if (rcode <= 0) return rcode;

	my->partial = NULL;

	/*
	 *	Partial writes are removed from the expiry tree until they're fully written.  When they're
	 *	written, either add it back to the tree if it's still operational, or add it to the free list
	 *	if it has been cancelled.
	 */
	if (!item->cancelled) {
		/*
		 *	See if we have to clean up this entry.  If so, do it now.  That avoids another bounce
		 *	through the event loop.
		 */
		if (fr_time_lteq(item->expires, fr_time())) {
			fr_bio_dedup_release(my, item, FR_BIO_DEDUP_EXPIRED);

		} else {
			/*
			 *	We've changed the tree, so update the timer.  fr_bio_dedup_write() only
			 *	updates the timer on successful write.
			 */
			(void) fr_rb_insert(&my->rb, item);
			(void) fr_bio_dedup_reset_timer(my);
		}

	} else {
#ifndef NDEBUG
		item->packet = NULL;
#endif
		item->uctx = NULL;
		item->packet_ctx = NULL;

		fr_bio_dedup_list_insert_head(&my->free, item);
	}

	/*
	 *	Unlike the retry BIO, we don't retry writes for items in the RB tree.  Those ones have already
	 *	been written.
	 */

	/*
	 *	Try to write the packet which we were given.
	 */
	my->bio.write = fr_bio_dedup_write;
	return fr_bio_dedup_write(bio, packet_ctx, buffer, size);
}

/** The write is blocked.
 *
 *  We couldn't write out the entire packet, the bio is blocked.  Don't write anything else until we become
 *  unblocked!
 *
 *  Do NOT free the timer.  We can still expire old entries.  This newly written entry usually ends up as the
 *  _last_ item in the RB tree.
 */
static ssize_t fr_bio_dedup_blocked(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, ssize_t rcode)
{
	fr_assert(!my->partial);
	fr_assert(rcode > 0);
	fr_assert((size_t) rcode < item->reply_size);

	if (fr_bio_dedup_buffer_save(my, item->reply, item->reply_size, rcode) < 0) return fr_bio_error(GENERIC);

	my->partial = item;

	/*
	 *	We cannot expire this entry, so remove it from the expiration tree.  That step lets us
	 *	expire other entries.
	 */
	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
	if (my->first == item) {
		my->first = NULL;
		(void) fr_bio_dedup_reset_timer(my);
	}

	/*
	 *	Reset the write routine, so that if the application tries any more writes, the partial entry
	 *	gets written first.
	 */
	my->bio.write = fr_bio_dedup_write_partial;
	return rcode;
}

/** There's a partial block of data written.  Write all of that data first, before writing another packet.
 */
static ssize_t fr_bio_dedup_write_data(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);

	rcode = fr_bio_dedup_buffer_write(my);
	if (rcode <= 0) return rcode;

	/*
	 *	Try to write the packet which we were given.
	 */
	my->bio.write = fr_bio_dedup_write;
	return fr_bio_dedup_write(bio, packet_ctx, buffer, size);
}


/** The write is blocked, but we don't have "item".
 *
 *  We couldn't write out the entire packet, the bio is blocked.  Don't write anything else until we become
 *  unblocked!
 *
 *  Do NOT free the timer.  We can still expire old entries.  This newly written entry usually ends up as the
 *  _last_ item in the RB tree.
 */
static ssize_t fr_bio_dedup_blocked_data(fr_bio_dedup_t *my, uint8_t const *buffer, size_t size, ssize_t rcode)
{
	fr_assert(!my->partial);
	fr_assert(rcode > 0);
	fr_assert((size_t) rcode < size);

	if (fr_bio_dedup_buffer_save(my, buffer, size, rcode) < 0) return fr_bio_error(GENERIC);

	/*
	 *	Reset the write routine, so that if the application tries any more writes, the data
	 *	gets written first.
	 */
	my->bio.write = fr_bio_dedup_write_data;
	return rcode;
}

/*
 *	There is no fr_bio_dedup_rewrite(), packets are never re-written by this bio.
 */

/** Expire an entry when its timer fires.
 *
 */
static void fr_bio_dedup_timer(UNUSED fr_event_list_t *el, fr_time_t now, void *uctx)
{
	fr_bio_dedup_t *my = talloc_get_type_abort(uctx, fr_bio_dedup_t);
	fr_bio_dedup_entry_t *item;
	fr_time_t expires;

	fr_assert(my->first != NULL);
	fr_assert(fr_rb_first(&my->rb) == my->first);

	my->first = NULL;

	/*
	 *	Expire all entries which are within 10ms of "now".  That way we don't reset the event many
	 *	times in short succession.
	 */
	expires = fr_time_add(now, fr_time_delta_from_msec(10));

	while ((item = fr_rb_first(&my->rb)) != NULL) {
		if (fr_time_gt(item->expires, expires)) break;

		fr_bio_dedup_release(my, item, FR_BIO_DEDUP_EXPIRED);
	}

	(void) fr_bio_dedup_reset_timer(my);
}

/** Write raw data to the bio.
 *
 *  This function is largely a duplicate of fr_bio_dedup_respond().  Except due to the BIO API, it can be
 *  passed a NULL buffer (for flushing the BIOs), and it can't be passed a #fr_bio_dedup_entry_t, and instead
 *  has to be passed a "void *packet_ctx".
 *
 *  The caller is free to ignore this function,
 */
static ssize_t fr_bio_dedup_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_dedup_entry_t *item;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);
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
	 *	Write out the packet.  If there's an error, OR we wrote nothing, return.
	 *
	 *	Note that we don't mark the socket as blocked if the next bio didn't write anything.  We want
	 *	the caller to know that the write didn't succeed, and the caller takes care of managing the
	 *	current packet.  So there's no need for us to do that.
	 */
	rcode = next->write(next, packet_ctx, buffer, size);
	if (rcode <= 0) return rcode;

	if ((size_t) rcode == size) return rcode;

	/*
	 *	We need the item pointer to mark this entry as blocked.  If that doesn't exist, then we try
	 *	really hard to write out the un-tracked data.
	 */
	item = NULL;
	if (my->get_item) item = my->get_item(bio, packet_ctx);
	if (!item) return fr_bio_dedup_blocked_data(my, buffer, size, rcode);

	fr_assert(item->reply == buffer);
	fr_assert(item->reply_size == size);

	return fr_bio_dedup_blocked(my, item, rcode);
}

static ssize_t fr_bio_dedup_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_dedup_entry_t *item;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);
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
	 *	
	 */
	item = fr_bio_dedup_list_pop_head(&my->free);
	fr_assert(item != NULL);

	fr_assert(item->my == my);
	*item = (fr_bio_dedup_entry_t) {
		.my = my,
		.packet_ctx = packet_ctx,
		.packet = buffer,
		.packet_size = (size_t) rcode,
	};

	/*
	 *	See if we want to respond to this packet.  If this isn't something we respond to, then we just
	 *	discard it.
	 *
	 *	The "respond" function is responsible for looking in a local dedup tree to see if there's a
	 *	cached reply.  It's also responsible for calling the fr_bio_retry_respond() function to send
	 *	any duplicate reply/
	 *
	 *	If we're NOT going to reply to this packet, then the item we just popped needs to get inserted
	 *	back into the free list.
	 *
	 *	The caller should potentially cancel any conflicting packets via fr_bio_dedup_entry_cancel(),
	 *	and potentially also write a duplicate reply via fr_bio_dedup_respond().
	 */
	if (!my->receive(bio, item, packet_ctx, buffer, rcode)) {
		fr_bio_dedup_list_insert_head(&my->free, item);
		return 0;
	}

	/*
	 *	The application can cache "item", and later update item->reply and item->reply_size.
	 *
	 *	Now that we know we're going to track the file, update the default expirty time.  The caller
	 *	can always call fr_bio_dedup_entry_extend() to change the expiry time.
	 */
	item->expires = fr_time_add_time_delta(fr_time(), my->config.lifetime);

	/*
	 *	This should never fail.
	 */
	if (!fr_rb_insert(&my->rb, item)) {
		fr_assert(my->first != item);

		my->release((fr_bio_t *) my, item, FR_BIO_DEDUP_INTERNAL_ERROR);
		fr_bio_dedup_list_insert_head(&my->free, item);
		return fr_bio_error(GENERIC);
	}

	return rcode;
}

static int8_t _entry_cmp(void const *one, void const *two)
{
	fr_bio_dedup_entry_t const *a = one;
	fr_bio_dedup_entry_t const *b = two;

	fr_assert(a->packet);
	fr_assert(b->packet);

	return fr_time_cmp(a->expires, b->expires);
}

/** Cancel one item.
 *
 *  @param bio		the binary IO handler
 *  @param item		the dedup context from #fr_bio_dedup_respond_t
 *  @return
 *	- <0 error
 *	- 0 - didn't cancel
 *	- 1 - did cancel
 */
int fr_bio_dedup_entry_cancel(fr_bio_t *bio, fr_bio_dedup_entry_t *item)
{
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);

	/*
	 *	If the caller has cached a previously finished item, then that's a fatal error.
	 */

	fr_bio_dedup_release(my, item, FR_BIO_DEDUP_CANCELLED);

	return 1;
}

/** Extend the expiry time for an entry
 *
 *  @param bio		the binary IO handler
 *  @param item		the dedup context from #fr_bio_dedup_respond_t
 *  @param expires     	the new expiry time
 *  @return
 *	- <0 error
 *	- 0 success
 */
int fr_bio_dedup_entry_extend(fr_bio_t *bio, fr_bio_dedup_entry_t *item, fr_time_t expires)
{
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);

	/*
	 *	Partially written replies aren't in the dedup tree.  We can just change their expiry time and
	 *	be done.
	 */
	if (my->partial == item) {
		item->expires = expires;
		return 0;
	}

	/*
	 *	Shortening the lifetime is OK.  If the caller does something dumb like set expiry to a time in
	 *	the past, well... that's their problem.
	 */
	fr_assert(fr_time_lteq(expires, fr_time()));

	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

	item->expires = expires;

	/*
	 *	We've changed the tree, so update the timer.
	 */
	(void) fr_rb_insert(&my->rb, item);

	/*
	 *	If we're not changing the first item, we don't need to change the timers.
	 *
	 *	Otherwise we clear the "first" flag, so that the reset timer function will change the timer
	 *	value.
	 */
	if (my->first != item) return 0;

	my->first = NULL;

	return fr_bio_dedup_reset_timer(my);
}


/**  Remove the dedup cache
 *
 */
static int fr_bio_dedup_destructor(fr_bio_dedup_t *my)
{
	fr_rb_iter_inorder_t iter;
	fr_bio_dedup_entry_t *item;

	talloc_const_free(my->ev);

	/*
	 *	Cancel all outgoing packets.  Don't bother updating the tree or the free list, as all of the
	 *	entries will be deleted when the memory is freed.
	 */
	while ((item = fr_rb_iter_init_inorder(&iter, &my->rb)) != NULL) {
		my->release((fr_bio_t *) my, item, FR_BIO_DEDUP_CANCELLED);
	}

#ifndef NDEBUG
	my->ev = NULL;
	my->first = NULL;
#endif

	return 0;
}

/**  Allocate a #fr_bio_dedup_t
 *
 */
fr_bio_t *fr_bio_dedup_alloc(TALLOC_CTX *ctx, size_t max_saved,
			     fr_bio_dedup_receive_t receive,
			     fr_bio_dedup_release_t release,
			     fr_bio_dedup_get_item_t get_item,
			     fr_bio_dedup_config_t const *cfg,
			     fr_bio_t *next)
{
	size_t i;
	fr_bio_dedup_t *my;
	fr_bio_dedup_entry_t *items;

	fr_assert(cfg->el);

	/*
	 *	Limit to reasonable values.
	 */
	if (!max_saved) return NULL;
	if (max_saved > 65536) return NULL;

	my = talloc_zero(ctx, fr_bio_dedup_t);
	if (!my) return NULL;

	/*
	 *	Allocate everything up front, to get better locality of reference, less memory fragmentation,
	 *	and better reuse of data structures.
	 */
	items = talloc_array(my, fr_bio_dedup_entry_t, max_saved);
	if (!items) return NULL;

	/*
	 *	Insert the entries into the free list in order.
	 */
	fr_bio_dedup_list_init(&my->free);
	for (i = 0; i < max_saved; i++) {
		items[i].my = my;
		fr_bio_dedup_list_insert_tail(&my->free, &items[i]);
	}

	(void) fr_rb_inline_init(&my->rb, fr_bio_dedup_entry_t, node, _entry_cmp, NULL);

	my->receive = receive;
	my->release = release;
	my->get_item = get_item;

	my->el = cfg->el;
	my->config = *cfg;

	my->bio.write = fr_bio_dedup_write;
	my->bio.read = fr_bio_dedup_read;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor(my, fr_bio_dedup_destructor);

	return (fr_bio_t *) my;
}
