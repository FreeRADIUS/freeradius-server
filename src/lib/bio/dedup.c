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
 * The dedup BIO receives packets from the network, and allows for deduplication of requests, so that
 * duplicate requests are only processed once.  In addition, if a reply is available, a duplicate request will
 * result in a duplicate reply.  The actual deduplication tree / table has to be maintained by the calling
 * application, as packet comparisons for deduplication is very protocol-specific.  The purpose of the dedup
 * BIO is to abstract all of the common support functions around this limitation.
 *
 * When packets are read() from the next bio, the #fr_bio_dedup_receive_t callback is run.  It tells the BIO
 * whether or not the packet should be received, and whether or not the packet should be returned to the
 * caller.  The receive callback is also passed a #fr_bio_dedup_entry_t pointer, where the packet_ctx, packet,
 * and size are already filled out.  This entry is used to correlate requests and replies.
 *
 * When packets are write() to the network, the #fr_bio_dedup_get_item_t callback is called to get the
 * previously cached #fr_bio_dedup_entry_t pointer.  This is because there is no generic way to get an
 * additional context to this BIO via the write() routine.  i.e. the packet_ctx for write() may include things
 * like src/dst ip/port, and therefore can't always be an #fr_bio_dedup_entry_t.  The caller should associate
 * the #fr_bio_dedup_entry_t with the packet_ctx for the reply.  The get_item() routine can then return the entry.
 *
 * For simplicity, the next bio should be a memory one.  That way the read() can read more than one packet if
 * necessary.  And the write() can cache a partial packet if it blocks.
 *
 * The entry needs to be cached in order to maintain the internal tracking used by the dedup BIO.
 *
 * On client retransmit, the #fr_bio_dedup_receive_t callback is run, just as if it is a new packet.  The
 * dedup BIO does not know if the received data is a new packet until the #fr_bio_dedup_receive_t callback
 * says so.  On duplicate client request, the #fr_bio_dedup_receive_t callback can call fr_bio_dedup_respond()
 * to send a duplicate reply.  That call bypasses the normal dedup stack, and writes directly to the next bio.
 *
 * The calling application can also call fr_bio_dedup_respond() as soon as it has a reply.  i.e. skip the BIO
 * write() call.  That works, and is safe.
 *
 * The dedup BIO tracks a number of lists / trees internally.  Packets which are received but which have no
 * reply are in an "active" list.  Packets which have a reply are in an "expired" RB tree, where a timer is
 * set to expire packets.  If a write() call results in a partial write, that packet is put into a "partially
 * written" state.  If multiple calls to write() are done when writing is blocked, the replies are put into a
 * "pending" state.
 *
 * The calling application can always call fr_bio_dedup_cancel() to cancel or expire a packet.  This call is
 * safe, and can be made at any time, no matter what state the packet is in.
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
 *	There is substantial similarity between this code and the
 *	"retry" bio.  Any fixes which are done here should be checked
 *	there, and vice versa.
 */

/*
 *	Define type-safe wrappers for head and entry definitions.
 */
FR_DLIST_TYPES(fr_bio_dedup_list)

typedef enum {
	FR_BIO_DEDUP_STATE_FREE,
	FR_BIO_DEDUP_STATE_ACTIVE,		//!< Received, but not replied.
	FR_BIO_DEDUP_STATE_PENDING,		//!< Have a reply, but we're trying to write it out.
	FR_BIO_DEDUP_STATE_REPLIED,		//!< Replied, and waiting for it to expire.
	FR_BIO_DEDUP_STATE_PARTIAL,		//!< Partially written
	FR_BIO_DEDUP_STATE_CANCELLED,		//!< Partially written, and then cancelled.
} fr_bio_dedup_state_t;

struct fr_bio_dedup_entry_s {
	void		*uctx;
	void		*packet_ctx;
	uint8_t		*packet;	       	//!< cached packet data for finding duplicates
	size_t		packet_size;		//!< size of the cached packet data
	void		*reply_ctx;		//!< reply ctx
	uint8_t		*reply;			//!< reply cached by the application
	size_t		reply_size;		//!< size of the cached reply

	fr_rb_node_t	dedup;			//!< user managed dedup node

	union {
		struct {
			fr_rb_node_t	node;		//!< for the expiry timers
		};
		FR_DLIST_ENTRY(fr_bio_dedup_list) entry; //!< for the free list
	};

	fr_bio_dedup_t	*my;			//!< so we can get to it from the event timer callback

	fr_time_t	expires;		//!< when this entry expires
	fr_bio_dedup_state_t state;		//!< which tree or list this item is in
};

FR_DLIST_FUNCS(fr_bio_dedup_list, fr_bio_dedup_entry_t, entry)

struct fr_bio_dedup_s {
	FR_BIO_COMMON;

	fr_event_list_t		*el;

	fr_rb_tree_t		rb;		//!< expire list

	fr_bio_dedup_config_t	config;

	fr_timer_t		*ev;

	/*
	 *	The "first" entry is cached here so that we can detect when it changes.  The insert / delete
	 *	code can just do its work without worrying about timers.  And then when the tree manipulation
	 *	is done, call the fr_bio_dedup_timer_reset() function to reset (or not) the timer.
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

	FR_DLIST_HEAD(fr_bio_dedup_list) active; //!< received but not yet replied
	FR_DLIST_HEAD(fr_bio_dedup_list) pending; //!< trying to write when the socket is blocked.
	FR_DLIST_HEAD(fr_bio_dedup_list) free;	//!< free list
};

static void fr_bio_dedup_timer(UNUSED fr_timer_list_t *el, fr_time_t now, void *uctx);
static ssize_t fr_bio_dedup_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);
static ssize_t fr_bio_dedup_blocked(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, ssize_t rcode);
static void fr_bio_dedup_release(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, fr_bio_dedup_release_reason_t reason);
static int fr_bio_dedup_timer_reset(fr_bio_dedup_t *my);

static inline void fr_bio_dedup_timer_reset_item(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item)
{
	if (my->first != item) return;

	my->first = NULL;
	(void) fr_bio_dedup_timer_reset(my);
}

/** Move an item from active to replied.
 *
 *  Note that we don't update any timers.  The caller is responsible for that.
 */
static void fr_bio_dedup_replied(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item)
{
	if (item->state == FR_BIO_DEDUP_STATE_REPLIED) return;

	fr_assert(item->state == FR_BIO_DEDUP_STATE_ACTIVE);

	(void) fr_bio_dedup_list_remove(&my->active, item);

	/*
	 *	Now that we have a reply, set the default expiry time.  The caller can always call
	 *	fr_bio_dedup_entry_extend() to change the expiry time.
	 */
	item->expires = fr_time_add_time_delta(fr_time(), my->config.lifetime);

	/*
	 *	This should never fail.
	 */
	(void) fr_rb_insert(&my->rb, item);
	item->state = FR_BIO_DEDUP_STATE_REPLIED;
}

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

	switch (item->state) {
		/*
		 *	Send a first reply if we can.
		 */
	case FR_BIO_DEDUP_STATE_ACTIVE:
		/*
		 *	If we're not writing to the socket, just insert the packet into the pending list.
		 */
		if (my->bio.write != fr_bio_dedup_write) {
			(void) fr_bio_dedup_list_remove(&my->active, item);
			fr_bio_dedup_list_insert_tail(&my->pending, item);

			item->state = FR_BIO_DEDUP_STATE_PENDING;
			item->expires = fr_time_add_time_delta(fr_time(), my->config.lifetime);
			return item->reply_size;
		}

		/*
		 *	The socket is writable, go do that.
		 */
		break;

		/*
		 *	Send a duplicate reply.
		 */
	case FR_BIO_DEDUP_STATE_REPLIED:
		if (my->bio.write == fr_bio_dedup_write) break;

		/*
		 *	The socket is blocked.  Save the packet in the pending queue.
		 */
	move_to_pending:
		fr_rb_remove_by_inline_node(&my->rb, &item->node);

	save_in_pending:
		/*
		 *	We could update the timer for pending packets.  However, that's more complicated.
		 *
		 *	The packets will be expire when the pending queue is flushed, OR when the application
		 *	cancels the pending packet.
		 */
		fr_bio_dedup_timer_reset_item(my, item);

		fr_bio_dedup_list_insert_tail(&my->pending, item);
		item->state = FR_BIO_DEDUP_STATE_PENDING;
		return item->reply_size;

		/*
		 *	We're already trying to write this entry, don't do anything else.
		 */
	case FR_BIO_DEDUP_STATE_PENDING:
		fr_assert(my->partial != NULL);
		FALL_THROUGH;

	case FR_BIO_DEDUP_STATE_PARTIAL:
		return fr_bio_error(IO_WOULD_BLOCK);

	case FR_BIO_DEDUP_STATE_CANCELLED:
	case FR_BIO_DEDUP_STATE_FREE:
		fr_assert(0);
		return fr_bio_error(GENERIC);
	}

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Write out the packet, if everything is OK, return.
	 */
	rcode = next->write(next, item->reply_ctx, item->reply, item->reply_size);
	if ((size_t) rcode == item->reply_size) {
		fr_bio_dedup_replied(my, item);
		return rcode;
	}

	/*
	 *	Can't write anything, be sad.
	 */
	if ((rcode == 0) || (rcode == fr_bio_error(IO_WOULD_BLOCK))) {
		if (item->state == FR_BIO_DEDUP_STATE_ACTIVE) {
			(void) fr_bio_dedup_list_remove(&my->active, item);
			goto save_in_pending;
		}

		fr_assert(item->state == FR_BIO_DEDUP_STATE_REPLIED);
		goto move_to_pending;
	}

	/*
	 *	There's an error writing the packet.  Release it, and move the item to the free list.
	 *
	 *	Note that we don't bother resetting the timer.  There's no point in changing the timer when
	 *	the bio is likely dead.
	 */
	if (rcode < 0) {
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
static int fr_bio_dedup_timer_reset(fr_bio_dedup_t *my)
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
	 *
	 *	We also don't care about the pending list.  The application will either cancel the item, or
	 *	the socket will become writable, and the item will get handled then.
	 */
	fr_assert(first != my->partial);

	/*
	 *	The timer is already set correctly, we're done.
	 */
	if (first == my->first) return 0;

	/*
	 *	Update the timer.  This should never fail.
	 */
	if (fr_timer_at(my, my->el->tl, &my->ev, first->expires, false, fr_bio_dedup_timer, my) < 0) return -1;

	my->first = first;
	return 0;
}

/** Release an entry back to the free list.
 *
 */
static void fr_bio_dedup_release(fr_bio_dedup_t *my, fr_bio_dedup_entry_t *item, fr_bio_dedup_release_reason_t reason)
{
	my->release((fr_bio_t *) my, item, reason);

	switch (item->state) {
		/*
		 *	Cancel an active item, just nuke it.
		 */
	case FR_BIO_DEDUP_STATE_ACTIVE:
		fr_bio_dedup_list_remove(&my->active, item);
		break;

		/*
		 *	We already replied, remove it from the expiry tree.
		 *
		 *	We only update the timer if the caller isn't already expiring the entry.
		 */
	case FR_BIO_DEDUP_STATE_REPLIED:
		(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);

		if (reason != FR_BIO_DEDUP_EXPIRED) fr_bio_dedup_timer_reset_item(my, item);
		break;

		/*
		 *	It was pending another write, so we just discard the write.
		 */
	case FR_BIO_DEDUP_STATE_PENDING:
		fr_bio_dedup_list_remove(&my->active, item);
		break;

		/*
		 *	Don't free it.  Just set its state to cancelled.
		 */
	case FR_BIO_DEDUP_STATE_PARTIAL:
		fr_assert(my->partial == item);
		item->state = FR_BIO_DEDUP_STATE_CANCELLED;
		return;

	case FR_BIO_DEDUP_STATE_CANCELLED:
	case FR_BIO_DEDUP_STATE_FREE:
		fr_assert(0);
		return;
	}

#ifndef NDEBUG
	item->packet = NULL;
#endif
	item->uctx = NULL;
	item->packet_ctx = NULL;

	fr_assert(my->first != item);
	fr_bio_dedup_list_insert_head(&my->free, item);
}

/** Flush any packets in the pending queue.
 *
 */
static ssize_t fr_bio_dedup_flush_pending(fr_bio_dedup_t *my)
{
	ssize_t rcode, out_rcode;
	fr_bio_dedup_entry_t *item;
	fr_bio_t *next;
	fr_time_t now;

	/*
	 *	We can only flush the pending list when any previous partial packet has been written.
	 */
	fr_assert(!my->partial);

	/*
	 *	Nothing in the list, we're done.
	 */
	if (fr_bio_dedup_list_num_elements(&my->pending) == 0) return 0;

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	now = fr_time();
	out_rcode = 0;

	/*
	 *	Write out any pending packets.
	 */
	while ((item = fr_bio_dedup_list_pop_head(&my->pending)) != NULL) {
		fr_assert(item->state == FR_BIO_DEDUP_STATE_PENDING);

		/*
		 *	It's already expired, don't bother replying.
		 */
		if (fr_time_lteq(item->expires, now)) {
			fr_bio_dedup_release(my, item, FR_BIO_DEDUP_EXPIRED);
			continue;
		}

		/*
		 *	Write the entry to the next bio.
		 */
		rcode = next->write(next, item->reply_ctx, item->reply, item->reply_size);
		if (rcode <= 0) return rcode; /* @todo - update timer if we've written one packet */

		/*
		 *	We've written the entire packet, move it to the expiry list.
		 */
		if ((size_t) rcode == item->reply_size) {
			(void) fr_bio_dedup_list_remove(&my->pending, item);
			(void) fr_rb_insert(&my->rb, item);
			item->state = FR_BIO_DEDUP_STATE_REPLIED;
			continue;
		}

		fr_bio_dedup_blocked(my, item, rcode);

		out_rcode = fr_bio_error(IO_WOULD_BLOCK);
		break;
	}

	/*
	 *	We may need to update the timer if we've removed the first entry from the tree, or added a new
	 *	first entry.
	 */
	if (!my->first || (my->first != fr_rb_first(&my->rb))) {
		my->first = NULL;
		(void) fr_bio_dedup_timer_reset(my);
	}

	return out_rcode;
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

	fr_assert((item->state == FR_BIO_DEDUP_STATE_PARTIAL) ||
		  (item->state == FR_BIO_DEDUP_STATE_CANCELLED));

	rcode = fr_bio_dedup_buffer_write(my);
	if (rcode <= 0) return rcode;

	my->partial = NULL;

	/*
	 *	Partial writes are removed from the expiry tree until they're fully written.  When they're
	 *	written, either add it back to the tree if it's still operational, or add it to the free list
	 *	if it has been cancelled.
	 */
	if (item->state == FR_BIO_DEDUP_STATE_PARTIAL) {

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
			item->state = FR_BIO_DEDUP_STATE_ACTIVE;
			(void) fr_rb_insert(&my->rb, item);
		}
		(void) fr_bio_dedup_timer_reset(my);

	} else {
		/*
		 *	The item was cancelled, add it to the free list.
		 */
#ifndef NDEBUG
		item->packet = NULL;
#endif
		item->uctx = NULL;
		item->packet_ctx = NULL;

		item->state = FR_BIO_DEDUP_STATE_FREE;
		fr_bio_dedup_list_insert_head(&my->free, item);
	}

	/*
	 *	Flush any packets which were pending during the blocking period.
	 */
	rcode = fr_bio_dedup_flush_pending(my);
	if (rcode < 0) return rcode;

	/*
	 *	Unlike the retry BIO, we don't retry writes for items in the RB tree.  Those packets have already
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

	if (fr_bio_dedup_buffer_save(my, item->reply, item->reply_size, rcode) < 0) return fr_bio_error(OOM);

	switch (item->state) {
	case FR_BIO_DEDUP_STATE_ACTIVE:
		(void) fr_bio_dedup_list_remove(&my->active, item);
		break;

		/*
		 *	We cannot expire this entry, so remove it from the expiration tree.  That step lets us
		 *	expire other entries.
		 */
	case FR_BIO_DEDUP_STATE_REPLIED:
		(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
		fr_bio_dedup_timer_reset_item(my, item);
		break;

		/*
		 *	We tried to write a pending packet and got blocked.
		 */
	case FR_BIO_DEDUP_STATE_PENDING:
		fr_assert(fr_bio_dedup_list_head(&my->pending) == item);
		(void) fr_bio_dedup_list_remove(&my->pending, item);
		break;

		/*
		 *	None of these states should be possible.
		 */
	case FR_BIO_DEDUP_STATE_PARTIAL:
	case FR_BIO_DEDUP_STATE_CANCELLED:
	case FR_BIO_DEDUP_STATE_FREE:
		fr_assert(0);
		return fr_bio_error(GENERIC);
	}

	my->partial = item;
	item->state = FR_BIO_DEDUP_STATE_PENDING;

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

	fr_assert(!my->partial);

	/*
	 *	Flush out any partly written data.
	 */
	rcode = fr_bio_dedup_buffer_write(my);
	if (rcode <= 0) return rcode;

	/*
	 *	Flush any packets which were pending during the blocking period.
	 */
	rcode = fr_bio_dedup_flush_pending(my);
	if (rcode < 0) return rcode;

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

	if (fr_bio_dedup_buffer_save(my, buffer, size, rcode) < 0) return fr_bio_error(OOM);

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
 *  @todo - expire items from the pending list, too
 */
static void fr_bio_dedup_timer(UNUSED fr_timer_list_t *tl, fr_time_t now, void *uctx)
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
	 *
	 *	@todo - also expire entries on the pending list?
	 */
	expires = fr_time_add(now, fr_time_delta_from_msec(10));

	while ((item = fr_rb_first(&my->rb)) != NULL) {
		if (fr_time_gt(item->expires, expires)) break;

		fr_bio_dedup_release(my, item, FR_BIO_DEDUP_EXPIRED);
	}

	(void) fr_bio_dedup_timer_reset(my);
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

	/*
	 *	We need the item pointer to mark this entry as blocked.  If that doesn't exist, then we try
	 *	really hard to write out the un-tracked data.
	 */
	item = NULL;
	if (my->get_item) item = my->get_item(bio, packet_ctx);
	if ((size_t) rcode == size) {
		if (item) fr_bio_dedup_replied(my, item);
		return rcode;
	}

	if (!item) return fr_bio_dedup_blocked_data(my, buffer, size, rcode);

	fr_assert(item->reply_ctx == packet_ctx);
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
	 *	Get a free item
	 */
	item = fr_bio_dedup_list_pop_head(&my->free);
	fr_assert(item != NULL);

	fr_assert(item->my == my);
	*item = (fr_bio_dedup_entry_t) {
		.my = my,
		.packet_ctx = packet_ctx,
		.packet = buffer,
		.packet_size = (size_t) rcode,
		.state = FR_BIO_DEDUP_STATE_ACTIVE,
	};

	/*
	 *	See if we want to receive this packet.  If this isn't
	 *	something we need to receive, then we just discard it.
	 *
	 *	The "receive" function is responsible for looking in a local dedup tree to see if there's a
	 *	cached reply.  It's also responsible for calling the fr_bio_retry_respond() function to send
	 *	a duplicate reply, and then return "don't receive" this packet.
	 *
	 *	The application can alos call fr_bio_dedup_entry_extend() in order to extend the lifetime of a
	 *	packet which has a cached response.
	 *
	 *	If there's an active packet, then the receive() function should do whatever it needs to do in
	 *	order to update the application for a duplicate packet.  And then return "don't receive" for
	 *	this packet.
	 *
	 *	If we're NOT going to process this packet, then the item we just popped needs to get inserted
	 *	back into the free list.
	 *
	 *	The caller should cancel any conflicting packets by calling fr_bio_dedup_entry_cancel().  Note
	 *	that for sanity, we don't re-use the previous #fr_bio_dedup_entry_t.
	 */
	if (!my->receive(bio, item, packet_ctx)) {
		item->state = FR_BIO_DEDUP_STATE_FREE;
		fr_bio_dedup_list_insert_head(&my->free, item);
		return 0;
	}

	fr_bio_dedup_list_insert_tail(&my->active, item);

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
 */
void fr_bio_dedup_entry_cancel(fr_bio_t *bio, fr_bio_dedup_entry_t *item)
{
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);

	fr_assert(item->state != FR_BIO_DEDUP_STATE_FREE);

	fr_bio_dedup_release(my, item, FR_BIO_DEDUP_CANCELLED);
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

	switch (item->state) {
	case FR_BIO_DEDUP_STATE_ACTIVE:
		return 0;

	case FR_BIO_DEDUP_STATE_REPLIED:
		break;

	/*
	 *	Partially written or pending replies aren't in the expirty tree.  We can just change their
	 *	expiry time and be done.
	 */
	case FR_BIO_DEDUP_STATE_PARTIAL:
	case FR_BIO_DEDUP_STATE_PENDING:
		item->expires = expires;
		return 0;

	case FR_BIO_DEDUP_STATE_CANCELLED:
	case FR_BIO_DEDUP_STATE_FREE:
		fr_assert(0);
		return fr_bio_error(GENERIC);
	}

	/*
	 *	Shortening the lifetime is OK.  If the caller does something dumb like set expiry to a time in
	 *	the past, well... that's their problem.
	 */
	fr_assert(fr_time_lteq(expires, fr_time()));

	/*
	 *	Change places in the tree.
	 */
	item->expires = expires;
	(void) fr_rb_remove_by_inline_node(&my->rb, &item->node);
	(void) fr_rb_insert(&my->rb, item);

	/*
	 *	If we're not changing the first item, we don't need to change the timers.
	 *
	 *	Otherwise we clear the "first" flag, so that the reset timer function will change the timer
	 *	value.
	 */
	if (my->first != item) return 0;

	my->first = NULL;

	return fr_bio_dedup_timer_reset(my);
}


/**  Remove the dedup cache
 *
 */
static int fr_bio_dedup_shutdown(fr_bio_t *bio)
{
	fr_rb_iter_inorder_t iter;
	fr_bio_dedup_entry_t *item;
	fr_bio_dedup_t *my = talloc_get_type_abort(bio, fr_bio_dedup_t);

	talloc_const_free(my->ev);

	/*
	 *	Cancel all outgoing packets.  Don't bother updating the tree or the free list, as all of the
	 *	entries will be deleted when the memory is freed.
	 */
	while ((item = fr_rb_iter_init_inorder(&my->rb, &iter)) != NULL) {
		fr_rb_iter_delete_inorder(&my->rb, &iter);
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
		items[i].state = FR_BIO_DEDUP_STATE_FREE;
		fr_bio_dedup_list_insert_tail(&my->free, &items[i]);
	}

	fr_bio_dedup_list_init(&my->active);
	fr_bio_dedup_list_init(&my->pending);

	(void) fr_rb_inline_init(&my->rb, fr_bio_dedup_entry_t, node, _entry_cmp, NULL);

	my->receive = receive;
	my->release = release;
	my->get_item = get_item;

	my->el = cfg->el;
	my->config = *cfg;

	my->bio.write = fr_bio_dedup_write;
	my->bio.read = fr_bio_dedup_read;

	fr_bio_chain(&my->bio, next);

	my->priv_cb.shutdown = fr_bio_dedup_shutdown;

	talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor); /* always use a common destructor */

	return (fr_bio_t *) my;
}
