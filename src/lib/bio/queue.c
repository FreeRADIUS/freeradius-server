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
 * @file lib/bio/queue.c
 * @brief Binary IO abstractions for queues of raw packets
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/queue.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/util/dlist.h>

typedef struct fr_bio_queue_list_s	fr_bio_queue_list_t;
typedef struct fr_bio_queue_s		fr_bio_queue_t;

/*
 *	Define type-safe wrappers for head and entry definitions.
 */
FR_DLIST_TYPES(fr_bio_queue_list)

/*
 *	For delayed writes.
 *
 *	@todo - we can remove the "cancelled" field by setting packet_ctx == my?
 */
struct fr_bio_queue_entry_s {
	void		*packet_ctx;
	void const	*buffer;
	size_t		size;
	size_t		already_written;
	bool		cancelled;

	fr_bio_queue_t *my;

	FR_DLIST_ENTRY(fr_bio_queue_list)	entry;		//!< List entry.
};

FR_DLIST_FUNCS(fr_bio_queue_list, fr_bio_queue_entry_t, entry)

typedef struct fr_bio_queue_s {
	FR_BIO_COMMON;

	size_t				max_saved;

	fr_bio_queue_saved_t		saved;
	fr_bio_queue_callback_t		sent;
	fr_bio_queue_callback_t		cancel;

	FR_DLIST_HEAD(fr_bio_queue_list)	pending;
	FR_DLIST_HEAD(fr_bio_queue_list)	free;

	fr_bio_queue_entry_t		array[];
} fr_bio_queue_t;

static ssize_t fr_bio_queue_write_buffer(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);

/** Forcibly cancel all outstanding packets.
 *
 *  Even partially written ones.  This function is called from
 *  shutdown(), when the destructor is called, or on fatal read / write
 *  errors.
 */
static void fr_bio_queue_list_cancel(fr_bio_queue_t *my)
{
	fr_bio_queue_entry_t *item;

	my->bio.read = fr_bio_fail_read;
	my->bio.write = fr_bio_fail_write;

	if (!my->cancel) return;

	if (fr_bio_queue_list_num_elements(&my->pending) == 0) return;

	/*
	 *	Cancel any remaining saved items.
	 */
	while ((item = fr_bio_queue_list_pop_head(&my->pending)) != NULL) {
		my->cancel(&my->bio, item->packet_ctx, item->buffer, item->size);
		item->cancelled = true;
		fr_bio_queue_list_insert_head(&my->free, item);
	}
}

static int fr_bio_queue_destructor(fr_bio_queue_t *my)
{
	fr_assert(my->cancel);	/* otherwise it would be fr_bio_destructor */

	fr_bio_queue_list_cancel(my);

	return 0;
}

/** Push a packet onto a list.
 *
 */
static ssize_t fr_bio_queue_list_push(fr_bio_queue_t *my, void *packet_ctx, const void *buffer, size_t size, size_t already_written)
{
	fr_bio_queue_entry_t	*item;

	item = fr_bio_queue_list_pop_head(&my->free);
	if (!item) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	If we're the first entry in the saved list, we can have a partially written packet.
	 *
	 *	Otherwise, we're a subsequent entry, and we cannot have any data which is partially written.
	 */
	fr_assert((fr_bio_queue_list_num_elements(&my->pending) == 0) ||
		  (already_written == 0));

	item->packet_ctx = packet_ctx;
	item->buffer = buffer;
	item->size = size;
	item->already_written = already_written;
	item->cancelled = false;

	fr_bio_queue_list_insert_tail(&my->pending, item);

	if (my->saved) my->saved(&my->bio, packet_ctx, buffer, size, item);

	return size;
}

/** Write one packet to the next bio.
 *
 *  If it blocks, save the packet and return OK to the caller.
 */
static ssize_t fr_bio_queue_write_next(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_queue_t *my = talloc_get_type_abort(bio, fr_bio_queue_t);
	fr_bio_t *next;

	/*
	 *	We can't call the next bio if there's still cached data to flush.
	 */
	fr_assert(fr_bio_queue_list_num_elements(&my->pending) == 0);

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Write the data out.  If we write all of it, we're done.
	 */
	rcode = next->write(next, packet_ctx, buffer, size);
	if ((size_t) rcode == size) return rcode;

	if (rcode < 0) {
		/*
		 *	A non-blocking error: return it back up the chain.
		 */
		if (rcode != fr_bio_error(IO_WOULD_BLOCK)) return rcode;

		/*
		 *	All other errors are fatal.
		 */
		fr_bio_queue_list_cancel(my);
		return rcode;
	}

	/*
	 *	We were flushing the next buffer, return any data which was written.
	 */
	if (!buffer) return rcode;

	/*
	 *	The next bio wrote a partial packet.  Save the entire packet, and swap the write function to
	 *	save all future packets in the saved list.
	 */
	bio->write = fr_bio_queue_write_buffer;

	fr_assert(fr_bio_queue_list_num_elements(&my->free) > 0);

	/*
	 *	This can only error out if the free list has no more entries.
	 */
	return fr_bio_queue_list_push(my, packet_ctx, buffer, size, (size_t) rcode);
}

/** Flush the packet list.
 *
 */
static ssize_t fr_bio_queue_write_flush(fr_bio_queue_t *my, size_t size)
{
	size_t written;
	fr_bio_t *next;

	if (fr_bio_queue_list_num_elements(&my->pending) == 0) {
		my->bio.write = fr_bio_queue_write_next;
		return 0;
	}

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Loop over the saved packets, flushing them to the next bio.
	 */
	written = 0;
	while (written < size) {
		ssize_t rcode;
		fr_bio_queue_entry_t *item;

		/*
		 *	No more saved packets to write: stop.
		 */
		item = fr_bio_queue_list_head(&my->pending);
		if (!item) break;

		/*
		 *	A cancelled item must be partially written.  A cancelled item which has zero bytes
		 *	written should not be in the saved list.
		 */
		fr_assert(!item->cancelled || (item->already_written > 0));

		/*
		 *	Push out however much data we can to the next bio.
		 */
		rcode = next->write(next, item->packet_ctx, ((uint8_t const *) item->buffer) + item->already_written, item->size - item->already_written);
		if (rcode == 0) break;

		if (rcode < 0) {
			if (rcode == fr_bio_error(IO_WOULD_BLOCK)) break;

			return rcode;
		}

		/*
		 *	Update the written count.
		 */
		written += rcode;
		item->already_written += rcode;

		if (item->already_written < item->size) break;

		/*
		 *	We don't run "sent" callbacks for cancelled items.
		 */
		if (item->cancelled) {
			if (my->cancel) my->cancel(&my->bio, item->packet_ctx, item->buffer, item->size);
		} else {
			if (my->sent) my->sent(&my->bio, item->packet_ctx, item->buffer, item->size);
		}

		(void) fr_bio_queue_list_pop_head(&my->pending);
#ifndef NDEBUG
		item->buffer = NULL;
		item->packet_ctx = NULL;
		item->size = 0;
		item->already_written = 0;
#endif
		item->cancelled = true;

		fr_bio_queue_list_insert_head(&my->free, item);
	}

	/*
	 *	If we've written all of the saved packets, go back to writing to the "next" bio.
	 */
	if (fr_bio_queue_list_head(&my->pending)) my->bio.write = fr_bio_queue_write_next;

	return written;
}

/** Write to the packet list buffer.
 *
 *  The special buffer pointer of NULL means flush().  On flush, we call next->read(), and if that succeeds,
 *  go back to "pass through" mode for the buffers.
 */
static ssize_t fr_bio_queue_write_buffer(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	fr_bio_queue_t *my = talloc_get_type_abort(bio, fr_bio_queue_t);

	if (!buffer) return fr_bio_queue_write_flush(my, size);

	/*
	 *	This can only error out if the free list has no more entries.
	 */
	return fr_bio_queue_list_push(my, packet_ctx, buffer, size, 0);
}

/**  Read one packet from next bio.
 *  
 *  This function does NOT respect packet boundaries.  The caller should use other APIs to determine how big
 *  the "next" packet is.
 *
 *  The caller may buffer the output data itself, or it may use other APIs to do checking.
 *
 *  The main
 */
static ssize_t fr_bio_queue_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	int rcode;
	fr_bio_queue_t *my = talloc_get_type_abort(bio, fr_bio_queue_t);
	fr_bio_t *next;

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->read(next, packet_ctx, buffer, size);
	if (rcode >= 0) return rcode;

	/*
	 *	We didn't read anything, return that.
	 */
	if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return rcode;

	/*
	 *	Error reading, which means that we can't write to it, either.  We don't care if the error is
	 *	EOF or anything else.  We just cancel the outstanding packets, and shut ourselves down.
	 */
	fr_bio_queue_list_cancel(my);
	return rcode;
}

/** Shutdown
 *
 *  Cancel / close has to be called before re-init.
 */
static void fr_bio_queue_shutdown(fr_bio_t *bio)
{
	fr_bio_queue_t *my = talloc_get_type_abort(bio, fr_bio_queue_t);

	fr_bio_queue_list_cancel(my);
}


/** Allocate a packet-based bio.
 *
 *  This bio assumes that each call to fr_bio_write() is for one packet, and only one packet.  If the next bio
 *  returns a partial write, or WOULD BLOCK, then information about the packet is cached.  Subsequent writes
 *  will write the partial data first, and then continue with subsequent writes.
 *
 *  The caller is responsible for not freeing the packet ctx or the packet buffer until either the write has
 *  been performed, or the write has been cancelled.
 *
 *  The read() API makes no provisions for reading complete packets.  It simply returns whatever the next bio
 *  allows.  If instead there is a need to read only complete packets, then the next bio should be
 *  fr_bio_mem_alloc() with a fr_bio_mem_set_verify()
 *
 *  The read() API may return 0.  There may have been data read from an underlying FD, but that data did not
 *  make it through the filters of the "next" bios.  e.g. Any underlying FD should be put into a "wait for
 *  readable" state.
 *
 *  The write() API will return a full write, even if the next layer is blocked.  Any underlying FD
 *  should be put into a "wait for writeable" state.  The packet which was supposed to be written has been
 *  cached, and cannot be cancelled as it is partially written.  The caller should likely start using another
 *  bio for writes.  If the caller continues to use the bio, then any subsequent writes will *always* cache
 *  the packets. @todo - we need to mark up the bio as "blocked", and then have a write_blocked() API?  ugh.
 *  or just add `bool blocked` and `bool eof` to both read/write bios
 *
 *  Once the underlying FD has become writeable, the caller should call fr_bio_write(bio, NULL, NULL, SIZE_MAX);
 *  That will cause the pending packets to be flushed.
 *
 *  The write() API may return that it's written a full packet, in which case it's either completely written to
 *  the next bio, or to the pending queue.
 *
 *  The read / write APIs can return WOULD_BLOCK, in which case nothing was done.  Any underlying FD should be
 *  put into a "wait for writeable" state.  Other errors from bios "further down" the chain can also be
 *  returned.
 *
 *  @param ctx		the talloc ctx
 *  @param max_saved	Maximum number of packets to cache.  Must be 1..1^17
 *  @param saved	callback to run when a packet is saved in the pending queue
 *  @param sent		callback to run when a packet is sent.
 *  @param cancel      	callback to run when a packet is cancelled.
 *  @param next		the next bio which will perform the underlying reads and writes.
 *	- NULL on error, memory allocation failed
 *	- !NULL the bio
 */
fr_bio_t *fr_bio_queue_alloc(TALLOC_CTX *ctx, size_t max_saved,
			      fr_bio_queue_saved_t saved,
			      fr_bio_queue_callback_t sent,
			      fr_bio_queue_callback_t cancel,
			      fr_bio_t *next)
{
	size_t i;
	fr_bio_queue_t *my;

	if (!max_saved) max_saved = 1;
	if (max_saved > (1 << 17)) max_saved = 1 << 17;

	my = (fr_bio_queue_t *) talloc_zero_array(ctx, uint8_t, sizeof(fr_bio_queue_t) +
						   sizeof(fr_bio_queue_entry_t) * max_saved);
	if (!my) return NULL;

	talloc_set_type(my, fr_bio_queue_t);

	my->max_saved = max_saved;

	fr_bio_queue_list_init(&my->pending);
	fr_bio_queue_list_init(&my->free);

	my->saved = saved;
	my->sent = sent;
	my->cancel = cancel;

	for (i = 0; i < max_saved; i++) {
		my->array[i].my = my;
		my->array[i].cancelled = true;
		fr_bio_queue_list_insert_tail(&my->free, &my->array[i]);
	}

	my->bio.read = fr_bio_queue_read;
	my->bio.write = fr_bio_queue_write_next;
	my->cb.shutdown = fr_bio_queue_shutdown;

	fr_bio_chain(&my->bio, next);

	if (my->cancel) {
		talloc_set_destructor(my, fr_bio_queue_destructor);
	} else {
		talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor);
	}

	return (fr_bio_t *) my;
}

/** Cancel the write for a packet.
 *
 *  Cancel one a saved packets, and call the cancel() routine if it exists.
 *
 *  There is no way to cancel all packets.  The caller must find the lowest bio in the chain, and shutdown it.
 *  e.g. by closing the socket via fr_bio_fd_close().  That function will take care of walking back up the
 *  chain, and shutting down each bio.
 *
 *  @param	bio	the #fr_bio_queue_t
 *  @param	item	The context returned from #fr_bio_queue_saved_t
 *  @return
 *	- <0 no such packet was found in the list of saved packets, OR the packet cannot be cancelled.
 *	- 0 the packet was cancelled.
 */
int fr_bio_queue_cancel(fr_bio_t *bio, fr_bio_queue_entry_t *item)
{
	fr_bio_queue_t *my = talloc_get_type_abort(bio, fr_bio_queue_t);

	if (!(item >= &my->array[0]) && (item < &my->array[my->max_saved])) {
		return -1;
	}

	/*
	 *	Already cancelled, that's a NOOP.
	 */
	if (item->cancelled) return 0;

	/*
	 *	If the item has been partially written, AND we have a working write function, see if we can
	 *	cancel it.
	 */
	if (item->already_written && (my->bio.write != fr_bio_null_write)) {
		ssize_t rcode;
		fr_bio_t *next;

		next = fr_bio_next(bio);
		fr_assert(next != NULL);

		/*
		 *	If the write fails or returns nothing, the item can't be cancelled.
		 */
		rcode = next->write(next, item->packet_ctx, ((uint8_t const *) item->buffer) + item->already_written, item->size - item->already_written);
		if (rcode <= 0) return -1;

		/*
		 *	If we haven't written the full item, it can't be cancelled.
		 */
		item->already_written += rcode;
		if (item->already_written < item->size) return -1;

		/*
		 *	Else the item has been fully written, it can be safely cancelled.
		 */
	}

	/*
	 *	Remove it from the saved list, and run the cancellation callback.
	 */
	(void) fr_bio_queue_list_remove(&my->pending, item);
	fr_bio_queue_list_insert_head(&my->free, item);

	if (my->cancel) my->cancel(bio, item->packet_ctx, item->buffer, item->size);

	return 0;
}
