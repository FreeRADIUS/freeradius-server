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
 * @brief Messages for inter-thread communication
 * @file io/message.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/message.h>
#include <freeradius-devel/util/strerror.h>

#include <string.h>

/*
 *	Debugging, mainly for message_set_test
 */
#if 0
#define MPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

#define MSG_ARRAY_SIZE (16)

/** A Message set, composed of message headers and ring buffer data.
 *
 *  A message set is intended to send short-lived messages.  The
 *  message headers are fixed in size, and allocated from an array
 *  which is treated like a circular buffer.  Message bodies (i.e. raw
 *  packets) are variable in size, and live in a separate ring buffer.
 *
 *  The message set starts off with a small array of message headers,
 *  and a small ring buffer.  If an array/buffer fills up, a new one
 *  is allocated at double the size of the previous one.
 *
 * The array / buffers are themselves kept in fixed-size arrays, of
 *  MSG_ARRAY_SIZE.  The reason is that the memory for fr_message_set_t
 *  should be contiguous, and not in a linked list scattered in
 *  memory.
 *
 *  The originator allocates a message, and sends it to a recipient.
 *  The recipient (usually in another thread) uses the message, and
 *  marks it as FR_MESSAGE_DONE.  The originator then asynchronously
 *  cleans up the message.
 *
 *  This asynchronous cleanup is done via self-clocking.  If there is
 *  no need to clean up the messages, it isn't done.  Only when we run
 *  out of space to store messages (or packets) is the cleanup done.
 *
 *  This cleanup latency ensures that we don't have cache line
 *  bouncing, where the originator sends the message, and then while
 *  the recipieent is reading it... thrashes the cache line with
 *  checks for "are you done?  Are you done?"
 *
 *  If there are more than one used entry in either array, we then try
 *  to coalesce the buffers on cleanup.  If we discover that one array
 *  is empty, we discard it, and move the used array entries into it's
 *  place.
 *
 *  This process ensures that we don't have too many buffers in
 *  progress.  It is better to have a few large buffers than many
 *  small ones.
 *
 *  MSG_ARRAY_SIZE is defined to be large (16 doublings) to allow for
 *  the edge case where messages are stuck for long periods of time.
 *
 *  With an initial message array size of 64, this gives us room for
 *  2M packets, if *all* of the mr_array entries have packets stuck in
 *  them that aren't cleaned up for extended periods of time.
 *
 *  @todo Add a flag for UDP-style protocols, where we can put the
 *  message into the ring buffer.  This helps with locality of
 *  reference, and removes the need to track two separate things.
 */
struct fr_message_set_s {
	int			mr_current;	//!< current used message ring entry
	int			mr_max;		//!< max used message ring entry

	size_t			message_size;	//!< size of the callers message, including fr_message_t

	int			mr_cleaned;	//!< where we last cleaned

	int			rb_current;	//!< current used ring buffer entry
	int			rb_max;		//!< max used ring buffer entry

	size_t			max_allocation;	//!< maximum allocation size

	int			allocated;
	int			freed;

	fr_ring_buffer_t	*mr_array[MSG_ARRAY_SIZE]; //!< array of message arrays

	fr_ring_buffer_t	*rb_array[MSG_ARRAY_SIZE]; //!< array of ring buffers
};


/** Create a message set
 *
 * @param[in] ctx the context for talloc
 * @param[in] num_messages size of the initial message array.  MUST be a power of 2.
 * @param[in] message_size the size of each message, INCLUDING fr_message_t, which MUST be at the start of the struct
 * @param[in] ring_buffer_size of the ring buffer.  MUST be a power of 2.
 * @return
 *	- NULL on error
 *	- newly allocated fr_message_set_t on success
 */
fr_message_set_t *fr_message_set_create(TALLOC_CTX *ctx, int num_messages, size_t message_size, size_t ring_buffer_size)
{
	fr_message_set_t *ms;

	/*
	 *	Too small, or not a power of 2.
	 */
	if (num_messages < 8) num_messages = 8;

	if ((num_messages & (num_messages - 1)) != 0) {
		fr_strerror_printf("Number of messages must be a power of 2");
		return NULL;
	}

	if (message_size < sizeof(fr_message_t)) {
		fr_strerror_printf("Message size must be at least %zd", sizeof(fr_message_t));
		return NULL;
	}

	if (message_size > 1024) {
		fr_strerror_printf("Message size must be no larger than 1024");
		return NULL;
	}

	ms = talloc_zero(ctx, fr_message_set_t);
	if (!ms) {
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	message_size += 15;
	message_size &= ~(size_t) 15;
	ms->message_size = message_size;

	ms->rb_array[0] = fr_ring_buffer_create(ms, ring_buffer_size);
	if (!ms->rb_array[0]) {
		talloc_free(ms);
		return NULL;
	}
	ms->rb_max = 0;

	ms->mr_array[0] = fr_ring_buffer_create(ms, num_messages * message_size);
	if (!ms->mr_array[0]) {
		talloc_free(ms);
		return NULL;
	}

	ms->max_allocation = ring_buffer_size / 2;

	return ms;
}


/** Mark a message as done
 *
 *  Note that this call is usually done from a thread OTHER than the
 *  originator of the message.  As such, the message is NOT actually
 *  freed.  Instead, it is just marked as freed.
 *
 * @param[in] m the message to make as done.
 * @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_message_done(fr_message_t *m)
{
	rad_assert(m->status != FR_MESSAGE_FREE);
	rad_assert(m->status != FR_MESSAGE_DONE);

	/*
	 *	Mark a message as freed.  The originator will take
	 *	care of cleaning it up.
	 */
	if (m->status == FR_MESSAGE_USED) {
		m->status = FR_MESSAGE_DONE;
		return 0;
	}

	/*
	 *	This message was localized, so we can free it via
	 *	talloc.
	 */
	if (m->status == FR_MESSAGE_LOCALIZED) {
		talloc_free(m);
		return 0;
	}

	/*
	 *	A catastrophic error.
	 */
	rad_assert(0 == 1);

	fr_strerror_printf("Failed marking message as done");
	return -1;
}


/** Localize a message by copying it to local storage
 *
 *  This function "localizes" a message by copying it to local
 *  storage.  In the case where the recipient of a message has to sit
 *  on it for a while, that blocks the originator from cleaning up the
 *  message.  The recipient can then copy the message to local
 *  storage, so that the originator can clean it up.
 *
 *  The localized message is marked as FR_MESSAGE_LOCALIZED, so that
 *  the recipient can call the normal fr_message_done() function to
 *  free it.
 *
 * @param[in] ctx the talloc context to use for localization
 * @param[in] m the message to be localized
 * @param[in] message_size the size of the message, including the fr_message_t
 * @return
 *	- NULL on allocation errror
 *	- a newly localized message
 */
fr_message_t *fr_message_localize(TALLOC_CTX *ctx, fr_message_t *m, size_t message_size)
{
	fr_message_t *l;

	if (m->status != FR_MESSAGE_USED) {
		fr_strerror_printf("Cannot localize message unless it is in use");
		return NULL;
	}

	if (message_size <= sizeof(fr_message_t)) {
		fr_strerror_printf("Message size is too small");
		return NULL;
	}

	l = talloc_memdup(ctx, m, message_size);
	if (!l) {
	nomem:
		fr_strerror_printf("Failed allocating memory");
		return NULL;
	}

	l->data = NULL;

	if (l->data_size) {
		l->data = talloc_memdup(l, m->data, l->data_size);
		if (!l->data) {
			talloc_free(l);
			goto nomem;
		}
	}

	l->status = FR_MESSAGE_LOCALIZED;

	/*
	 *	After this change, "m" should not be used for
	 *	anything.
	 */
	m->status = FR_MESSAGE_DONE;

	/*
	 *	Now clean up the other fields of the newly localized
	 *	message.
	 */
	l->rb = NULL;
	l->rb_size = 0;

	return l;
}


/** Clean up messages in a message ring.
 *
 *  Find the oldest messages which are marked FR_MESSAGE_DONE,
 *  and mark them FR_MESSAGE_FREE.
 *
 *  FIXME: If we care, track which ring buffer is in use, and how
 *  many contiguous chunks we can free.  Then, free the chunks at
 *  once, instead of piecemeal.  Realistically tho... this will
 *  probably make little difference.
 *
 * @param[in] ms the message set
 * @param[in] mr the message ring
 * @param[in] max_to_clean maximum number of messages to clean at a time.
 */
static int fr_message_ring_gc(fr_message_set_t *ms, fr_ring_buffer_t *mr, int max_to_clean)
{
	int messages_cleaned = 0;
	size_t size;
	fr_message_t *m;

	while (true) {
		(void) fr_ring_buffer_start(mr, (uint8_t **) &m, &size);
		if (size == 0) break;

		rad_assert(m != NULL);
		rad_assert(size >= ms->message_size);


		rad_assert(m->status != FR_MESSAGE_FREE);
		if (m->status != FR_MESSAGE_DONE) break;

		messages_cleaned++;
		m->status = FR_MESSAGE_FREE;
		ms->freed++;

		if (m->rb) {
			(void) fr_ring_buffer_free(m->rb, m->rb_size);
#ifndef NDEBUG
			memset(m, 0, ms->message_size);
#endif
		}

		fr_ring_buffer_free(mr, ms->message_size);

		if (messages_cleaned >= max_to_clean) break;
	}

	MPRINT("CLEANED %d (%p) left\n", messages_cleaned, mr);
	return messages_cleaned;
}


/** Garbage collect "done" messages.
 *
 *  Called only from the originating thread.  We also clean a limited
 *  number of messages at a time, so that we don't have sudden latency
 *  spikes when cleaning 1M messages.
 *
 * @param[in] ms the message set
 * @param[in] max_to_clean the maximum number of messages to clean
 */
static void fr_message_gc(fr_message_set_t *ms, int max_to_clean)
{
	int i;
	int arrays_freed, arrays_used, empty_slot;
	int largest_free_slot;
	int total_cleaned;
	size_t largest_free_size;

	/*
	 *	Clean up "done" messages.
	 */
	total_cleaned = 0;

	/*
	 *	Garbage collect the smaller buffers first.
	 */
	for (i = 0; i <= ms->mr_max; i++) {
		int cleaned;

		cleaned = fr_message_ring_gc(ms, ms->mr_array[i], max_to_clean - total_cleaned);
		total_cleaned += cleaned;
		rad_assert(total_cleaned <= max_to_clean);

		/*
		 *	Stop when we've reached our GC limit.
		 */
		if (total_cleaned == max_to_clean) break;
	}

	/*
	 *	Couldn't GC anything.  Don't do more work.
	 */
	if (total_cleaned == 0) return;

	arrays_freed = 0;
	arrays_used = 0;

	/*
	 *	Keep the two largest message buffers (used or not),
	 *	and free all smaller ones which are empty.
	 */
	for (i = ms->mr_max; i >= 0; i--) {
		rad_assert(ms->mr_array[i] != NULL);

		if (arrays_used < 2) {
			MPRINT("\tleaving entry %d alone\n", i);
			arrays_used++;
			continue;
		}

		/*
		 *	If the message ring buffer is empty, check if
		 *	we should perhaps delete it.
		 */
		if (fr_ring_buffer_used(ms->mr_array[i]) == 0) {
			MPRINT("\tfreeing entry %d\n", i);
			TALLOC_FREE(ms->mr_array[i]);
			arrays_freed++;
			continue;
		}

		MPRINT("\tstill in use entry %d\n", i);
	}

	/*
	 *	Some entries have been freed.  We need to coalesce the
	 *	remaining entries.
	 */
	if (arrays_freed) {
		MPRINT("TRYING TO PACK from %d free arrays out of %d\n", arrays_freed, ms->rb_max + 1);

		empty_slot = -1;

		/*
		 *	Pack the rb array by moving used entries to
		 *	the bottom of the array.
		 */
		for (i = 0; i <= ms->mr_max; i++) {
			int j;

			/*
			 *	Skip over empty entries, but set
			 *	"empty_slot" to the first empty on we
			 *	found.
			 */
			if (!ms->mr_array[i]) {
				if (empty_slot < 0) empty_slot = i;

				continue;
			}

			/*
			 *	This array entry is used, but there is
			 *	no empty slot to put it into.  Ignore
			 *	it, and continue
			 */
			if (empty_slot < 0) continue;

			rad_assert(ms->mr_array[empty_slot] == NULL);

			ms->mr_array[empty_slot] = ms->mr_array[i];
			ms->mr_array[i] = NULL;

			/*
			 *	Find the next empty slot which is
			 *	greater than the one we just used.
			 */
			for (j = empty_slot + 1; j <= i; j++) {
				if (!ms->mr_array[j]) {
					empty_slot = j;
					break;
				}
			}
		}

		/*
		 *	Lower max, and set current to the largest
		 *	array, whether or not it's used.
		 */
		ms->mr_max -= arrays_freed;
		ms->mr_current = ms->mr_max;

#ifndef NDEBUG
		MPRINT("NUM RB ARRAYS NOW %d\n", ms->mr_max + 1);
		for (i = 0; i <= ms->mr_max; i++) {
			MPRINT("\t%d %p\n", i, ms->mr_array[i]);
			rad_assert(ms->mr_array[i] != NULL);
		}
#endif
	}

	/*
	 *	And now we do the same thing for the ring buffers.
	 *	Except that freeing the messages above also cleaned up
	 *	the contents of each ring buffer, so all we need to do
	 *	is find the largest empty ring buffer.
	 *
	 *	We do this by keeping the two largest ring buffers
	 *	(used or not), and then freeing all smaller ones which
	 *	are empty.
	 */
	arrays_used = 0;
	arrays_freed = 0;
	MPRINT("TRYING TO FREE ARRAYS %d\n", ms->rb_max);
	for (i = ms->rb_max; i >= 0; i--) {
		rad_assert(ms->rb_array[i] != NULL);

		if (arrays_used < 2) {
			MPRINT("\tleaving entry %d alone\n", i);
			arrays_used++;
			continue;
		}

		if (fr_ring_buffer_used(ms->rb_array[i]) == 0) {
			MPRINT("\tfreeing entry %d\n", i);
			TALLOC_FREE(ms->rb_array[i]);
			arrays_freed++;
			continue;
		}

		MPRINT("\tstill in use entry %d\n", i);
	}

	/*
	 *	Pack the array entries back down.
	 */
	if (arrays_freed > 0) {
		MPRINT("TRYING TO PACK from %d free arrays out of %d\n", arrays_freed, ms->rb_max + 1);

		empty_slot = -1;

		/*
		 *	Pack the rb array by moving used entries to
		 *	the bottom of the array.
		 */
		for (i = 0; i <= ms->rb_max; i++) {
			int j;

			/*
			 *	Skip over empty entries, but set
			 *	"empty_slot" to the first empty on we
			 *	found.
			 */
			if (!ms->rb_array[i]) {
				if (empty_slot < 0) empty_slot = i;

				continue;
			}

			/*
			 *	This array entry is used, but there is
			 *	no empty slot to put it into.  Ignore
			 *	it, and continue
			 */
			if (empty_slot < 0) continue;

			rad_assert(ms->rb_array[empty_slot] == NULL);

			ms->rb_array[empty_slot] = ms->rb_array[i];
			ms->rb_array[i] = NULL;

			/*
			 *	Find the next empty slot which is
			 *	greater than the one we just used.
			 */
			for (j = empty_slot + 1; j <= i; j++) {
				if (!ms->rb_array[j]) {
					empty_slot = j;
					break;
				}
			}
		}

		/*
		 *	Lower max, and set current to the largest
		 *	array, whether or not it's used.
		 */
		ms->rb_max -= arrays_freed;
		ms->rb_current = ms->rb_max;

#ifndef NDEBUG
		MPRINT("NUM RB ARRAYS NOW %d\n", ms->rb_max + 1);
		for (i = 0; i <= ms->rb_max; i++) {
			MPRINT("\t%d %p\n", i, ms->rb_array[i]);
			rad_assert(ms->rb_array[i] != NULL);
		}
#endif
	}

	/*
	 *	Set the current ring buffer to the one with the
	 *	largest free space in it.
	 *
	 *	This is different from the allocation strategy for
	 *	messages.
	 */
	if (!fr_cond_assert(ms->rb_array[ms->rb_max] != NULL)) return;

	largest_free_slot = ms->rb_max;
	largest_free_size = (fr_ring_buffer_size(ms->rb_array[ms->rb_max]) -
			     fr_ring_buffer_used(ms->rb_array[ms->rb_max]));

	for (i = 0; i < ms->rb_max; i++) {
		size_t free_size;

		rad_assert(ms->rb_array[i] != NULL);

		free_size = (fr_ring_buffer_size(ms->rb_array[i]) -
			     fr_ring_buffer_used(ms->rb_array[i]));
		if (largest_free_size < free_size) {
			largest_free_slot = i;
			largest_free_size = free_size;
		}
	}

	ms->rb_current = largest_free_slot;
	rad_assert(ms->rb_current >= 0);
	rad_assert(ms->rb_current <= ms->rb_max);
}

/** Allocate a message from a message ring.
 *
 * The newly allocated message is zeroed.
 *
 * @param[in] ms the message set
 * @param[in] mr the message ring to allocate from
 * @param[in] clean whether to clean the message ring
 * @return
 *	- NULL on failed allocation
 *      - fr_message_t* on successful allocation.
 */
static fr_message_t *fr_message_ring_alloc(fr_message_set_t *ms, fr_ring_buffer_t *mr, bool clean)
{
	fr_message_t *m;

	/*
	 *	We're at the start of a buffer with data, and there's
	 *	no room.  Do a quick check to see if we can free up
	 *	the oldest entry.  If not, return.
	 *
	 *	Otherwise, fall through to allocating a entry, of
	 *	which there must now be at least one free one.
	 *
	 *	This check results in a small amount of cache line
	 *	thrashing.  But if the buffer is full, it's likely
	 *	that the oldest entry can be freed.  If not, we have a
	 *	small amount of cache thrashing, which should be
	 *	extremely rare.
	 */
	if (clean) {
		if (fr_message_ring_gc(ms, mr, 4) == 0) {
			fr_strerror_printf("No free memory after GC attempt");
			return NULL;
		}

		/*
		 *	Else we cleaned up some entries in this array.
		 *	Go allocate a message.
		 */
	}

	/*
	 *	Grab a new message from the underlying ring buffer.
	 */
	m = (fr_message_t *) fr_ring_buffer_alloc(mr, ms->message_size);
	if (!m) return NULL;

#ifndef NDEBUG
	memset(m, 0, ms->message_size);
#endif
	m->status = FR_MESSAGE_USED;
	return m;
}

/**  Allocate a fr_message_t, WITHOUT a ring buffer.
 *
 * @param[in] ms the message set
 * @param[out] p_cleaned a flag to indicate if we cleaned the message array
 * @return
 *      - NULL on error
 *	- fr_message_t* on success
 */
static fr_message_t *fr_message_get_message(fr_message_set_t *ms, bool *p_cleaned)
{
	int i;
	fr_message_t *m;
	fr_ring_buffer_t *mr;

	ms->allocated++;
	*p_cleaned = false;

	/*
	 *	Grab the current message array.  In the general case,
	 *	there's room, so we grab a message and go find a ring
	 *	buffer.
	 */
	mr = ms->mr_array[ms->mr_current];
	m = (fr_message_t *) fr_ring_buffer_alloc(mr, ms->message_size);
	if (m) {
		memset(m, 0, ms->message_size);
		m->status = FR_MESSAGE_USED;
		MPRINT("ALLOC normal\n");
		return m;
	}

	MPRINT("CLEANING UP (%zd - %zd = %zd)\n", ms->allocated, ms->freed,
		ms->allocated - ms->freed);

	/*
	 *	Else the buffer is full.  Do a global cleanup.
	 */
	fr_message_gc(ms, 128);
	*p_cleaned = true;

	/*
	 *	If we're lucky, the cleanup has given us a new
	 *	"current" buffer, which is empty.  If so, use it.
	 */
	mr = ms->mr_array[ms->mr_current];
	m = fr_message_ring_alloc(ms, mr, true);
	if (m) {
		MPRINT("ALLOC after cleanup\n");
		return m;
	}

	/*
	 *	We've tried two allocations, and both failed.  Brute
	 *	force over all arrays, trying to allocate one
	 *	somewhere... anywhere.  We start from the largest
	 *	array, because that is the one we want to use the
	 *	most.
	 *
	 *	We want to avoid allocations in the smallest array,
	 *	because that array will quickly wrap, and will cause
	 *	us to do cleanups more often.  That also lets old
	 *	entries in the smallest array age out, so that we can
	 *	free the smallest arrays.
	 */
	for (i = ms->mr_max; i >= 0; i--) {
		mr = ms->mr_array[i];

		m = fr_message_ring_alloc(ms, mr, true);
		if (m) {
			ms->mr_current = i;
			MPRINT("ALLOC from changed ring buffer\n");
			MPRINT("SET MR to changed %d\n", ms->mr_current);
			return m;
		}
	}

	/*
	 *	All of the arrays are full.  If we don't have
	 *	room to allocate another array, we're dead.
	 */
	if ((ms->mr_max + 1) >= MSG_ARRAY_SIZE) {
		fr_strerror_printf("All message arrays are full");
		return NULL;
	}

	/*
	 *	Allocate another message ring, double the size
	 *	of the previous maximum.
	 */
	mr = fr_ring_buffer_create(ms, fr_ring_buffer_size(ms->mr_array[ms->mr_max]) * 2);
	if (!mr) {
		fr_strerror_printf_push("Failed allocating ring buffer");
		return NULL;
	}

	/*
	 *	Set the new one as current for all new
	 *	allocations, allocate a message, and go try to
	 *	reserve room for the raw packet data.
	 */
	ms->mr_max++;
	ms->mr_current = ms->mr_max;
	ms->mr_array[ms->mr_max] = mr;

	MPRINT("SET MR to doubled %d\n", ms->mr_current);

	/*
	 *	And we should now have an entirely empty message ring.
	 */
	m = fr_message_ring_alloc(ms, mr, false);
	if (!m) return NULL;

	MPRINT("ALLOC after doubled message ring\n");

	return m;
}


/** Get a ring buffer for a message
 *
 * @param[in] ms the message set
 * @param[in] m the message
 * @param[in] cleaned_up whether the message set was partially garbage collected
 * @return
 *	- NULL on error, and m is deallocated
 *	- m on success
 */
static fr_message_t *fr_message_get_ring_buffer(fr_message_set_t *ms, fr_message_t *m,
						bool cleaned_up)
{
	int i;
	fr_ring_buffer_t *rb;

	/*
	 *	And... we go through a bunch of hoops, all over again.
	 */
	m->rb = ms->rb_array[ms->rb_current];
	rad_assert(m->rb != NULL);
	m->data = fr_ring_buffer_reserve(m->rb, m->rb_size);
	if (m->data) return m;

	/*
	 *	When the simple allocation fails, ensure we don't do
	 *	the cleanup twice in one allocation.
	 */
	if (!cleaned_up) {
		/*
		 *	If we run out of room in the current ring
		 *	buffer, AND it's our only one, then just
		 *	double it in size.
		 */
		if (ms->rb_max == 0) goto alloc_rb;

		/*
		 *	We're using multiple ring buffers, and we
		 *	haven't already done a cleanup.  Force a
		 *	cleanup.
		 */
		MPRINT("CLEANED UP BECAUSE OF RING BUFFER (%zd - %zd = %zd)\n", ms->allocated, ms->freed,
			ms->allocated - ms->freed);

		fr_message_gc(ms, 128);

		/*
		 *	Try to allocate the packet from the newly current ring buffer.
		 */
		m->rb = ms->rb_array[ms->rb_current];
		rad_assert(m->rb != NULL);
		m->data = fr_ring_buffer_reserve(m->rb, m->rb_size);
		if (m->data) return m;

		MPRINT("CLEANUP RING BUFFER FAILED\n");
	}

	/*
	 *	We've tried two allocations, and both failed.  Brute
	 *	force over all arrays, trying to allocate one
	 *	somewhere... anywhere.  We start from the largest
	 *	array, because that is the one we want to use the
	 *	most.
	 *
	 *	We want to avoid allocations in the smallest array,
	 *	because that array will quickly wrap, and will cause
	 *	us to do cleanups more often.  That also lets old
	 *	entries in the smallest array age out, so that we can
	 *	free the smallest arrays.
	 */
	for (i = ms->rb_max; i >= 0; i--) {
		m->rb = ms->rb_array[i];
		rad_assert(m->rb != NULL);
		m->data = fr_ring_buffer_reserve(m->rb, m->rb_size);
		if (m->data) {
			MPRINT("MOVED TO RING BUFFER %d\n", i);
			ms->rb_current = i;
			return m;
		}
	}

	/*
	 *	All of the arrays are full.  If we don't have
	 *	room to allocate another array, we're dead.
	 */
	if ((ms->rb_max + 1) >= MSG_ARRAY_SIZE) {
		fr_strerror_printf("Message arrays are full");
		goto cleanup;
	}

alloc_rb:
	/*
	 *	Allocate another message ring, double the size
	 *	of the previous maximum.
	 */
	rb = fr_ring_buffer_create(ms, fr_ring_buffer_size(ms->rb_array[ms->rb_max]) * 2);
	if (!rb) {
		fr_strerror_printf_push("Failed allocating ring buffer");
		goto cleanup;
	}

	MPRINT("RING BUFFER DOUBLES\n");

	/*
	 *	Set the new one as current for all new
	 *	allocations, allocate a message, and go try to
	 *	reserve room for the raw packet data.
	 */
	ms->rb_max++;
	ms->rb_current = ms->rb_max;
	ms->rb_array[ms->rb_current] = rb;

	/*
	 *	And we should now have an entirely empty message ring.
	 */
	m->rb = rb;
	m->data = fr_ring_buffer_reserve(m->rb, m->rb_size);
	if (m->data) return m;

cleanup:
	MPRINT("OUT OF MEMORY\n");

	m->rb = NULL;
	m->status = FR_MESSAGE_DONE;
	return NULL;
}


/** Reserve a message
 *
 *  A later call to fr_message_alloc() will allocate the correct
 *  packet ring buffer size.  This call just allocates a message
 *  header, and reserves space for the packet.
 *
 *  If the caller later decides that the message is not needed, he
 *  should call fr_message_free() to free the message.
 *
 *  We assume that the caller will call fr_message_reserve(), and then
 *  almost immediately fr_message_alloc().  Multiple calls in series
 *  to fr_message_reserve() MUST NOT be done.  The caller could also
 *  just call fr_ring_buffer_alloc(m->rb, size) if they wanted, and
 *  then udpate m->data_size by hand...
 *
 *  The message is returned
 *
 * @param[in] ms the message set
 * @param[in] reserve_size to reserve
 * @return
 *      - NULL on error
 *	- fr_message_t* on success
 */
fr_message_t *fr_message_reserve(fr_message_set_t *ms, size_t reserve_size)
{
	bool cleaned_up;
	fr_message_t *m;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	if (reserve_size > ms->max_allocation) {
		fr_strerror_printf("Cannot reserve %zd > max allocation %zd\n", reserve_size, ms->max_allocation);
		return NULL;
	}

	/*
	 *	Allocate a bare message.
	 */
	m = fr_message_get_message(ms, &cleaned_up);
	if (!m) {
		MPRINT("Failed to reserve message\n");
		return NULL;
	}

	/*
	 *	If the caller is not allocating any packet data, just
	 *	return the empty message.
	 */
	if (!reserve_size) return m;

	/*
	 *	We leave m->data_size as zero, and m->rb_size as the
	 *	reserved size.  This indicates that the message has
	 *	reserved room for the packet data, but nothing has
	 *	been allocated.
	 */
	m->rb_size = reserve_size;

	return fr_message_get_ring_buffer(ms, m, cleaned_up);
}

/** Allocate packet data for a message
 *
 *  The caller will normally call fr_message_reserve() before calling
 *  this function, and pass the resulting message 'm' here.  If 'm' is
 *  NULL, however, this function will call fr_message_reserve() of
 *  'actual_packet_size'.  This capability is there for callers who
 *  know the size of the message in advance.
 *
 * @param[in] ms the message set
 * @param[in] m the message message to allocate packet data for
 * @param[in] actual_packet_size to use
 * @return
 *      - NULL on error, and input message m is left alone
 *	- fr_message_t* on success.  Will always be input message m.
 */
fr_message_t *fr_message_alloc(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size)
{
	uint8_t *p;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */

	if (!m) {
		m = fr_message_reserve(ms, actual_packet_size);
		if (!m) return NULL;
	}

	rad_assert(m->status == FR_MESSAGE_USED);
	rad_assert(m->rb != NULL);
	rad_assert(m->data != NULL);
	rad_assert(m->data_size == 0);
	rad_assert(m->rb_size >= actual_packet_size);

	p = fr_ring_buffer_alloc(m->rb, actual_packet_size);
	rad_assert(p != NULL);
	if (!p) {
		fr_strerror_printf_push("Failed allocating from ring buffer");
		return NULL;
	}

	rad_assert(p == m->data);

	/*
	 *	The caller can change m->data size to something a bit
	 *	smaller, e.g. for cache alignment issues.
	 */
	m->data_size = actual_packet_size;
	m->rb_size = actual_packet_size;

	return m;
}

/** Allocate packet data for a message, and reserve a new message
 *
 *  This function allocates a previously reserved message, and then
 *  reserves a new message.
 *
 *  The application should call fr_message_reserve() with a large
 *  buffer, and then read data into the buffer.  If the buffer
 *  contains multiple packets, the application should call
 *  fr_message_alloc_reserve() repeatedly to allocate the full
 *  packets, while reserving room for the partial packet.
 *
 *  When the application is determines that there is only one full
 *  packet, and one partial packet in the buffer, it should call this
 *  function with actual_packet_size, and a large reserve_size.  The
 *  partial packet will be reserved.  If the ring buffer is full, the
 *  partial packet will be copied to a new ring buffer.
 *
 *  When the application determines that there are multiple full
 *  packets in the buffer, it should call this function with
 *  actual_packet_size for each buffer, and reserve_size which
 *  reserves all of the data in the buffer.  i.e. the full packets +
 *  partial packets, which should start off as the original
 *  reserve_size.
 *
 *  The application should call this function to allocate each packet,
 *  while decreasing reserve_size by each actual_packet_size that was
 *  allocated.  Once there is only one full and a partial packet in
 *  the buffer, it should use a large reserve_size, as above.
 *
 *  The application could just always ecall this function with a large
 *  reserve_size, at the cost of substantially more memcpy()s.
 *
 * @param[in] ms the message set
 * @param[in] m the message message to allocate packet data for
 * @param[in] actual_packet_size to use
 * @param[in] leftover "dirty" bytes in the buffer
 * @param[in] reserve_size to reserve for new message
 * @return
 *      - NULL on error, and input message m is left alone
 *	- fr_message_t* on success.  Will always be a new message.
 */
fr_message_t *fr_message_alloc_reserve(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size,
				       size_t leftover, size_t reserve_size)
{
	bool cleaned_up;
	uint8_t *p;
	fr_message_t *m2;
	size_t m_rb_size;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */

	rad_assert(m->status == FR_MESSAGE_USED);
	rad_assert(m->rb != NULL);
	rad_assert(m->data != NULL);
	rad_assert(m->rb_size >= actual_packet_size);

	p = fr_ring_buffer_alloc(m->rb, actual_packet_size);
	rad_assert(p != NULL);
	if (!p) {
		fr_strerror_printf_push("Failed allocating from ring buffer");
		return NULL;
	}

	rad_assert(p == m->data);

	m_rb_size = m->rb_size;	/* for ring buffer cleanups */

	/*
	 *	The caller can change m->data size to something a bit
	 *	smaller, e.g. for cache alignment issues.
	 */
	m->data_size = actual_packet_size;
	m->rb_size = actual_packet_size;

	/*
	 *	If we've allocated all of the reserved ring buffer
	 *	data, then just reserve a brand new reservation.
	 */
	if (!leftover) return fr_message_reserve(ms, reserve_size);

	/*
	 *	Allocate a new message.
	 */
	m2 = fr_message_get_message(ms, &cleaned_up);
	if (!m2) return NULL;

	/*
	 *	Track how much data there is in the packet.
	 */
	m2->rb = m->rb;
	m2->data_size = leftover;
	m2->rb_size = reserve_size;

	/*
	 *	Try to extend the reservation.  If we can do it,
	 *	return.
	 */
	m2->data = fr_ring_buffer_reserve(m2->rb, m2->rb_size);
	if (m2->data) {
		/*
		 *	We've wrapped around in the reservation.  Copy the data over.
		 */
		if (m2->data != (m->data + actual_packet_size)) {
			memcpy(m2->data, m->data + actual_packet_size, leftover);
		}
		return m2;
	}

	/*
	 *	Reserve data from a new ring buffer.  If it doesn't
	 *	succeed, ensure that the old message will properly
	 *	clean up the old ring buffer.
	 */
	if (!fr_message_get_ring_buffer(ms, m2, false)) {
		m->rb_size = m_rb_size;
		return NULL;
	}

	/*
	 *	If necessary, copy the remaining data from the old
	 *	buffer to the new one.
	 */
	if (m2->data != (m->data + actual_packet_size)) {
		memcpy(m2->data, m->data + actual_packet_size, leftover);
	}

	/*
	 *	This shouldn't happen, but it's possible if the caller
	 *	takes shortcuts, and doesn't check the things they
	 *	need to check.
	 */
	if (m2->rb == m->rb) {
		return m2;
	}

	/*
	 *	Ensure that the old message will properly clean up the
	 *	ring buffer.
	 */
	m->rb_size = m_rb_size;
	return m2;
}

#define MS_ALIGN_SIZE (16)
#define MS_ALIGN(_x) (((_x) + (MS_ALIGN_SIZE-1)) & ~(MS_ALIGN_SIZE-1))

/** Allocate an aligned pointer for packet (or struct data).
 *
 *  This function is similar to fr_message_alloc() except that the
 *  return value is aligned to CPU boundaries.  The amount of data
 *  allocated is also rounded up to the nearest alignment size.
 *
 * @param[in] ms the message set
 * @param[in] m the message message to allocate packet data for
 * @param[in] actual_packet_size to reserve
 * @return
 *      - NULL on error
 *	- fr_message_t* on success
 */
fr_message_t *fr_message_alloc_aligned(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size)
{
	uint8_t *p, *aligned_p;
	intptr_t addr;
	size_t aligned_size;


	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */

	/*
	 *	No existing message, try allocate enough room to align
	 *	both the start of the packet, and it's total size.
	 */
	if (!m) {
		m = fr_message_reserve(ms, actual_packet_size + (2 * MS_ALIGN_SIZE) - 1);
		if (!m) return NULL;
	}

	rad_assert(m->status == FR_MESSAGE_USED);
	rad_assert(m->rb != NULL);
	rad_assert(m->data != NULL);
	rad_assert(m->data_size == 0);
	rad_assert(m->rb_size >= actual_packet_size);

	/*
	 *	Align the address and the actual packet size.
	 */
	addr = (intptr_t) m->data;
	addr = MS_ALIGN(addr);
	aligned_p = (uint8_t *) addr;

	aligned_size = MS_ALIGN(actual_packet_size);

	if ((aligned_p + aligned_size) > (m->data + m->rb_size)) {
		fr_strerror_printf("Aligned message size overflows reserved size");
		return NULL;
	}

	/*
	 *	The ring buffer has already allocated a possibly
	 *	un-aligned pointer.  We wish to allocate enough room
	 *	to align both the pointer, and the structure size.
	 */
	aligned_size = (aligned_p - m->data) + actual_packet_size;
	aligned_size = MS_ALIGN(aligned_size);

	p = fr_ring_buffer_alloc(m->rb, aligned_size);
	rad_assert(p != NULL);
	if (!p) {
		fr_strerror_printf_push("Failed allocating from ring buffer");
		return NULL;
	}

	rad_assert(p == m->data);
	rad_assert((aligned_p + aligned_size) <= (m->data + m->rb_size));

	/*
	 *	Set the aligned pointer, the total aligned size, and
	 *	the structure size.
	 */
	m->data = aligned_p;
	m->rb_size = aligned_size;
	m->data_size = actual_packet_size;

	return m;
}


/** Count the number of used messages
 *
 * @param[in] ms the message set
 * @return
 *      - number of used messages
 */
int fr_message_set_messages_used(fr_message_set_t *ms)
{
	int i, used;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	used = 0;
	for (i = 0; i <= ms->mr_max; i++) {
		fr_ring_buffer_t *mr;

		mr = ms->mr_array[i];

		used += fr_ring_buffer_used(mr) / ms->message_size;
	}

	return used;
}

/** Garbage collect the message set.
 *
 *  This function should ONLY be called just before freeing the
 *  message set.  It is intended only for debugging, and will cause
 *  huge latency spikes if used at run time.
 *
 * @param[in] ms the message set
 */
void fr_message_set_gc(fr_message_set_t *ms)
{
	int i;
	int num_cleaned;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/*
	 *	Manually clean up each message ring.
	 */
	num_cleaned = 0;
	for (i = 0; i <= ms->mr_max; i++) {
		num_cleaned += fr_message_ring_gc(ms, ms->mr_array[i], ~0);
	}

	MPRINT("GC cleaned %d\n", num_cleaned);

	/*
	 *	And then do one last pass to clean up the arrays.
	 */
	fr_message_gc(ms, 1 << 24);
}

/** Print debug information about the message set.
 *
 * @param[in] ms the message set
 * @param[in] fp the FILE where the messages are printed.
 */
void fr_message_set_debug(fr_message_set_t *ms, FILE *fp)
{
	int i;

	(void) talloc_get_type_abort(ms, fr_message_set_t);

	fprintf(fp, "message arrays = %d\t(current %d)\n", ms->mr_max + 1, ms->mr_current);
	fprintf(fp, "ring buffers   = %d\t(current %d)\n", ms->rb_max + 1, ms->rb_current);

	for (i = 0; i <= ms->mr_max; i++) {
		fr_ring_buffer_t *mr = ms->mr_array[i];

		fprintf(fp, "messages[%d] =\tsize %zu, used %zu\n",
			i, fr_ring_buffer_size(mr), fr_ring_buffer_used(mr));
	}

	for (i = 0; i <= ms->rb_max; i++) {
		fprintf(fp, "ring buffer[%d] =\tsize %zu, used %zu\n",
			i, fr_ring_buffer_size(ms->rb_array[i]), fr_ring_buffer_used(ms->rb_array[i]));
	}
}
