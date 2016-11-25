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
 * @file util/message.c
 *
 * @copyright 2016 Alan DeKok <aland@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/message.h>
#include <freeradius-devel/rad_assert.h>

#include <string.h>

/*
 *	Debugging, mainly for message_set_test
 */
#if 0
#define MPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define MPRINT(...)
#endif

/** An array of messages
 *
 *  We wish to occasionally increase the size of the message array,
 *  without re-allocing it.  Some recipients may still be referencing
 *  messages.
 */
typedef struct fr_message_ring_t {
	uint8_t			*messages;	//!< array of messages
	int			size;		//!< size of the array
	size_t			message_size;	//!< size of each message, including fr_message_t

	int			data_start;	//!< start of used portion of the array
	int			data_end;	//!< end of the used portion of the array
	int			write_offset;	//!< where the writes are done.

	//  6 7 8 for alignment ?
} fr_message_ring_t;

#define MSG_ARRAY_SIZE (16)

/**
 *  Get a fr_message_t pointer from an array index.
 */
#define MR_ARRAY(_x) (fr_message_t *)(mr->messages + ((_x) * mr->message_size))

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
struct fr_message_set_t {
	int			mr_current;	//!< current used message ring entry
	int			mr_max;		//!< max used message ring entry

	size_t			message_size;	//!< size of the callers message, including fr_message_t

	int			mr_cleaned;	//!< where we last cleaned

	int			rb_current;	//!< current used ring buffer entry
	int			rb_max;		//!< max used ring buffer entry

	size_t			max_allocation;	//!< maximum allocation size

	int			allocated;
	int			freed;

	fr_message_ring_t	*mr_array[MSG_ARRAY_SIZE]; //!< array of message arrays

	fr_ring_buffer_t	*rb_array[MSG_ARRAY_SIZE]; //!< array of ring buffers
};


/** Create a new message ring.
 *
 * @param[in] ctx the talloc ctx
 * @param[in] num_messages to allow in the ring
 * @param[in] message_size of each message, including fr_message_t
 * @return
 *	- NULL on error
 *	- fr_message_ring_t * on success
 */
static fr_message_ring_t *fr_message_ring_create(TALLOC_CTX *ctx, int num_messages, size_t message_size)
{
	int i;
	fr_message_ring_t *mr;

	mr = talloc_zero(ctx, fr_message_ring_t);
	if (!mr) return NULL;

	MPRINT("MEMORY RING ALLOC %d\n", num_messages);

	mr->messages = talloc_size(mr, num_messages * message_size);
	if (!mr->messages) {
		talloc_free(mr);
		return NULL;
	}

	talloc_set_type(mr->messages, fr_message_t);

	mr->size = num_messages;
	mr->message_size = message_size;
	for (i = 0; i < num_messages; i++) {
		fr_message_t *m;

		m = MR_ARRAY(i);

		m->status = FR_MESSAGE_FREE;
	}

	return mr;
}



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
	if (num_messages < 8) return NULL;

	if ((num_messages & (num_messages - 1)) != 0) return NULL;

	if (message_size < sizeof(fr_message_t)) return NULL;

	if (message_size > 1024) return NULL;

	if (ring_buffer_size < 1024) return NULL;

	if ((ring_buffer_size & (ring_buffer_size - 1)) != 0) return NULL;

	ms = talloc_zero(ctx, fr_message_set_t);
	if (!ms) return NULL;

	message_size += 15;
	message_size &= ~(size_t) 15;
	ms->message_size = message_size;

	ms->rb_array[0] = fr_ring_buffer_create(ms, ring_buffer_size);
	if (!ms->rb_array[0]) {
		talloc_free(ms);
		return NULL;
	}

	ms->mr_array[0] = fr_message_ring_create(ms, num_messages, message_size);
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
		return NULL;
	}

	if (message_size <= sizeof(fr_message_t)) return NULL;

	l = talloc_memdup(ctx, m, message_size);
	if (!l) return NULL;

	if (l->data_size) {
		l->data = talloc_memdup(l, l->data, l->data_size);
		if (!l->data) {
			talloc_free(l);
			return NULL;
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
static int fr_message_ring_gc(fr_message_set_t *ms, fr_message_ring_t *mr, int max_to_clean)
{
	int i;
	int messages_cleaned = 0;

	/*
	 *	Wrap indices prior to doing any cleanup.
	 */
recheck:
	if (mr->data_start >= mr->size) {
		rad_assert(mr->data_start == mr->data_end);
		rad_assert(mr->data_start == mr->size);

		if (mr->write_offset < mr->data_start) {
			mr->data_start = 0;
			mr->data_end = mr->write_offset;
		} else {
			mr->data_start = 0;
			mr->data_end = 0;
			mr->write_offset = 0;
		}
	}

	rad_assert(mr->data_start <= mr->data_end);
	rad_assert(mr->data_start < mr->size);
	rad_assert(mr->data_end <= mr->size);
	rad_assert(mr->write_offset <= mr->size);

	/*
	 *	Loop over messages in the oldest block, seeing if we
	 *	need to delete them.
	 */
	for (i = mr->data_start; i < mr->data_end; i++) {
		fr_message_t *m;

		m = MR_ARRAY(i);

		rad_assert(m->status != FR_MESSAGE_FREE);

		if (m->status != FR_MESSAGE_DONE) {
			max_to_clean = messages_cleaned;
			break;
		}

		mr->data_start++;
		messages_cleaned++;
		m->status = FR_MESSAGE_FREE;
		ms->freed++;

		if (m->rb) {
			(void) fr_ring_buffer_free(m->rb, m->rb_size);
#ifndef NDEBUG
			memset(m, 0, ms->message_size);
#endif
		}
		if (messages_cleaned >= max_to_clean) break;
	}

	/*
	 *	There's still data in the ring buffer, we're done
	 *	cleaning.
	 */
	if (mr->data_start < mr->data_end) {
		MPRINT("CLEANED %d (%p) non-empty (wo %d, start %d, end %d)\n", messages_cleaned, mr,
			mr->write_offset, mr->data_start, mr->data_end);
		return messages_cleaned;
	}

	/*
	 *	We've cleaned everything.
	 */
	if (mr->data_start == mr->data_end) {
		if (mr->write_offset == mr->data_end) {
			mr->data_start = 0;
			mr->data_end = 0;
			mr->write_offset = 0;

			MPRINT("CLEANED %d (%p) empty\n", messages_cleaned, mr);
			return messages_cleaned;
		}

		rad_assert(mr->write_offset < mr->data_start);
		rad_assert(mr->write_offset < mr->size);
		mr->data_start = 0;
		mr->data_end = mr->write_offset;
	}

	/*
	 *	The ring buffer still has data, and we're allowed to
	 *	clean more messages.  Go do so.
	 */
	if ((mr->write_offset > 0) && (messages_cleaned < max_to_clean)) {
		goto recheck;
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
	int arrays_freed, empty_slot;
	int largest_free_slot;
	size_t largest_free_size;

	/*
	 *	Clean up "done" messages.
	 */
	arrays_freed = 0;
	empty_slot = -1;

	for (i = 0; i <= ms->mr_max; i++) {

		fr_message_ring_t *mr = ms->mr_array[i];

		(void) fr_message_ring_gc(ms, mr, max_to_clean);

		/*
		 *	If the message ring buffer is empty, check if
		 *	we should perhaps delete it.
		 */
		if ((mr->data_start == 0) && (mr->data_end == 0)) {
			/*
			 *	Try to ensure that at least one array
			 *	is empty.
			 */
			if (empty_slot < 0) {
				empty_slot = i;
				continue;
			}

			/*
			 *	Don't ever free the largest array, but
			 *	do set the empty slot here.
			 */
			if (i == ms->mr_max) {
				empty_slot = i;
				continue;
			}

			/*
			 *	We now have at least two arrays which
			 *	are free.  Free the old one, and keep
			 *	the new one.
			 */
			TALLOC_FREE(ms->mr_array[empty_slot]);
			arrays_freed++;
			empty_slot = i;
		}

		/*
		 *	If we're cleaning up small array entries, do
		 *	so aggressively.  This allows for smaller
		 *	arrays to be cleaned up and freed, so that we
		 *	can keep using large arrays.
		 */
		if ((i + 2) < ms->mr_max) {
			continue;
		}

		/*
		 *	We're cleaning up the large arrays, i.e. ones
		 *	with recent packets.  Limit latency to only a
		 *	few cleanups at a time.  We DON'T want to
		 *	clean up 1M packets at once, but instead
		 *	amortize that work over incoming packets.
		 */
		if (max_to_clean == 0) {
			break;
		}
	}

	/*
	 *	Some entries have been freed.  We need to coalesce the
	 *	remaining entries.
	 */
	if (arrays_freed) {
		for (i = 0; i < ms->mr_max; i++) {
			if (ms->mr_array[i] != NULL) continue;


			memmove(&ms->mr_array[i], &ms->mr_array[i + 1],
				sizeof(ms->mr_array[i]) * (ms->mr_max - i + 1));

			if (empty_slot > i) empty_slot--;
			if (ms->mr_current > i) ms->mr_current--;
		}

		/*
		 *	Reset the max, and current to the lowest
		 *	array entry.
		 */
		ms->mr_max -= arrays_freed;
		rad_assert(ms->mr_current <= ms->mr_max);

#ifndef NDEBUG
		for (i = 0; i <= ms->mr_max; i++) {
			rad_assert(ms->mr_array[i] != NULL);
		}
#endif
	}

	/*
	 *	If there's no array which is completely empty, Reset
	 *	the index to the largest array, which means
	 *	allocations are more likely to be from the largest
	 *	array.  This make it more likely that entries in the
	 *	smaller arrays will age out, meaning we can free the
	 *	smaller arrays.
	 */
	if (empty_slot < 0) {
		ms->mr_current = ms->mr_max;
		MPRINT("SET MR to %d\n", ms->mr_current);
	}

	/*
	 *	And now we do the same thing for the ring buffers.
	 *	Except that freeing the messages above also cleaned up
	 *	the contents of each ring buffer, so all we need to do
	 *	is find the largest empty ring buffer.
	 */
	arrays_freed = 0;
	empty_slot = -1;
	for (i = 0; i <= ms->rb_max; i++) {
		if (fr_ring_buffer_used(ms->rb_array[i]) == 0) {
			if (empty_slot < 0) {
				empty_slot = i;
				continue;
			}

			/*
			 *	Don't ever free the largest array, but
			 *	do set the empty slot here.
			 */
			if (i == ms->rb_max) {
				empty_slot = i;
				break;
			}

			TALLOC_FREE(ms->rb_array[empty_slot]);
			empty_slot = i;
			arrays_freed++;
		}
	}

	/*
	 *	This code is the same as above, except with s/m_/rb_/.
	 *	We could arguably turn this into a function...
	 */
	if (arrays_freed) {
		MPRINT("TRYING TO FREE %d arrays out of %d empty %d\n", arrays_freed, ms->rb_max + 1, empty_slot);

		for (i = 0; i < ms->rb_max; i++) {
			if (ms->rb_array[i] != NULL) continue;

			memmove(&ms->rb_array[i], &ms->rb_array[i + 1],
				sizeof(ms->rb_array[i]) * (ms->rb_max - i + 1));

			if (empty_slot > i) empty_slot--;
			if (ms->rb_current > i) ms->rb_current--;
		}

		/*
		 *	Reset the max, and current to the lowest
		 *	array entry.
		 */
		ms->rb_max -= arrays_freed;
		rad_assert(ms->rb_current <= ms->rb_max);

#ifndef NDEBUG
		MPRINT("NUM ARRAYS NOW %d\n", ms->rb_max + 1);
		for (i = 0; i <= ms->rb_max; i++) {
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
static fr_message_t *fr_message_ring_alloc(fr_message_set_t *ms, fr_message_ring_t *mr, bool clean)
{
	fr_message_t *m;

	rad_assert(mr != NULL);
	rad_assert(mr->write_offset <= mr->size);
	rad_assert(mr->data_start <= mr->size);
	rad_assert(mr->data_start <= mr->data_end);
	rad_assert(mr->data_end <= mr->size);

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
		int used = 0;

		if (mr->write_offset < mr->data_start) {
			used += mr->write_offset;
		}
		used += (mr->data_end - mr->data_start);

		if (used >= mr->size) {
			if (fr_message_ring_gc(ms, mr, 4) == 0) {
				return NULL;
			}

			/*
			 *	Else we cleaned up some entries in this array.
			 *	Go allocate a message.
			 */
		}
	}

	/*
	 *	We're at the start of the buffer, and there's room.
	 *	Grab an entry and continue.
	 */
	if (mr->write_offset < mr->data_start) {
		m = MR_ARRAY(mr->write_offset);
		mr->write_offset++;

#ifndef NDEBUG
		memset(m, 0, mr->message_size);
#endif
		m->status = FR_MESSAGE_USED;
		return m;
	}

	/*
	 *	We've wrapped around and filled the buffer.
	 */
	if (mr->write_offset != mr->data_end) {
		rad_assert(mr->data_start < mr->data_end);
		rad_assert(mr->data_start < mr->size);
		rad_assert(mr->data_end <= mr->size);
		rad_assert(mr->write_offset == mr->data_start);
		return NULL;
	}

	/*
	 *	We're writing to the end of the buffer.  Grab an entry
	 *	and continue.
	 */
	rad_assert(mr->write_offset == mr->data_end);
	rad_assert(mr->data_end < mr->size);

	m = MR_ARRAY(mr->write_offset);
	mr->write_offset++;
	mr->data_end++;

	/*
	 *	Wrap around to the start if we fall off of the
	 *	end of the buffer.
	 *
	 *	Note that data_start MAY still be zero, in
	 *	which case we don't want to write anything
	 *	here.
	 */
	if (mr->write_offset >= mr->size) {
		mr->write_offset = 0;
	}

#ifndef NDEBUG
	memset(m, 0, mr->message_size);
#endif
	m->status = FR_MESSAGE_USED;
	return m;
}

/**  Allocate a fr_message_t, WITHOUT a ring buffer.
 *
 * @param[in] ms the message set
 * @param[out] p_mr the message ring we allocated the message from
 * @param[out] p_cleaned a flag to indicate if we cleaned the message array
 * @return
 *      - NULL on error
 *	- fr_message_t* on success
 */
static fr_message_t *fr_message_get_message(fr_message_set_t *ms, fr_message_ring_t **p_mr, bool *p_cleaned)
{
	int i;
	fr_message_t *m;
	fr_message_ring_t *mr;

	ms->allocated++;
	*p_cleaned = false;
	*p_mr = NULL;

	/*
	 *	Grab the current message array.  In the general case,
	 *	there's room, so we grab a message and go find a ring
	 *	buffer.
	 */
	mr = ms->mr_array[ms->mr_current];
	m = fr_message_ring_alloc(ms, mr, true);
	if (m) {
		MPRINT("ALLOC normal\n");
		*p_mr = mr;
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
		*p_mr = mr;
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
			*p_mr = mr;
			return m;
		}
	}

	/*
	 *	All of the arrays are full.  If we don't have
	 *	room to allocate another array, we're dead.
	 */
	if ((ms->mr_max + 1) >= MSG_ARRAY_SIZE) {
		return NULL;
	}

	/*
	 *	Allocate another message ring, double the size
	 *	of the previous maximum.
	 */
	mr = fr_message_ring_create(ms, ms->mr_array[ms->mr_max]->size * 2, ms->message_size);
	if (!mr) return NULL;

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

	*p_mr = mr;
	return m;
}

/** Deallocate a message
 *
 * @param[in] ms the message set
 * @param[in] mr the message ring
 * @param[in] m the message
 * @return NULL, always
 */
static fr_message_t *fr_message_unalloc(fr_message_set_t *ms, fr_message_ring_t *mr, fr_message_t *m)
{
	/*
	 *	Undo the allocation we did here.  Which requires us to
	 *	remember that "mr" was the message ring from which we
	 *	allocated the message.
	 */
	m->rb = NULL;
	m->status = FR_MESSAGE_FREE;

	mr->write_offset--;
	ms->allocated--;

	return NULL;
}


/** Get a ring buffer for a message
 *
 * @param[in] ms the message set
 * @param[in] mr the message ring
 * @param[in] m the message
 * @param[in] cleaned_up whether the message set was partially garbage collected
 * @return
 *	- NULL on error, and m is deallocated
 *	- m on success
 */
static fr_message_t *fr_message_get_ring_buffer(fr_message_set_t *ms, fr_message_ring_t *mr, fr_message_t *m,
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
		goto cleanup;
	}

alloc_rb:
	/*
	 *	Allocate another message ring, double the size
	 *	of the previous maximum.
	 */
	rb = fr_ring_buffer_create(ms, fr_ring_buffer_size(ms->rb_array[ms->rb_max]) * 2);
	if (!rb) goto cleanup;

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

	return fr_message_unalloc(ms, mr, m);
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
	fr_message_ring_t *mr;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	if (reserve_size > ms->max_allocation) return NULL;

	/*
	 *	Allocate a bare message.
	 */
	m = fr_message_get_message(ms, &mr, &cleaned_up);
	if (!m) return NULL;

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

	return fr_message_get_ring_buffer(ms, mr, m, cleaned_up);
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

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */
#endif

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
 * @param[in] reserve_size to reserve for new message
 * @return
 *      - NULL on error, and input message m is left alone
 *	- fr_message_t* on success.  Will always be a new message.
 */
fr_message_t *fr_message_alloc_reserve(fr_message_set_t *ms, fr_message_t *m, size_t actual_packet_size,
				       size_t reserve_size)
{
	bool cleaned_up;
	size_t room;
	uint8_t *p;
	fr_message_t *m2;
	fr_message_ring_t *mr;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */
#endif

	rad_assert(m->status == FR_MESSAGE_USED);
	rad_assert(m->rb != NULL);
	rad_assert(m->data != NULL);
	rad_assert(m->data_size == 0);
	rad_assert(m->rb_size >= actual_packet_size);

	p = fr_ring_buffer_alloc(m->rb, actual_packet_size);
	rad_assert(p != NULL);
	if (!p) {
		return NULL;
	}

	rad_assert(p == m->data);

	room = m->rb_size - actual_packet_size;

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
	if (!room) return fr_message_reserve(ms, reserve_size);

	/*
	 *	Allocate a new message.
	 */
	m2 = fr_message_get_message(ms, &mr, &cleaned_up);
	if (!m2) {
		return NULL;
	}

	/*
	 *	Mark how much room there is in this message.
	 */
	m2->rb = m->rb;
	m2->data_size = room;
	m2->rb_size = room;

	/*
	 *	There is more room than the asked reservation.  The
	 *	reservation MUST succeed.
	 */
	if (room >= reserve_size) {
		m2->data = fr_ring_buffer_reserve(m2->rb, m2->rb_size);
		rad_assert(m2->data != NULL);
		if (!m2->data) {
			return fr_message_unalloc(ms, mr, m2);
		}
	}

	/*
	 *	The caller is asking for more reserve than we have
	 *	room for.  Find a new ring buffer, and call
	 *	fr_ring_buffer_reserve_split() on it, and on the old
	 *	one.
	 */
	if (!fr_message_get_ring_buffer(ms, mr, m2, false)) {
		return NULL;
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
	 *	Copy the remaining data from the old buffer to the new one.
	 */
	memcpy(m2->data, m->data + actual_packet_size, room);
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


#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);

	/* m is NOT talloc'd */
#endif

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
		// allocation failure, fix M.
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
		// allocation failure, fix M.
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

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	used = 0;
	for (i = 0; i <= ms->mr_max; i++) {
		fr_message_ring_t *mr;

		mr = ms->mr_array[i];

		if (mr->write_offset < mr->data_start) {
			used += mr->write_offset;
		}

		used += (mr->data_end - mr->data_start);
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

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	/*
	 *	Manually clean up each message ring.
	 */
	num_cleaned = 0;
	for (i = 0; i <= ms->mr_max; i++) {
		num_cleaned += fr_message_ring_gc(ms, ms->mr_array[i],
						  ms->mr_array[i]->size);
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

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	fprintf(fp, "message arrays = %d\t(current %d)\n", ms->mr_max + 1, ms->mr_current);
	fprintf(fp, "ring buffers   = %d\t(current %d)\n", ms->rb_max + 1, ms->rb_current);

	for (i = 0; i <= ms->mr_max; i++) {
		fr_message_ring_t *mr = ms->mr_array[i];

		fprintf(fp, "messages[%d] =\tsize %d, write_offset %d, data_start %d, data_end %d\n",
			i, mr->size, mr->write_offset, mr->data_start, mr->data_end);
	}

	for (i = 0; i <= ms->rb_max; i++) {
		fprintf(fp, "ring buffer[%d] =\tsize %zd, used %zd\n",
			i, fr_ring_buffer_size(ms->rb_array[i]), fr_ring_buffer_used(ms->rb_array[i]));
	}
}
