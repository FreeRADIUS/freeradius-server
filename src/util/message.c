/*
 * message.c	Messages for inter-thread communication.
 *
 * Version:	$Id$
 *
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
 *
 * Copyright 2016  Alan DeKok <aland@freeradius.org>
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

#ifndef NDEBUG
#define DBG_UNUSED
#else
#define DBG_UNUSED UNUSED
#endif

/** An array of messages
 *
 *  We wish to occasionally increase the size of the message array,
 *  without re-allocing it.  Some recipients may still be referencing
 *  messages.
 */
typedef struct fr_message_ring_t {
	fr_message_t		*messages;	//!< array of messages
	int			size;		//!< size of the array

	int			data_start;	//!< start of used portion of the array
	int			data_end;	//!< end of the used portion of the array
	int			write_offset;	//!< where the writes are done.

	//  6 7 8 for alignment ?
} fr_message_ring_t;

#define M_ARRAY_SIZE (16)

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
 *  M_ARRAY_SIZE.  The reason is that the memory for fr_message_set_t
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
 *  M_ARRAY_SIZE is defined to be large (16 doublings) to allow for
 *  the edge case where messages are stuck for long periods of time.
 *
 *  With an initial message array size of 64, this gives us room for
 *  2M packets, if *all* of the m_array entries have packets stuck in
 *  them that aren't cleaned up for extended periods of time.
 *  
 */
struct fr_message_set_t {
	int			m_current;	//!< current used message array entry
	int			m_max;		//!< max used message array entry

	int			m_cleaned;	//!< where we last cleaned

	int			rb_current;	//!< current used ring buffer entry
	int			rb_max;		//!< max used ring buffer entry

	size_t			max_allocation;	//!< maximum allocation size

	int			allocated;
	int			freed;

	fr_message_ring_t	*m_array[M_ARRAY_SIZE]; //!< array of message arrays

	fr_ring_buffer_t	*rb_array[M_ARRAY_SIZE]; //!< array of ring buffers
};

static fr_message_ring_t *fr_message_ring_create(TALLOC_CTX *ctx, int num_messages)
{
	fr_message_ring_t *mr;

	mr = talloc_zero(ctx, fr_message_ring_t);
	if (!mr) return NULL;

	MPRINT("MEMORY RING ALLOC %d\n", num_messages);
	mr->messages = talloc_zero_array(mr, fr_message_t, num_messages);
	if (!mr->messages) {
		talloc_free(mr);
		return NULL;
	}

	mr->size = num_messages;

	return mr;
}



/** Create a message set
 *
 * @param[in] ctx the context for talloc
 * @param[in] num_messages size of the initial message array.  MUST be a power of 2.
 * @param[in] ring_buffer_size of the ring buffer.  MUST be a power of 2.
 * @return
 *    NULL on error
 *    newly allocated fr_message_set_t on success
 */
fr_message_set_t *fr_message_set_create(TALLOC_CTX *ctx, int num_messages, size_t ring_buffer_size)
{
	fr_message_set_t *ms;

	/*
	 *	Too small, or not a power of 2.
	 */
	if (num_messages < 8) return NULL;

	if ((num_messages & (num_messages - 1)) != 0) return NULL;

	if (ring_buffer_size < 1024) return NULL;

	if ((ring_buffer_size & (ring_buffer_size - 1)) != 0) return NULL;

	ms = talloc_zero(ctx, fr_message_set_t);
	if (!ms) return NULL;

	ms->m_array[0] = fr_message_ring_create(ms, num_messages);
	if (!ms->m_array[0]) {
		talloc_free(ms);
		return NULL;
	}

	ms->rb_array[0] = fr_ring_buffer_create(ms, ring_buffer_size);
	if (!ms->rb_array[0]) {
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
 * @param[in] ms the message set
 * @param[in] m the message to make as done.
 * @return
 *     <0 on error
 *	0 on success
 */
int fr_message_done(DBG_UNUSED fr_message_set_t *ms, fr_message_t *m)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	rad_assert(m->type != FR_MESSAGE_FREE);
	rad_assert(m->type != FR_MESSAGE_DONE);

	/*
	 *	Mark a message as freed.  The originator will take
	 *	care of cleaning it up.
	 */
	if (m->type == FR_MESSAGE_USED) {
		m->type = FR_MESSAGE_DONE;
		return 0;
	}

	/*
	 *	This message was localized, so we can free it via
	 *	talloc.
	 */
	if (m->type == FR_MESSAGE_LOCALIZED) {
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
 * @param[in] ms the message set
 * @param[in] m the message to be localized
 * @param[in] ctx the talloc context to use for localization
 * @return
 *      NULL on allocation errror
 *	a newly localized message
 */
fr_message_t *fr_message_localize(DBG_UNUSED fr_message_set_t *ms, fr_message_t *m, TALLOC_CTX *ctx)
{
	fr_message_t *l;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	if (m->type != FR_MESSAGE_USED) {
		return NULL;
	}

	l = talloc_memdup(ctx, m, sizeof(*m));
	if (!l) return NULL;

	if (l->data_size) {
		l->data = talloc_memdup(l, l->data, l->data_size);
		if (!l->data) {
			talloc_free(l);
			return NULL;
		}
	}

	l->type = FR_MESSAGE_LOCALIZED;

	/*
	 *	After this change, "m" should not be used for
	 *	anything.
	 */
	m->type = FR_MESSAGE_DONE;

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
static int fr_message_ring_cleanup(fr_message_set_t *ms, fr_message_ring_t *mr, int max_to_clean)
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
		rad_assert(mr->messages[i].type != FR_MESSAGE_FREE);

		if (mr->messages[i].type != FR_MESSAGE_DONE) {
			max_to_clean = messages_cleaned;
			break;
		}

		mr->data_start++;
		messages_cleaned++;
		mr->messages[i].type = FR_MESSAGE_FREE;
		ms->freed++;

		if (mr->messages[i].rb) {
			(void) fr_ring_buffer_free(mr->messages[i].rb,
						   mr->messages[i].rb_size);
#ifndef NDEBUG
			memset(&mr->messages[i], 0, sizeof(mr->messages[i]));
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


/** Clean up "done" messages.
 *
 *  Called only from the originating thread.  We also clean a limited
 *  number of messages at a time, so that we don't have sudden latency
 *  spikes when cleaning 1M messages.
 *
 * @param[in] ms the message set
 * @param[in] max_to_clean the maximum number of messages to clean
 */
static void fr_message_cleanup(fr_message_set_t *ms, int max_to_clean)
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

	for (i = 0; i <= ms->m_max; i++) {

		fr_message_ring_t *mr = ms->m_array[i];

		(void) fr_message_ring_cleanup(ms, mr, max_to_clean);

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
			if (i == ms->m_max) {
				empty_slot = i;
				continue;
			}

			/*
			 *	We now have at least two arrays which
			 *	are free.  Free the old one, and keep
			 *	the new one.
			 */
			TALLOC_FREE(ms->m_array[empty_slot]);
			arrays_freed++;
			empty_slot = i;
		}

		/*
		 *	If we're cleaning up small array entries, do
		 *	so aggressively.  This allows for smaller
		 *	arrays to be cleaned up and freed, so that we
		 *	can keep using large arrays.
		 */
		if ((i + 2) < ms->m_max) {
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
		for (i = 0; i < ms->m_max; i++) {
			if (ms->m_array[i] != NULL) continue;


			memmove(&ms->m_array[i], &ms->m_array[i + 1],
				sizeof(ms->m_array[i]) * (ms->m_max - i + 1));

			if (empty_slot > i) empty_slot--;
		}

		/*
		 *	Reset the max, and current to the lowest
		 *	array entry.
		 */
		ms->m_max -= arrays_freed;

#ifndef NDEBUG
		for (i = 0; i <= ms->m_max; i++) {
			rad_assert(ms->m_array[i] != NULL);
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
		ms->m_current = ms->m_max;
		MPRINT("SET MR to %d\n", ms->m_current);
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
		}

		/*
		 *	Reset the max, and current to the lowest
		 *	array entry.
		 */
		ms->rb_max -= arrays_freed;

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
 *      NULL on failed allocation
 *      fr_message_t* on successful allocation.
 */
static fr_message_t *fr_message_ring_alloc(fr_message_set_t *ms, fr_message_ring_t *mr, bool clean)
{
	fr_message_t *m;

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
			if (fr_message_ring_cleanup(ms, mr, 4) == 0) {
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
		m = &mr->messages[mr->write_offset];
		mr->write_offset++;

		memset(m, 0, sizeof(*m));
		m->type = FR_MESSAGE_USED;
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

	m = &mr->messages[mr->write_offset];
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

	memset(m, 0, sizeof(*m));
	m->type = FR_MESSAGE_USED;
	return m;
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
 *      NULL on error
 *	fr_message_t* on success
 */
fr_message_t *fr_message_reserve(fr_message_set_t *ms, size_t reserve_size)
{
	int i;
	bool cleaned_up = false;
	fr_message_t *m;
	fr_message_ring_t *mr;
	fr_ring_buffer_t *rb;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	if (reserve_size > ms->max_allocation) return NULL;

	ms->allocated++;

	/*
	 *	Grab the current message array.  In the general case,
	 *	there's room, so we grab a message and go find a ring
	 *	buffer.
	 */
	mr = ms->m_array[ms->m_current];
	m = fr_message_ring_alloc(ms, mr, true);
	if (m) {
		MPRINT("ALLOC normal\n");
		goto get_rb;
	}

	MPRINT("CLEANING UP (%zd - %zd = %zd)\n", ms->allocated, ms->freed,
		ms->allocated - ms->freed);

	/*
	 *	Else the buffer is full.  Do a global cleanup.
	 */
	fr_message_cleanup(ms, 128);
	cleaned_up = true;

	/*
	 *	If we're lucky, the cleanup has given us a new
	 *	"current" buffer, which is empty.  If so, use it.
	 */
	mr = ms->m_array[ms->m_current];
	m = fr_message_ring_alloc(ms, mr, true);
	if (m) {
		MPRINT("ALLOC after cleanup\n");
		goto get_rb;
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
	for (i = ms->m_max; i >= 0; i--) {
		mr = ms->m_array[i];

		m = fr_message_ring_alloc(ms, mr, true);
		if (m) {
			ms->m_current = i;
			MPRINT("ALLOC from changed ring buffer\n");
			MPRINT("SET MR to changed %d\n", ms->m_current);
			goto get_rb;
		}
	}

	/*
	 *	All of the arrays are full.  If we don't have
	 *	room to allocate another array, we're dead.
	 */
	if ((ms->m_max + 1) >= M_ARRAY_SIZE) {
		return NULL;
	}

	/*
	 *	Allocate another message ring, double the size
	 *	of the previous maximum.
	 */
	mr = fr_message_ring_create(ms, ms->m_array[ms->m_max]->size * 2);
	if (!mr) return NULL;

	/*
	 *	Set the new one as current for all new
	 *	allocations, allocate a message, and go try to
	 *	reserve room for the raw packet data.
	 */
	ms->m_max++;
	ms->m_current = ms->m_max;
	ms->m_array[ms->m_max] = mr;

	MPRINT("SET MR to doubled %d\n", ms->m_current);

	/*
	 *	And we should now have an entirely empty message ring.
	 */
	m = fr_message_ring_alloc(ms, mr, false);
	if (!m) return NULL;
	MPRINT("ALLOC after doubled message ring\n");
	
get_rb:
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

	/*
	 *	And... we go through all of the above hoops, all over again.
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

		fr_message_cleanup(ms, 128);

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
	if ((ms->rb_max + 1) >= M_ARRAY_SIZE) {
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
	if (m) return m;

cleanup:
	MPRINT("OUT OF MEMORY\n");

	/*
	 *	Undo the allocation we did here.  Which requires us to
	 *	remember that "mr" was the message ring from which we
	 *	allocated the message.
	 */
	m->rb = NULL;
	m->type = FR_MESSAGE_FREE;

	mr->write_offset--;
	ms->allocated--;

	return NULL;
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
 * @param[in] actual_packet_size to reserve
 * @return
 *      NULL on error
 *	fr_message_t* on success
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

	rad_assert(m->type == FR_MESSAGE_USED);
	rad_assert(m->rb != NULL);
	rad_assert(m->data != NULL);
	rad_assert(m->data_size == 0);
	rad_assert(m->rb_size >= actual_packet_size);

	p = fr_ring_buffer_alloc(m->rb, actual_packet_size);
	rad_assert(p != NULL);
	if (!p) {
		// allocation failure, fix M.
		return NULL;
	}

	rad_assert(p == m->data);

	/*
	 *	The caller can change m->data size to soemthing a bit
	 *	smaller, e.g. for cache alignment issues.
	 */
	m->data_size = actual_packet_size;
	m->rb_size = actual_packet_size;
	return m;
}

#define MS_ALIGN_SIZE (16)
#define MS_ALIGN(_x) (((_x) + (MS_ALIGN_SIZE-1) ) & ~(MS_ALIGN_SIZE-1))

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
 *      NULL on error
 *	fr_message_t* on success
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
		m = fr_message_reserve(ms, actual_packet_size + 2 * MS_ALIGN_SIZE);
		if (!m) return NULL;
	}

	rad_assert(m->type == FR_MESSAGE_USED);
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
	MS_ALIGN(aligned_size);

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
 *      number of used messages
 */
int fr_message_set_messages_used(fr_message_set_t *ms)
{
	int i, used;

#ifndef NDEBUG
	(void) talloc_get_type_abort(ms, fr_message_set_t);
#endif

	used = 0;
	for (i = 0; i <= ms->m_max; i++) {
		fr_message_ring_t *mr;

		mr = ms->m_array[i];

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
	for (i = 0; i <= ms->m_max; i++) {
		num_cleaned += fr_message_ring_cleanup(ms, ms->m_array[i],
						       ms->m_array[i]->size);
	}

	MPRINT("GC cleaned %d\n", num_cleaned);

	/*
	 *	And then do omne last pass to clean up the arrays.
	 */
	fr_message_cleanup(ms, 1 << 24);
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

	fprintf(fp, "message arrays = %d\t(current %d)\n", ms->m_max + 1, ms->m_current);
	fprintf(fp, "ring buffers   = %d\t(current %d)\n", ms->rb_max + 1, ms->rb_current);

	for (i = 0; i <= ms->m_max; i++) {
		fr_message_ring_t *mr = ms->m_array[i];

		fprintf(fp, "messages[%d] =\tsize %d, write_offset %d, data_start %d, data_end %d\n",
			i, mr->size, mr->write_offset, mr->data_start, mr->data_end);
	}

	for (i = 0; i <= ms->rb_max; i++) {
		fprintf(fp, "ring buffer[%d] =\tsize %zd, used %zd\n",
			i, fr_ring_buffer_size(ms->rb_array[i]), fr_ring_buffer_used(ms->rb_array[i]));
	}
}
