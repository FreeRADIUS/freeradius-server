/*
 * ring_buffer.c	Simple ring buffers for packet contents.
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

#include <freeradius-devel/ring_buffer.h>
#include <freeradius-devel/rad_assert.h>
#include <string.h>

/*
 *	Ring buffers are allocated in a block.
 */
struct fr_ring_buffer_t {
	uint8_t		*buffer;	//!< actual start of the ring buffer
	size_t		size;		//!< Size of this ring buffer

	size_t		data_start;	//!< start of used portion of the buffer
	size_t		data_end;	//!< end of used portion of the buffer

	size_t		write_offset;	//!< where writes are done

	bool		closed;		//!< whether allocations are closed
};


/** Create a ring buffer.
 *
 *  The ring buffer should be a power of two in size.
 *
 * @param[in] ctx a talloc context
 * @param[in] size of the raw ring buffer array to allocate.
 * @return a ring buffer, or NULL on failure.
 */
fr_ring_buffer_t *fr_ring_buffer_create(TALLOC_CTX *ctx, size_t size)
{
	fr_ring_buffer_t *rb;

	rb = talloc_zero(ctx, fr_ring_buffer_t);
	if (!rb) return NULL;

	rb->buffer = talloc_array(rb, uint8_t, size);
	if (!rb->buffer) {
		talloc_free(rb);
		return NULL;
	}

	rb->size = size;
	return rb;
}


/** Check if we can reserve bytes in the ring buffer.
 *
 *  The size does not need to be a power of two.  The caller is
 *  responsible for doing cache alignment, if required.
 *
 *  If the reservation fails, the caller should create a new ring
 *  buffer, and start reserving data there.
 *
 * @param[in] rb a ring buffer
 * @param[in] size to see if we can reserve
 * @return
 *	NULL on error.  Which can only be "ring buffer is full".
 *      pointer to data on success
 */
uint8_t *fr_ring_buffer_reserve(fr_ring_buffer_t *rb, size_t size)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	if (rb->closed) return NULL;

	/*
	 *	We're writing to the start of the buffer, and there is
	 *	already data in it.  See if the data fits.
	 *
	 *	|***W....S****E....|
	 */
	if (rb->write_offset < rb->data_start) {
		if ((rb->write_offset + size) < rb->data_start) {
			return rb->buffer + rb->write_offset;
		}

		return NULL;
	}

	/*
	 *	Data fits at the end of the ring buffer.
	 *
	 *	|....S****WE....|
	 */
	if ((rb->write_offset + size) <= rb->size) {
		return rb->buffer + rb->write_offset;
	}

	/*
	 *	Data fits at the start of the ring buffer, ensure that
	 *	we write it there.  This also catches the case where
	 *	data_start==0.
	 *
	 *	|W....S****E....|
	 */
	if (size < rb->data_start) {
		rb->write_offset = 0;
		return rb->buffer;
	}

	/*
	 *	Not enough room for the new data, fail the allocation.
	 *
	 *	|....S****WE....|
	 */
	return NULL;
}


/** Mark data as allocated.
 *
 *  The size does not need to be a power of two.  The caller is
 *  responsible for doing cache alignment, if required.
 *
 *  If the allocation fails, the caller should create a new ring
 *  buffer, and start allocating data there.
 *
 * @param[in] rb a ring buffer
 * @param[in] size to mark as "used" at the tail end of the buffer.
 * @return
 *	NULL on error.  Which can only be "ring buffer is full".
 *      pointer to data on success
 */
uint8_t *fr_ring_buffer_alloc(fr_ring_buffer_t *rb, size_t size)
{
	uint8_t *p;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	if (rb->closed) return NULL;

	/*
	 *	We're writing to the start of the buffer, and there is
	 *	already data in it.  See if the data fits.
	 *
	 *	|***W....S****E....|
	 */
	if (rb->write_offset < rb->data_start) {
		if ((rb->write_offset + size) < rb->data_start) {
			p = rb->buffer + rb->write_offset;
			rb->write_offset += size;
			return p;
		}

		return NULL;
	}

	/*
	 *	Data fits at the end of the ring buffer.
	 *
	 *	|....S****WE....|
	 */
	if ((rb->write_offset + size) <= rb->size) {
		p = rb->buffer + rb->write_offset;

		rb->write_offset += size;
		rb->data_end = rb->write_offset;

		/*
		 *	Don't update write_offset if it's fallen off
		 *	of the end of the buffer.  The data_start may
		 *	be zero, and we don't want to over-write
		 *	that.
		 */
		return p;
	}

	/*
	 *	Data fits at the start of the ring buffer, ensure that
	 *	we write it there.  This also catches the case where
	 *	data_start==0.
	 *
	 *	|W....S****E....|
	 */
	if (size < rb->data_start) {
		rb->write_offset = size;

		/*
		 *	Don't update data_end.  It points to the tail
		 *	end of the ring buffer.
		 */
		return rb->buffer;
	}

	/*
	 *	Not enough room for the new data, fail the allocation.
	 *
	 *	|....S****WE....|
	 */
	return NULL;
}


/** Move data from the end of the buffer to the start.
 *
 *  For protocols like TCP, there may sometimes be a partial packet at
 *  the end of the ring buffer.  We would like to pass a *complete*
 *  packet around instead of a partial one.  In that case, the partial
 *  packet at the end of the buffer should be copied to the start of
 *  the buffer, and the various pointers adjusted.
 *
 *  Note that the currently allocated data MUST exactly reach the end
 *  of the ring buffer, and the start of the ring buffer MUST NOT have
 *  any data in it.  If either condition fails, or if there isn't
 *  enough room for the data, the allocation fails.
 *
 *  The caller could arguable do this themselves via calls to
 *  fr_ring_buffer_reserve() and fr_ring_buffer_shrink(), and a
 *  memcpy().  But having an API means less code duplication, and more
 *  assertions.
 *
 * @param[in] rb a ring buffer
 * @param[in] move_size of data to move from the tail of the buffer to the start.
 * @param[in] reserve_size size of the data to reserve at the start of the buffer.
 * @return
 *	NULL on error.
 *      pointer to data on success
 */
uint8_t *fr_ring_buffer_move(fr_ring_buffer_t *rb, size_t move_size, size_t reserve_size)
{
	uint8_t *p;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	if (rb->closed) return NULL;

	/*
	 *	Not at the end of the buffer.
	 */
	if (rb->write_offset != rb->size) return NULL;

	/*
	 *	Asked to move more data than is in the buffer.
	 */
	if (rb->data_start + move_size > rb->size) return NULL;

	/*
	 *	Allocate the new memory.  If it exists, it must be at
	 *	the start of the buffer.
	 */
	p = fr_ring_buffer_reserve(rb, reserve_size);
	if (!p) return NULL;

	rad_assert(p = rb->buffer);
	rad_assert(rb->data_end == rb->write_offset);

	/*
	 *	Copy the data to the start of the buffer, and shift
	 *	the "data end" pointer down to compensate.
	 */
	memcpy(p, rb->buffer + rb->size - move_size, move_size);
	rb->data_end -= move_size;

	return p;
}


/** Shrink the data in the ring buffer.
 *
 *  The partner to fr_ring_buffer_move().  If calling
 *  fr_ring_buffer_move() fails, then the caller needs to move the
 *  partial packet to a *new* ring buffer.  In that case, the caller
 *  allocates a new ring buffer, reserves memory there, manually
 *  memcpy()'s the data over, and then calls fr_ring_buffer_shrink()
 *  to inform the buffer that the trailing data is no longer relevant.
 *
 * @param[in] rb a ring buffer
 * @param[in] data pointer to the data to free
 * @param[in] size of data to discard from the end of the buffer.
 * @return
 *	<0 on error
 *      0 on success
 */
int fr_ring_buffer_shrink(fr_ring_buffer_t *rb, uint8_t *data, size_t size)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	/*
	 *	Callers can shrink a closed ring buffer.
	 */

	/*
	 *	Free data from the start of the buffer.
	 */
	if (rb->write_offset < rb->data_start) {
		if (rb->write_offset < size) return -1;

		if ((data + size) != (rb->buffer + rb->write_offset)) return -1;

		rb->write_offset -= size;

		/*
		 *	If the write_offset is at the start of the
		 *	buffer, back it up to the end of the buffer.
		 */
		if ((rb->write_offset == 0) &&
		    (rb->data_end < rb->size)) {
			rb->write_offset = rb->data_end;
		}

		return 0;
	}

	/*
	 *	Free data from the middle of the buffer.
	 */
	if ((rb->data_end - rb->data_start) > size) return -1;

	if ((data + size) != (rb->buffer + rb->data_end)) return -1;

	rb->data_end -= size;
	rb->write_offset = rb->data_end;

	return 0;
}


/** Mark data as free,
 *
 *  The size does not need to be a power of two.  The caller is
 *  responsible for doing cache alignment, if required.  The caller is
 *  responsible for tracking sizes of packets in the ring buffer.
 *
 *  If "unused" bytes are more than what's in the buffer, the used
 *  bytes are reset to zero.
 *
 * @param[in] rb a ring buffer
 * @param[in] size to mark as "unused" in the buffer.
 * @return
 *	<0 on error.  Which can only be "ring buffer is full".
 *      0 on success
 */
int fr_ring_buffer_free(fr_ring_buffer_t *rb, size_t size)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	/*
	 *	Nothing to free, do nothing.
	 */
	if (!size) return 0;

	/*
	 *	Freeing data from the middle of the buffer.
	 *
	 *	|***W....S****E....|
	 */
	if (rb->write_offset < rb->data_start) {
		size_t block_size;

		block_size = rb->data_end - rb->data_start;

		/*
		 *	|***W....S****E....|, free 3
		 *
		 *	|***W.......S*E....|
		 */
		if (size < block_size) {
			rb->data_start += size;
			return 0;
		}

		/*
		 *	Free all (or more than) the block.
		 */
		rb->data_start = 0;
		rb->data_end = rb->write_offset;
		size -= block_size;

		/*
		 *	Free everything left: empty the buffer
		 *	entirely.  This also handles the case of
		 *	size==0 and write_offset==0.
		 */
		if (size == rb->write_offset) {
			goto empty_buffer;
		}

		/*
		 *	The buffer has data but we're not freeing
		 *	any more of it, return.
		 */
		if (!size) return 0;
	}

	/*
	 *	Free some data from the start.
	 */
	if (size < rb->data_end) {
		rb->data_start += size;
		return 0;
	}

	/*
	 *	Freeing too much, return an error.
	 */
	if (size > rb->data_end) return -1;

	/*
	 *	Free all data in the buffer.
	 */
empty_buffer:
	rb->data_start = 0;
	rb->data_end = 0;
	rb->write_offset = 0;

	/*
	 *	If the ring buffer is closed to all allocations, and
	 *	it's now empty, we automatically free it.
	 */
	if (rb->closed) talloc_free(rb);

	return 0;
}

/** Close a ring buffer so that no further allocations can take place.
 *
 *  Once the ring buffer is empty, it will be automatically freed.
 *  It's called "close" and not "delete", because the ring buffer will
 *  still be active until all data has been removed.
 *
 *  If you don't care about the data in the ring buffer, you can just
 *  call talloc_free() on it.
 *
 * @param[in] rb a ring buffer
 * @return
 *	<0 on error.
 *      0 on success
 */
int fr_ring_buffer_close(fr_ring_buffer_t *rb)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	rb->closed = true;
	return 0;
}


/** Get the size of the ring buffer
 *
 * @param[in] rb a ring buffer
 * @return size of the ring buffer.
 *	<0 on error.
 *      0 on success
 */
size_t fr_ring_buffer_size(fr_ring_buffer_t *rb)
{
#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	return rb->size;
}

/** Get the amount of data used in a ring buffer.
 *
 * @param[in] rb a ring buffer
 * @return size of the used data in the ring buffer.
 *	<0 on error.
 *      0 on success
 */
size_t fr_ring_buffer_used(fr_ring_buffer_t *rb)
{
	size_t size;

#ifndef NDEBUG
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);
#endif

	if (rb->write_offset < rb->data_start) {
		size = rb->write_offset;
	} else {
		size = 0;
	}

	size += (rb->data_end - rb->data_start);

	return size;
}
