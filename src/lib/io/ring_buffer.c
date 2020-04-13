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
 * @brief Simple ring buffers for packet contents
 * @file io/ring_buffer.c
 *
 * @copyright 2016 Alan DeKok (aland@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/io/ring_buffer.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/debug.h>
#include <string.h>

/*
 *	Ring buffers are allocated in a block.
 */
struct fr_ring_buffer_s {
	uint8_t		*buffer;	//!< actual start of the ring buffer
	size_t		size;		//!< Size of this ring buffer

	size_t		data_start;	//!< start of used portion of the buffer
	size_t		data_end;	//!< end of used portion of the buffer

	size_t		write_offset;	//!< where writes are done
	size_t		reserved;	//!< amount of reserved data at write_offset

	bool		closed;		//!< whether allocations are closed
};

/** Create a ring buffer.
 *
 *  The size provided will be rounded up to the next highest power of
 *  2, if it's not already a power of 2.
 *
 *  The ring buffer manages how much room is reserved (i.e. available
 *  to write to), and used.  The application is responsible for
 *  tracking the start of the reservation, *and* it's write offset
 *  within that reservation.
 *
 * @param[in] ctx	a talloc context
 * @param[in] size	of the raw ring buffer array to allocate.
 * @return
 *	- A new ring buffer on success.
 *	- NULL on failure.
 */
fr_ring_buffer_t *fr_ring_buffer_create(TALLOC_CTX *ctx, size_t size)
{
	fr_ring_buffer_t	*rb;

	rb = talloc_zero(ctx, fr_ring_buffer_t);
	if (!rb) {
	fail:
		fr_strerror_printf("Failed allocating memory.");
		return NULL;
	}

	if (size < 1024) size = 1024;

	if (size > (1 << 30)) {
		fr_strerror_printf("Ring buffer size must be no more than (1 << 30)");
		return NULL;
	}

	/*
	 *	Round up to the nearest power of 2.
	 */
	size--;
	size |= size >> 1;
	size |= size >> 2;
	size |= size >> 4;
	size |= size >> 8;
	size |= size >> 16;
	size++;

	rb->buffer = talloc_array(rb, uint8_t, size);
	if (!rb->buffer) {
		talloc_free(rb);
		goto fail;
	}
	rb->size = size;

	return rb;
}


/** Reserve room in the ring buffer.
 *
 *  The size does not need to be a power of two.  The application is
 *  responsible for doing cache alignment, if required.
 *
 *  If the reservation fails, the application should create a new ring
 *  buffer, and start reserving data there.
 *
 * @param[in] rb a ring buffer
 * @param[in] size to see if we can reserve
 * @return
 *	- NULL on error.  Which can only be "ring buffer is full".
 *      - pointer to data on success
 */
uint8_t *fr_ring_buffer_reserve(fr_ring_buffer_t *rb, size_t size)
{
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	if (rb->closed) {
		fr_strerror_printf("Allocation request after ring buffer is closed");
		return NULL;
	}

	/*
	 *	We're writing to the start of the buffer, and there is
	 *	already data in it.  See if the data fits.
	 *
	 *	|***W....S****E....|
	 */
	if (rb->write_offset < rb->data_start) {
		if ((rb->write_offset + size) < rb->data_start) {
			rb->reserved = size;
			return rb->buffer + rb->write_offset;
		}

		fr_strerror_printf("No memory available in ring buffer");
		return NULL;
	}

	fr_assert(rb->write_offset == rb->data_end);

	/*
	 *	Data fits at the end of the ring buffer.
	 *
	 *	|....S****WE....|
	 */
	if ((rb->write_offset + size) <= rb->size) {
		rb->reserved = size;
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
		rb->reserved = size;
		return rb->buffer;
	}

	/*
	 *	Not enough room for the new data, fail the allocation.
	 *
	 *	|....S****WE....|
	 */
	fr_strerror_printf("No memory available in ring buffer");
	return NULL;
}


/** Mark data as allocated.
 *
 *  The size does not need to be a power of two.  The application is
 *  responsible for doing cache-line alignment, if required.
 *
 *  The application does NOT need to call fr_ring_buffer_reserve() before
 *  calling this function.
 *
 *  If the allocation fails, the application should create a new ring
 *  buffer, and start allocating data there.
 *
 * @param[in] rb a ring buffer
 * @param[in] size to mark as "used" at the tail end of the buffer.
 * @return
 *	- NULL on error.  Which can only be "ring buffer is full".
 *      - pointer to data on success
 */
uint8_t *fr_ring_buffer_alloc(fr_ring_buffer_t *rb, size_t size)
{
	uint8_t *p;

	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	if (rb->closed) {
#ifndef NDEBUG
		fr_strerror_printf("Allocation request after ring buffer is closed");
#endif
		return NULL;
	}

	/*
	 *	Shrink the "reserved" portion of the buffer by the
	 *	allocated size.
	 */
	if (rb->reserved >= size) {
		rb->reserved -= size;
	} else {
		rb->reserved = 0;
	}

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

#ifndef NDEBUG
		fr_strerror_printf("No memory available in ring buffer");
#endif
		return NULL;
	}

	fr_assert(rb->write_offset == rb->data_end);

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
#ifndef NDEBUG
	fr_strerror_printf("No memory available in ring buffer");
#endif
	return NULL;
}


/** Split an existing reservation into two.
 *
 *  For protocols like TCP, there may sometimes be a partial packet at
 *  the end of the ring buffer.  We would like to pass a *complete*
 *  packet around instead of a partial one.  In that case, the partial
 *  packet at the end of the buffer should be copied to a reservation
 *  in a new ring buffer.
 *
 *  i.e. the application uses fr_ring_buffer_reserve() to reserve 32K
 *  of room.  He then reads 32K of data into that buffer.  This data
 *  comprises 3 full packets of 10K, and one partial packet of 10K.
 *  The application then calls fr_ring_buffer_alloc() three times, to
 *  consume those packets.  (Note that the caller doesn't really need
 *  to do 3 calls to fr_ring_buffer_alloc().  The ring buffer does not
 *  keep track of individual allocations).
 *
 *  The application then calls fr_ring_buffer_reserve() to reserve
 *  another 32K of room, while leaving 2K of data in the ring buffer.
 *  If that reservation succeeds, great.  Everything proceeds as
 *  before.  (Note that the application has to remember how much data
 *  was in the ring buffer, and do it's reading there, instead of to
 *  the pointer returned from fr_ring_buffer_reserve()).
 *
 *  If that call fails, there is 2K of partial data in the buffer
 *  which needs to be moved.  The application should allocate a new
 *  ring buffer, and then call this function to move the data to the
 *  new ring buffer.  The application then uses the new reservation to
 *  read data.
 *
 * @param[in] dst ring buffer where the reservation will be made
 * @param[in] reserve_size size of the new reservation
 * @param[in] src ring buffer where the data is sitting.
 * @param[in] move_size of data to move from the tail of the buffer to the start.
 * @return
 *	- NULL on error.
 *      - pointer to data on success
 */
uint8_t *fr_ring_buffer_reserve_split(fr_ring_buffer_t *dst, size_t reserve_size,
				      fr_ring_buffer_t *src, size_t move_size)
{
	uint8_t *p;

	(void) talloc_get_type_abort(src, fr_ring_buffer_t);
	(void) talloc_get_type_abort(dst, fr_ring_buffer_t);

	if (dst->closed) {
		fr_strerror_printf("Allocation request after ring buffer is closed");
		return NULL;
	}

	/*
	 *	The application hasn't reserved enough space, so we can't
	 *	split the reservation.
	 */
	if (src->reserved < move_size) {
		fr_strerror_printf("Cannot move more data than was reserved.");
		return NULL;
	}

	/*
	 *	Create a new reservation.
	 */
	p = fr_ring_buffer_reserve(dst, reserve_size);
	if (!p) return NULL;

	/*
	 *	Alloc and reserve in the same ring buffer.  Maybe
	 *	there's no need to memcpy() the data?
	 */
	if ((src == dst) && (p == (src->buffer + src->write_offset))) {
		return 0;
	}

	/*
	 *	Copy the data from the old buffer to the new one.
	 */
	memcpy(p, src->buffer + src->write_offset, move_size);

	/*
	 *	We now have no data reserved here.  All bets are
	 *	off...
	 */
	src->reserved = 0;

	return p;
}


/** Mark data as free,
 *
 *  The size does not need to be a power of two.  The application is
 *  responsible for doing cache alignment, if required.  The
 *  application is responsible for tracking sizes of packets in the
 *  ring buffer.
 *
 *  If "unused" bytes are more than what's in the buffer, the used
 *  bytes are reset to zero.
 *
 * @param[in] rb a ring buffer
 * @param[in] size_to_free bytes to mark as "unused" in the buffer.
 * @return
 *	- <0 on error.  Which can only be "ring buffer is full".
 *      - 0 on success
 */
int fr_ring_buffer_free(fr_ring_buffer_t *rb, size_t size_to_free)
{
	size_t block_size;

	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	/*
	 *	Nothing to free, do nothing.
	 */
	if (!size_to_free) return 0;

	/*
	 *	Freeing data from the middle of the buffer.
	 *
	 *	|***W....S****E....|
	 */
	if (rb->write_offset < rb->data_start) {
		block_size = rb->data_end - rb->data_start;

		/*
		 *	|***W....S****E....|, free 3
		 *
		 *	|***W.......S*E....|
		 */
		if (size_to_free < block_size) {
			rb->data_start += size_to_free;
			return 0;
		}

		/*
		 *	Free all (or more than) the block.
		 */
		rb->data_start = 0;
		rb->data_end = rb->write_offset;
		size_to_free -= block_size;

		/*
		 *	Free everything left: empty the buffer
		 *	entirely.  This also handles the case of
		 *	size_to_free==0 and write_offset==0.
		 */
		if (size_to_free == rb->write_offset) {
			goto empty_buffer;
		}

		/*
		 *	The buffer has data but we're not freeing
		 *	any more of it, return.
		 */
		if (!size_to_free) return 0;
	}

	fr_assert(rb->write_offset == rb->data_end);

	block_size = rb->data_end - rb->data_start;

	/*
	 *	Freeing too much, return an error.
	 */
	if (size_to_free > block_size) {
		fr_strerror_printf("Cannot free more memory than exists.");
		return -1;
	}

	/*
	 *	Free some data from the start.
	 */
	if (size_to_free < block_size) {
		rb->data_start += size_to_free;
		return 0;
	}

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
 *	- <0 on error.
 *      - 0 on success
 */
int fr_ring_buffer_close(fr_ring_buffer_t *rb)
{
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	rb->closed = true;
	return 0;
}


/** Get the size of the ring buffer
 *
 * @param[in] rb a ring buffer
 * @return size of the ring buffer.
 *	- <0 on error.
 *      - 0 on success
 */
size_t fr_ring_buffer_size(fr_ring_buffer_t *rb)
{
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	return rb->size;
}

/** Get the amount of data used in a ring buffer.
 *
 * @param[in] rb a ring buffer
 * @return size of the used data in the ring buffer.
 *	- <0 on error.
 *      - 0 on success
 */
size_t fr_ring_buffer_used(fr_ring_buffer_t *rb)
{
	size_t size;

	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	if (rb->write_offset < rb->data_start) {
		size = rb->write_offset;
	} else {
		fr_assert(rb->write_offset == rb->data_end);
		size = 0;
	}

	size += (rb->data_end - rb->data_start);

	return size;
}

/** Get a pointer to the data at the start of the ring buffer.
 *
 * @param[in] rb a ring buffer
 * @param[out] p_start pointer to data at the start of the ring buffer
 * @param[in] p_size size of the allocated block at the start of the ring buffer.
 * @return size of the used data in the ring buffer.
 *	- <0 on error.
 *      - 0 on success
 */
int fr_ring_buffer_start(fr_ring_buffer_t *rb, uint8_t **p_start, size_t *p_size)
{
	(void) talloc_get_type_abort(rb, fr_ring_buffer_t);

	*p_start = rb->buffer + rb->data_start;

	if (rb->write_offset < rb->data_start) {
		*p_size = rb->write_offset;
		return 0;
	}

	*p_size = (rb->data_end - rb->data_start);

	return 0;
}

/** Print debug information about the ring buffer
 *
 * @param[in] rb the ring buffer
 * @param[in] fp the FILE where the messages are printed.
 */
void fr_ring_buffer_debug(fr_ring_buffer_t *rb, FILE *fp)
{
	fprintf(fp, "Buffer %p, write_offset %zu, data_start %zu, data_end %zu\n",
		rb->buffer, rb->write_offset, rb->data_start, rb->data_end);
}
