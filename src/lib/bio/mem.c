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
 * @file lib/bio/mem.c
 * @brief BIO abstractions for memory buffers
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/buf.h>

#include <freeradius-devel/bio/mem.h>

/** The memory buffer bio
 *
 *  It is used to buffer reads / writes to a streaming socket.
 */
typedef struct fr_bio_mem_s {
	FR_BIO_COMMON;

	fr_bio_verify_t	verify;		//!< verify data to see if we have a packet.
	void		*verify_ctx;	//!< verify context

	fr_bio_buf_t	read_buffer;	//!< buffering for reads
	fr_bio_buf_t	write_buffer;	//!< buffering for writes
} fr_bio_mem_t;

static ssize_t fr_bio_mem_write_buffer(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);

static int     fr_bio_mem_call_verify(fr_bio_t *bio, void *packet_ctx, size_t *size) CC_HINT(nonnull(1,3));

/** At EOF, read data from the buffer until it is empty.
 *
 *  When "next" bio returns EOF, there may still be pending data in the memory buffer.  Return that until it's
 *  empty, and then EOF from then on.
 */
static ssize_t fr_bio_mem_read_eof(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	/*
	 *	No more data: return EOF from now on.
	 */
	if (fr_bio_buf_used(&my->read_buffer) == 0) {

		/*
		 *	Don't call our EOF function.  But do tell the other BIOs that we're at EOF.
		 */
		my->priv_cb.eof = NULL;
		fr_bio_eof(&my->bio);
		return 0;
	}

	/*
	 *	Return whatever data we have available.  One the buffer is empty, the next read will get EOF.
	 */
	return fr_bio_buf_read(&my->read_buffer, buffer, size);
}

static int fr_bio_mem_eof(fr_bio_t *bio)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	/*
	 *	Nothing more for us to read, tell fr_bio_eof() that it can continue with poking other BIOs.
	 */
	if (fr_bio_buf_used(&my->read_buffer) == 0) {
		return 1;
	}

	my->bio.read = fr_bio_mem_read_eof;

	return 0;
}

/** Read from a memory BIO
 *
 *  This bio reads as much data as possible into the memory buffer.  On the theory that a few memcpy() or
 *  memmove() calls are much cheaper than a system call.
 *
 *  If the read buffer has enough data to satisfy the read, then it is returned.
 *
 *  Otherwise the next bio is called to re-fill the buffer.  The next read call will try to get as much data
 *  as possible into the buffer, even if that results in reading more than "size" bytes.
 *
 *  Once the next read has been done, then the data from the buffer is returned, even if it is less than
 *  "size".
 */
static ssize_t fr_bio_mem_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	size_t used, room;
	uint8_t *p;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);
	fr_bio_t *next;

	/*
	 *      We can satisfy the read from the memory buffer: do so.
	 */
	used = fr_bio_buf_used(&my->read_buffer);
	if (size <= used) {
		return fr_bio_buf_read(&my->read_buffer, buffer, size);
	}

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	If there's no room to store more data in the buffer.  Just return whatever data we have in the
	 *	buffer.
	 */
	room = fr_bio_buf_write_room(&my->read_buffer);
	if (!room) return fr_bio_buf_read(&my->read_buffer, buffer, size);

	/*
	 *	We try to fill the buffer as much as possible from the network, even if that means reading
	 *	more than "size" amount of data.
	 */
	p = fr_bio_buf_write_reserve(&my->read_buffer, room);
	fr_assert(p != NULL);	/* otherwise room would be zero */

	rcode = next->read(next, packet_ctx, p, room);

	/*
	 *	Ensure that whatever data we have read is marked as "used" in the buffer, and then return
	 *	whatever data is available back to the caller.
	 */
	if (rcode >= 0) {
		if (rcode > 0) (void) fr_bio_buf_write_alloc(&my->read_buffer, (size_t) rcode);

		return fr_bio_buf_read(&my->read_buffer, buffer, size);
	}

	/*
	 *	The next bio returned an error.  Whatever it is, it's fatal.  We can read from the memory
	 *	buffer until it's empty, but we can no longer write to the memory buffer.  Any data written to
	 *	the buffer is lost.
	 */
	bio->read = fr_bio_mem_read_eof;
	bio->write = fr_bio_null_write;
	return rcode;
}

/** Return data only if we have a complete packet.
 *
 */
static ssize_t fr_bio_mem_read_verify(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	size_t used, room, want;
	uint8_t *p;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);
	fr_bio_t *next;

	/*
	 *	We may be able to satisfy the read from the memory buffer.
	 */
	used = fr_bio_buf_used(&my->read_buffer);
	if (used) {
		/*
		 *	See if there are valid packets in the buffer.
		 */
		rcode = fr_bio_mem_call_verify(bio, packet_ctx, &want);
		if (rcode < 0) {
			rcode = fr_bio_error(VERIFY);
			goto fail;
		}

		/*
		 *	There's at least one valid packet, return it.
		 */
		if (rcode == 1) {
			/*
			 *	This isn't a fatal error.  The caller should check how much room is needed by calling
			 *	fr_bio_mem_call_verify(), and retry.
			 *
			 *	But in general, the caller should make sure that the output buffer has enough
			 *	room for at least one packet.  The verify() function should also ensure that
			 *	the packet is no larger than our application maximum, even if the protocol
			 *	allows for it to be larger.
			 */
			if (want > size) return fr_bio_error(BUFFER_TOO_SMALL);

			return fr_bio_buf_read(&my->read_buffer, buffer, want);
		}

		/*
		 *	Else we need to read more data to have a complete packet.
		 */
	}

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	If there's no room to store more data in the buffer, try to make some room.
	 */
	room = fr_bio_buf_write_room(&my->read_buffer);
	if (!room) {
		room = fr_bio_buf_make_room(&my->read_buffer);

		/*
		 *	We've tried to make room and failed.  Which means that the buffer is full, AND there
		 *	still isn't a complete packet in the buffer.  This is therefore a fatal error.  The
		 *	application has not supplied us with enough read_buffer space to store a complete
		 *	packet.
		 */
		if (!room) {
			rcode = fr_bio_error(BUFFER_FULL);
			goto fail;
		}
	}

	/*
	 *	We try to fill the buffer as much as possible from the network.  The theory is that a few
	 *	extra memcpy() or memmove()s are cheaper than a system call for reading each packet.
	 */
	p = fr_bio_buf_write_reserve(&my->read_buffer, room);
	fr_assert(p != NULL);	/* otherwise room would be zero */

	rcode = next->read(next, packet_ctx, p, room);

	/*
	 *	The next bio returned some data.  See if it's a valid packet.
	 */
	if (rcode > 0) {
		(void) fr_bio_buf_write_alloc(&my->read_buffer, (size_t) rcode);

		want = fr_bio_buf_used(&my->read_buffer);
		if (size <= want) want = size;

		/*
		 *	See if there are valid packets in the buffer.
		 */
		rcode = fr_bio_mem_call_verify(bio, packet_ctx, &want);
		if (rcode < 0) {
			rcode = fr_bio_error(VERIFY);
			goto fail;
		}

		/*
		 *	There's at least one valid packet, return it.
		 */
		if (rcode == 1) return fr_bio_buf_read(&my->read_buffer, buffer, want);

		/*
		 *	No valid packets.  The next call to read will call verify again, which will return a
		 *	partial packet.  And then it will try to fill the buffer from the next bio.
		 */
		return 0;
	}

	/*
	 *	No data was read from the next bio, we still don't have a packet.  Return nothing.
	 */
	if (rcode == 0) return 0;

	/*
	 *	The next bio returned an error either when our buffer was empty, or else it had only a partial
	 *	packet in it.  We can no longer read full packets from this BIO, and we can't read from the
	 *	next one, either.  So shut down the BIO completely.
	 */
fail:
	bio->read = fr_bio_fail_read;
	bio->write = fr_bio_fail_write;
	return rcode;
}

/** Return data only if we have a complete packet.
 *
 */
static ssize_t fr_bio_mem_read_verify_datagram(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);
	fr_bio_t *next;

	/*
	 *	There must be a next bio.
	 */
	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	rcode = next->read(next, packet_ctx, buffer, size);
	if (rcode > 0) {
		size_t want = rcode;

		/*
		 *	It's a datagram socket, there can only be one packet in the buffer.
		 *
		 *	@todo - if we're allowed more than one packet in the buffer, we should just call
		 *	fr_bio_mem_read_verify(), or this function should call fr_bio_mem_call_verify().
		 */
		switch (my->verify((fr_bio_t *) my, my->verify_ctx, packet_ctx, buffer, &want)) {
			/*
			 *	The data in the buffer is exactly a packet.  Return that.
			 *
			 *	@todo - if there are multiple packets, return the total size of packets?
			 */
		case FR_BIO_VERIFY_OK:
			fr_assert(want <= (size_t) rcode);
			return want;

			/*
			 *	The data in the buffer doesn't make up a complete packet, discard it.  The
			 *	called verify function should take care of logging.
			 */
		case FR_BIO_VERIFY_WANT_MORE:
			return 0;

		case FR_BIO_VERIFY_DISCARD:
			return 0;

			/*
			 *	Some kind of fatal validation error.
			 */
		case FR_BIO_VERIFY_ERROR_CLOSE:
			break;
		}

		rcode = fr_bio_error(VERIFY);
		goto fail;
	}

	/*
	 *	No data was read from the next bio, we still don't have a packet.  Return nothing.
	 */
	if (rcode == 0) return 0;

	/*
	 *	The next bio returned an error.  Whatever it is, it's fatal.  We can read from the memory
	 *	buffer until it's empty, but we can no longer write to the memory buffer.  Any data written to
	 *	the buffer is lost.
	 */
fail:
	bio->read = fr_bio_mem_read_eof;
	bio->write = fr_bio_null_write;
	return rcode;
}


/** Pass writes to the next BIO
 *
 *  For speed, we try to bypass the memory buffer and write directly to the next bio.  However, if the next
 *  bio returns EWOULDBLOCK, we write the data to the memory buffer, even if it is partial data.
 */
static ssize_t fr_bio_mem_write_next(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	int error;
	ssize_t rcode;
	size_t room, leftover;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);
	fr_bio_t *next;

	/*
	 *	We can't call the next bio if there's still cached data to flush.
	 *
	 *	There must be a next bio.
	 */
	fr_assert(fr_bio_buf_used(&my->write_buffer) == 0);

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	The next bio may write all of the data.  If so, we return that,
	 */
	rcode = next->write(next, packet_ctx, buffer, size);
	if ((size_t) rcode == size) return rcode;

	/*
	 *	The next bio returned an error.  Anything other than WOULD BLOCK is fatal.  We can read from
	 *	the memory buffer until it's empty, but we can no longer write to the memory buffer.
	 */
	if ((rcode < 0) && (rcode != fr_bio_error(IO_WOULD_BLOCK))) {
		bio->read = fr_bio_mem_read_eof;
		bio->write = fr_bio_null_write;
		return rcode;
	}

	/*
	 *	We were flushing the BIO, return however much data we managed to write.
	 *
	 *	Note that flushes should never block.
	 */
	if (!buffer) {
		fr_assert(rcode != fr_bio_error(IO_WOULD_BLOCK));
		return rcode;
	}

	/*
	 *	Tell previous BIOs in the chain that they are blocked.
	 */
	error = fr_bio_write_blocked(bio);
	if (error < 0) return error;

	fr_assert(error != 0); /* what to do? */

	/*
	 *	We had WOULD BLOCK, or wrote partial bytes.  Save the data to the memory buffer, and ensure
	 *	that future writes are ordered.  i.e. they write to the memory buffer before writing to the
	 *	next bio.
	 */
	bio->write = fr_bio_mem_write_buffer;

	/*
	 *	Clamp the write to however much data is available in the buffer.
	 */
	leftover = size - rcode;
	room = fr_bio_buf_write_room(&my->write_buffer);

	/*
	 *	If we have "used == 0" above, then we must also have "room > 0".
	 */
	fr_assert(room > 0);

	if (room < leftover) leftover = room;

	/*
	 *	Since we've clamped the write, this call can never fail.
	 */
	(void) fr_bio_buf_write(&my->write_buffer, ((uint8_t const *) buffer) + rcode, leftover);

	/*
	 *	Some of the data base been written to the next bio, and some to our cache.  The caller has to
	 *	ensure that the first subsequent write will send over the rest of the data.
	 *
	 *	However, we tell the caller that we wrote the entire packet.  Because we are now responsible
	 *	for writing the remaining bytes.
	 */
	return size;
}

/** Flush the memory buffer.
 *
 */
static ssize_t fr_bio_mem_write_flush(fr_bio_mem_t *my, size_t size)
{
	int rcode;
	size_t used;
	fr_bio_t *next;

	/*
	 *	Nothing to flush, don't do any writes.
	 *
	 *	Instead, set the write function to write next, where data will be sent directly to the next
	 *	bio, and will bypass the write buffer.
	 */
	used = fr_bio_buf_used(&my->write_buffer);
	if (!used) {
		my->bio.write = fr_bio_mem_write_next;
		return 0;
	}

	next = fr_bio_next(&my->bio);
	fr_assert(next != NULL);

	/*
	 *	Clamp the amount of data written.  If the caller wants to write everything, it should
	 *	pass SIZE_MAX.
	 */
	if (used < size) used = size;

	/*
	 *	Flush the buffer to the next bio in line.  That function will write as much data as possible,
	 *	but may return a partial write.
	 */
	rcode = next->write(next, NULL, my->write_buffer.write, used);

	/*
	 *	We didn't write anything, the bio is blocked.
	 */
	if ((rcode == 0) || (rcode == fr_bio_error(IO_WOULD_BLOCK))) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	All other errors are fatal.  We can read from the memory buffer until it's empty, but we can
	 *	no longer write to the memory buffer.
	 */
	if (rcode < 0) return rcode;

	/*
	 *	Tell the buffer that we've read a certain amount of data from it.
	 */
	(void) fr_bio_buf_read(&my->write_buffer, NULL, (size_t) rcode);

	/*
	 *	We haven't emptied the buffer, any further IO is blocked.
	 */
	if ((size_t) rcode < used) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	We've flushed all of the buffer.  Revert back to "pass through" writing.
	 */
	fr_assert(fr_bio_buf_used(&my->write_buffer) == 0);
	my->bio.write = fr_bio_mem_write_next;
	return rcode;
}

/** Write to the memory buffer.
 *
 *  The special buffer pointer of NULL means flush().  On flush, we call next->read(), and if that succeeds,
 *  go back to "pass through" mode for the buffers.
 */
static ssize_t fr_bio_mem_write_buffer(fr_bio_t *bio, UNUSED void *packet_ctx, void const *buffer, size_t size)
{
	size_t room;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	/*
	 *	Flush the output buffer.
	 */
	if (unlikely(!buffer)) return fr_bio_mem_write_flush(my, size);

	/*
	 *	Clamp the write to however much data is available in the buffer.
	 */
	room = fr_bio_buf_write_room(&my->write_buffer);

	/*
	 *	The buffer is full, we can't write anything.
	 */
	if (!room) return fr_bio_error(IO_WOULD_BLOCK);

	/*
	 *	If we're asked to write more bytes than are available in the buffer, then tell the caller that
	 *	writes are now blocked, and we can't write any more data.
	 *
	 *	Return an WOULD_BLOCK error instead of breaking our promise by writing part of the data,
	 *	instead of accepting a full application write.
	 */
	if (room < size) {
		int rcode;

		rcode = fr_bio_write_blocked(bio);
		if (rcode < 0) return rcode;

		return fr_bio_error(IO_WOULD_BLOCK);
	}

	/*
	 *	As we have clamped the write, we know that this call must succeed.
	 */
	(void) fr_bio_buf_write(&my->write_buffer, buffer, size);

	/*
	 *	If we've filled the buffer, tell the caller that writes are now blocked, and we can't write
	 *	any more data.  However, we still return the amount of data we wrote.
	 */
	if (room == size) {
		int rcode;

		rcode = fr_bio_write_blocked(bio);
		if (rcode < 0) return rcode;
	}

	return size;
}

/** Peek at the data in the read buffer
 *
 *  Peeking at the data allows us to avoid many memory copies.
 */
uint8_t const *fr_bio_mem_read_peek(fr_bio_t *bio, size_t *size)
{
	size_t used;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	used = fr_bio_buf_used(&my->read_buffer);

	if (!used) return NULL;

	*size = used;
	return my->read_buffer.read;
}

/** Discard data from the read buffer.
 *
 *  Discarding allows the caller to silently omit packets, so that
 *  they are not passed up to previous bios.
 */
void fr_bio_mem_read_discard(fr_bio_t *bio, size_t size)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	(void) fr_bio_buf_read(&my->read_buffer, NULL, size);
}

/** Verify that a packet is OK.
 *
 *  @todo - have this as a parameter to the read routines, so that they only return complete packets?
 *
 *  @param	bio	the #fr_bio_mem_t
 *  @param	packet_ctx the packet ctx
 *  @param[out]	size	how big the verified packet is
 *  @return
 *	- <0 for FR_BIO_VERIFY_ERROR_CLOSE, the caller should close the bio.
 *	- 0 for "we have a partial packet", the size to read is in *size
 *	- 1 for "we have at least one good packet", the size of it is in *size
 */
static int fr_bio_mem_call_verify(fr_bio_t *bio, void *packet_ctx, size_t *size)
{
	uint8_t *packet, *end;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	packet = my->read_buffer.read;
	end = my->read_buffer.write;

	while (packet < end) {
		size_t want;
#ifndef NDEBUG
		size_t used;

		used = end - packet;
#endif

		want = end - packet;

		switch (my->verify((fr_bio_t *) my, my->verify_ctx, packet_ctx, packet, &want)) {
			/*
			 *	The data in the buffer is exactly a packet.  Return that.
			 *
			 *	@todo - if there are multiple packets, return the total size of packets?
			 */
		case FR_BIO_VERIFY_OK:
			fr_assert(want <= used);
			*size = want;
			return 1;

			/*
			 *	The packet needs more data.  Return how much data we need for one packet.
			 */
		case FR_BIO_VERIFY_WANT_MORE:
			fr_assert(want > used);
			*size = want;
			return 0;

		case FR_BIO_VERIFY_DISCARD:
			/*
			 *	We don't call fr_bio_buf_read(), because that will move the memory around, and
			 *	we want to avoid that if at all possible.
			 */
			fr_assert(want <= used);
			fr_assert(packet == my->read_buffer.read);
			my->read_buffer.read += want;
			continue;

			/*
			 *	Some kind of fatal validation error.
			 */
		case FR_BIO_VERIFY_ERROR_CLOSE:
			break;
		}
	}

	return -1;
}

/*
 *	The application can read from the BIO until EOF, but cannot write to it.
 */
static void fr_bio_mem_shutdown(fr_bio_t *bio)
{
	bio->read = fr_bio_mem_read_eof;
	bio->write = fr_bio_null_write;
}

/** Allocate a memory buffer bio for either reading or writing.
 */
static bool fr_bio_mem_buf_alloc(fr_bio_mem_t *my, fr_bio_buf_t *buf, size_t size)
{
	if (size < 1024) size = 1024;
	if (size > (1 << 20)) size = 1 << 20;

	if (fr_bio_buf_alloc(my, buf, size) < 0) {
		talloc_free(my);
		return false;
	}

	return true;
}

/** Allocate a memory buffer bio
 *
 *  The "read buffer" will cache reads from the next bio in the chain.  If the next bio returns more data than
 *  the caller asked for, the extra data is cached in the read buffer.
 *
 *  The "write buffer" will buffer writes to the next bio in the chain.  If the caller writes more data than
 *  the next bio can process, the extra data is cached in the write buffer.
 *
 *  When the bio is closed (or freed) any pending data in the buffers is lost.  The same happens if the next
 *  bio returns a fatal error.
 *
 *  At some point during a read, the next bio may return EOF.  When that happens, the caller should not rely
 *  on the next FD being readable or writable.  Instead, it should keep reading from the memory bio until it
 *  returns EOF.  See fr_bio_fd_eof() for details.
 *
 *  @param ctx		the talloc ctx
 *  @param read_size	size of the read buffer.  Must be 1024..1^20
 *  @param write_size	size of the write buffer.  Can be zero. If non-zero, must be 1024..1^20
 *  @param next		the next bio which will perform the underlying reads and writes.
 *	- NULL on error, memory allocation failed
 *	- !NULL the bio
 */
fr_bio_t *fr_bio_mem_alloc(TALLOC_CTX *ctx, size_t read_size, size_t write_size, fr_bio_t *next)
{
	fr_bio_mem_t *my;

	/*
	 *	The caller has to state that the API is caching data both ways.
	 */
	if (!read_size) {
		fr_strerror_const("Read size must be non-zero");
		return NULL;
	}

	my = talloc_zero(ctx, fr_bio_mem_t);
	if (!my) return NULL;

	if (!fr_bio_mem_buf_alloc(my, &my->read_buffer, read_size)) {
	oom:
		fr_strerror_const("Out of memory");
		return NULL;
	}
	my->bio.read = fr_bio_mem_read;

	if (write_size) {
		if (!fr_bio_mem_buf_alloc(my, &my->write_buffer, write_size)) goto oom;

		my->bio.write = fr_bio_mem_write_next;
	} else {
		my->bio.write = fr_bio_next_write;
	}
	my->priv_cb.eof = fr_bio_mem_eof;
	my->priv_cb.write_resume = fr_bio_mem_write_resume;
	my->priv_cb.shutdown = fr_bio_mem_shutdown;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor);
	return (fr_bio_t *) my;
}


/** Allocate a memory buffer which sources data from the callers application into the bio system.
 *
 *  The caller writes data to the buffer, but never reads from it.  This bio will call the "next" bio to sink
 *  the data.
 */
fr_bio_t *fr_bio_mem_source_alloc(TALLOC_CTX *ctx, size_t write_size, fr_bio_t *next)
{
	fr_bio_mem_t *my;

	/*
	 *	The caller has to state that the API is caching data.
	 */
	if (!write_size) return NULL;

	my = talloc_zero(ctx, fr_bio_mem_t);
	if (!my) return NULL;

	if (!fr_bio_mem_buf_alloc(my, &my->write_buffer, write_size)) {
		talloc_free(my);
		return NULL;
	}

	my->bio.read = fr_bio_null_read; /* reading FROM this bio is not possible */
	my->bio.write = fr_bio_mem_write_next;

	/*
	 *	@todo - have write pause / write resume callbacks?
	 */
	my->priv_cb.shutdown = fr_bio_mem_shutdown;

	fr_bio_chain(&my->bio, next);

	talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor);
	return (fr_bio_t *) my;
}

/** Read from a buffer which a previous bio has filled.
 *
 *  This function is called by the application which wants to read from a sink.
 */
static ssize_t fr_bio_mem_read_buffer(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	return fr_bio_buf_read(&my->read_buffer, buffer, size);
}

/** Write to the read buffer.
 *
 *  This function is called by an upstream function which writes into our local buffer.
 */
static ssize_t fr_bio_mem_write_read_buffer(fr_bio_t *bio, UNUSED void *packet_ctx, void const *buffer, size_t size)
{
	size_t room;
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	/*
	 *	Clamp the write to however much data is available in the buffer.
	 */
	room = fr_bio_buf_write_room(&my->read_buffer);

	/*
	 *	The buffer is full.  We're now blocked.
	 */
	if (!room) return fr_bio_error(IO_WOULD_BLOCK);

	if (room < size) size = room;

	/*
	 *	As we have clamped the write, we know that this call must succeed.
	 */
	return fr_bio_buf_write(&my->read_buffer, buffer, size);
}

/** Allocate a memory buffer which sinks data from a bio system into the callers application.
 *
 *  The caller reads data from this bio, but never writes to it.  Upstream BIOs will source the data.
 */
fr_bio_t *fr_bio_mem_sink_alloc(TALLOC_CTX *ctx, size_t read_size)
{
	fr_bio_mem_t *my;

	/*
	 *	The caller has to state that the API is caching data.
	 */
	if (!read_size) return NULL;

	my = talloc_zero(ctx, fr_bio_mem_t);
	if (!my) return NULL;

	if (!fr_bio_mem_buf_alloc(my, &my->read_buffer, read_size)) {
		talloc_free(my);
		return NULL;
	}

	my->bio.read = fr_bio_mem_read_buffer;
	my->bio.write = fr_bio_mem_write_read_buffer; /* the upstream will write to our read buffer */

	talloc_set_destructor((fr_bio_t *) my, fr_bio_destructor);
	return (fr_bio_t *) my;
}

/** Set the verification function for memory bios.
 *
 *  It is possible to add a verification function.  It is not currently possible to remove one.
 *
 *  @param bio		the binary IO handler
 *  @param verify	the verification function
 *  @param datagram	whether or not this bio is a datagram one.
 *  @return
 *	- <0 on error
 *	- 0 on success
 */
int fr_bio_mem_set_verify(fr_bio_t *bio, fr_bio_verify_t verify, void *verify_ctx, bool datagram)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	if (my->bio.read != fr_bio_mem_read) {
		fr_strerror_const("Cannot add verify to a memory sink bio");
		return fr_bio_error(GENERIC);
	}

	my->verify = verify;
	my->verify_ctx = verify_ctx;

	/*
	 *	If we are writing datagrams, then we cannot buffer individual datagrams.  We must write
	 *	either all of the datagram out, or none of it.
	 */
	if (datagram) {
		my->bio.read = fr_bio_mem_read_verify_datagram;
		my->bio.write = fr_bio_next_write;

		/*
		 *	Might as well free the memory for the write buffer.  It won't be used.
		 */
		if (my->write_buffer.start) {
			talloc_free(my->write_buffer.start);
			my->write_buffer = (fr_bio_buf_t) {};
		}
	} else {
		my->bio.read = fr_bio_mem_read_verify;
		/* don't touch the write function or the write buffer. */
	}

	return 0;
}

/*
 *	There's no fr_bio_mem_write_blocked()
 */

/** See if we can resume writes to the memory bio.
 *
 *  Note that there is no equivalent fr_bio_mem_write_blocked(), as that function wouldn't do anything.
 *  Perhaps it could swap the write function to fr_bio_mem_write_buffer(), but the fr_bio_mem_write_next()
 *  function should automatically do that when the write to the next bio only writes part of the data,
 *  or if it returns fr_bio_error(IO_WOULD_BLOCK)
 */
int fr_bio_mem_write_resume(fr_bio_t *bio)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);
	ssize_t rcode;

	if (bio->write != fr_bio_mem_write_buffer) return 1;

	/*
	 *	Flush the buffer, and then reset the write routine if we were successful.
	 */
	rcode = fr_bio_mem_write_flush(my, SIZE_MAX);
	if (rcode <= 0) return rcode;

	if (fr_bio_buf_used(&my->write_buffer) > 0) return 0;

	if (!my->cb.write_resume) return 1;

	return my->cb.write_resume(bio);
}

/** Pause writes.
 *
 *  Calls to fr_bio_write() will write to the memory buffer, and not
 *  to the next bio.  You MUST call fr_bio_mem_write_resume() after
 *  this to flush any data.
 */
int fr_bio_mem_write_pause(fr_bio_t *bio)
{
	fr_bio_mem_t *my = talloc_get_type_abort(bio, fr_bio_mem_t);

	if (my->bio.write == fr_bio_mem_write_buffer) return 0;

	if (my->bio.write != fr_bio_mem_write_buffer) return -1;

	my->bio.write = fr_bio_mem_write_buffer;

	return 0;
}
