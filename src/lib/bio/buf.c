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
 * @file lib/bio/buf.c
 * @brief BIO abstractions for file descriptors
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/bio/buf.h>

size_t fr_bio_buf_make_room(fr_bio_buf_t *bio_buf)
{
	size_t used;

	if (bio_buf->read == bio_buf->start) return fr_bio_buf_write_room(bio_buf);

	used = bio_buf->write - bio_buf->read;
	if (!used) return fr_bio_buf_write_room(bio_buf);

	memmove(bio_buf->start, bio_buf->read, used);

	bio_buf->read = bio_buf->start;
	bio_buf->write = bio_buf->read + used;

	return fr_bio_buf_write_room(bio_buf);
}

size_t fr_bio_buf_read(fr_bio_buf_t *bio_buf, void *buffer, size_t size)
{
	size_t used;

	fr_bio_buf_verify(bio_buf);

	used = bio_buf->write - bio_buf->read;
	if (!used || !size) return 0;

	/*
	 *	Clamp the data to read at how much data is in the buffer.
	 */
	if (size > used) size = used;

	if (buffer) memcpy(buffer, bio_buf->read, size);

	bio_buf->read += size;
	if (bio_buf->read == bio_buf->write) {
		fr_bio_buf_reset(bio_buf);

	} else if ((bio_buf->end - bio_buf->read) < (bio_buf->read - bio_buf->start)) {
		/*
		 *	The "read" pointer is closer to the end of the
		 *	buffer than to the start.  Shift the data
		 *	around to give more room for reading.
		 *
		 *	@todo - change the check instead to "(end - write) < min_room"
		 *
		 *	@todo - what about pending packets which point to the buffer?
		 */
		fr_bio_buf_make_room(bio_buf);
	}

	return size;
}

ssize_t	fr_bio_buf_write(fr_bio_buf_t *bio_buf, const void *buffer, size_t size)
{
	size_t room;

	fr_bio_buf_verify(bio_buf);

	room = fr_bio_buf_write_room(bio_buf);

	if (room < size) {
		return -room;	/* how much more room we would need */
	}

	/*
	 *	The data might already be in the buffer, in which case we can skip the memcpy().
	 *
	 *	But the data MUST be at the current "write" position.  i.e. we can't have overlapping /
	 *	conflicting writes.
	 *
	 *	@todo - if it's after the current write position, maybe still allow it?  That's so
	 *	fr_bio_mem_write() and friends can write partial packets into the buffer.  Maybe add a
	 *	fr_bio_buf_write_partial() API, which takes (packet, already_written, size), and then does the
	 *	right thing.  If the packet is not within the buffer, then it devolves to fr_bio_buf_write(),
	 *	otherwise it moves the write ptr in the buffer to after the packet.
	 */
	if (buffer != bio_buf->write) {
		fr_assert(!fr_bio_buf_contains(bio_buf, buffer));
		memcpy(bio_buf->write, buffer, size);
	}
	bio_buf->write += size;

	return size;
}

int fr_bio_buf_alloc(TALLOC_CTX *ctx, fr_bio_buf_t *bio_buf, size_t size)
{
	void *ptr;

	ptr = talloc_array(ctx, uint8_t, size);
	if (!ptr) return -1;

	if (bio_buf->start) talloc_free(bio_buf->start);

	fr_bio_buf_init(bio_buf, ptr, size);

	return 0;
}
