#pragma once
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
 * @file lib/bio/buf.h
 * @brief Binary IO abstractions for buffers
 *
 *  The #fr_bio_buf_t allows readers and writers to use a shared buffer, without overflow.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_buf_h, "$Id$")

typedef struct {
	uint8_t		*start;		//!< start of the buffer
	uint8_t		*end;		//!< end of the buffer

	uint8_t		*read;		//!< where in the buffer reads are taken from
	uint8_t		*write;		//!< where in the buffer writes are sent to
} fr_bio_buf_t;

static inline void fr_bio_buf_init(fr_bio_buf_t *bio_buf, uint8_t *buffer, size_t size)
{
	bio_buf->start = bio_buf->read = bio_buf->write = buffer;
	bio_buf->end = buffer + size;
}

size_t		fr_bio_buf_make_room(fr_bio_buf_t *bio_buf);

size_t		fr_bio_buf_read(fr_bio_buf_t *bio_buf, void *buffer, size_t size) CC_HINT(nonnull(1));
ssize_t		fr_bio_buf_write(fr_bio_buf_t *bio_buf, const void *buffer, size_t size) CC_HINT(nonnull);


#ifndef NDEBUG
static inline void CC_HINT(nonnull) fr_bio_buf_verify(fr_bio_buf_t const *bio_buf)
{
	fr_assert(bio_buf->start != NULL);
	fr_assert(bio_buf->start <= bio_buf->read);
	fr_assert(bio_buf->read <= bio_buf->write);
	fr_assert(bio_buf->write <= bio_buf->end);
}
#else
#define fr_bio_buf_verify(_x)
#endif

static inline void CC_HINT(nonnull) fr_bio_buf_reset(fr_bio_buf_t *bio_buf)
{
	fr_bio_buf_verify(bio_buf);

	bio_buf->read = bio_buf->write = bio_buf->start;
}

static inline bool CC_HINT(nonnull) fr_bio_buf_initialized(fr_bio_buf_t const *bio_buf)
{
	return (bio_buf->start != NULL);
}

static inline size_t CC_HINT(nonnull) fr_bio_buf_used(fr_bio_buf_t const *bio_buf)
{
	if (!fr_bio_buf_initialized(bio_buf)) return 0;

	fr_bio_buf_verify(bio_buf);

	return (bio_buf->write - bio_buf->read);
}

static inline size_t CC_HINT(nonnull) fr_bio_buf_write_room(fr_bio_buf_t const *bio_buf)
{
	fr_bio_buf_verify(bio_buf);

	return bio_buf->end - bio_buf->write;
}

static inline uint8_t *CC_HINT(nonnull) fr_bio_buf_write_reserve(fr_bio_buf_t *bio_buf, size_t size)
{
	fr_bio_buf_verify(bio_buf);

	if (fr_bio_buf_write_room(bio_buf) < size) return NULL;

	return bio_buf->write;
}

static inline int CC_HINT(nonnull) fr_bio_buf_write_alloc(fr_bio_buf_t *bio_buf, size_t size)
{
	fr_bio_buf_verify(bio_buf);

	if (fr_bio_buf_write_room(bio_buf) < size) return -1;

	bio_buf->write += size;

	fr_bio_buf_verify(bio_buf);

	return 0;
}

static inline void CC_HINT(nonnull) fr_bio_buf_write_undo(fr_bio_buf_t *bio_buf, size_t size)
{
	fr_bio_buf_verify(bio_buf);

	fr_assert(bio_buf->read + size <= bio_buf->write);

	bio_buf->write -= size;
	fr_bio_buf_verify(bio_buf);

	if (bio_buf->read == bio_buf->write) {
		fr_bio_buf_reset(bio_buf);
	}
}

static inline bool fr_bio_buf_contains(fr_bio_buf_t *bio_buf, void const *buffer)
{
	return ((uint8_t const *) buffer >= bio_buf->start) && ((uint8_t const *) buffer <= bio_buf->end);
}

#if 0
static inline void CC_HINT(nonnull) fr_bio_buf_write_update(fr_bio_buf_t *bio_buf, void const *buffer, size_t size, size_t written)
{
	if (!fr_bio_buf_initialized(bio_buf)) return;

	fr_bio_buf_verify(bio_buf);

	if (bio_buf->read == buffer) {
		fr_assert(fr_bio_buf_used(bio_buf) >= size);

		(void) fr_bio_buf_read(bio_buf, NULL, written);
	} else {
		/*
		 *	If we're not writing from the start of write_buffer, then the data to
		 *	be written CANNOT appear anywhere in the buffer.
		 */
		fr_assert(!fr_bio_buf_contains(bio_buf, buffer));
	}
}
#endif

static inline size_t CC_HINT(nonnull) fr_bio_buf_size(fr_bio_buf_t const *bio_buf)
{
	fr_bio_buf_verify(bio_buf);

	return (bio_buf->end - bio_buf->start);
}

int	fr_bio_buf_alloc(TALLOC_CTX *ctx, fr_bio_buf_t *bio_buf, size_t size) CC_HINT(nonnull);
