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
 * @file lib/bio/pipe.c
 * @brief BIO abstractions for in-memory pipes
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/bio/buf.h>

#include <freeradius-devel/bio/pipe.h>

#include <pthread.h>

/** The pipe bio
 *
 */
typedef struct {
	FR_BIO_COMMON;

	fr_bio_buf_t	buf;		//!< for reading and writing

	bool		eof;		//!< are we at EOF?

	pthread_mutex_t mutex;
} fr_bio_pipe_t;


static int fr_bio_pipe_destructor(fr_bio_pipe_t *my)
{
	FR_BIO_DESTRUCTOR_COMMON;

	pthread_mutex_destroy(&my->mutex);

	return 0;
}

/** Read from the pipe.
 *
 *  Once EOF is set, any pending data is read, and then EOF is returned.
 */
static ssize_t fr_bio_pipe_read(fr_bio_t *bio, UNUSED void *packet_ctx, void *buffer, size_t size)
{
	bool eof = false;
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);

	pthread_mutex_lock(&my->mutex);
	size = fr_bio_buf_read(&my->buf, buffer, size);

	if (my->eof && (fr_bio_buf_used(&my->buf) == 0)) {
		eof = true;
		my->bio.read = fr_bio_null_read;
	}
	pthread_mutex_unlock(&my->mutex);

	if (size > 0) {
		if (eof) {
			my->cb.eof(&my->bio);
			my->cb.eof = NULL;

		} else {
			(void) my->cb.write_resume(&my->bio);
		}

	} else {
		(void) my->cb.read_blocked(&my->bio);
	}

	return size;
}


/** Write to the pipe.
 *
 *  Once EOF is set, no further writes are possible.
 */
static ssize_t fr_bio_pipe_write(fr_bio_t *bio, UNUSED void *packet_ctx, void const *buffer, size_t size)
{
	size_t room;
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	pthread_mutex_lock(&my->mutex);
	room = fr_bio_buf_write_room(&my->buf);
	if (room > 0) {
		if (room < size) size = room;
		(void) fr_bio_buf_write(&my->buf, buffer, size); /* always succeeds */
	} else {
		size = 0;
	}
	pthread_mutex_unlock(&my->mutex);

	if (size > 0) {
		(void) my->cb.read_resume(&my->bio);
	} else {
		(void) my->cb.write_blocked(&my->bio);
	}

	return size;
}

/** Shutdown callback.
 *
 */
static int fr_bio_pipe_shutdown(fr_bio_t *bio)
{
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	pthread_mutex_lock(&my->mutex);
	my->bio.read = fr_bio_fail_read;
	my->bio.write = fr_bio_fail_write;
	pthread_mutex_unlock(&my->mutex);

	return 0;
}

/** Set EOF.
 *
 *  Either side can set EOF, in which case pending reads are still processed.  Writes return EOF immediately.
 *  Readers return pending data, and then EOF.
 */
static int fr_bio_pipe_eof(fr_bio_t *bio)
{
	int rcode;
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	/*
	 *	@todo - fr_bio_eof() sets our read to NULL read before this callback is run.  That has to be
	 *	addressed.
	 */
	pthread_mutex_lock(&my->mutex);
	my->eof = true;	
	my->bio.write = fr_bio_null_write;
	if (fr_bio_buf_used(&my->buf) == 0) {
		my->bio.read = fr_bio_null_read;
		rcode = 0;
	} else {
		rcode = -1;	/* can't close this BIO yet */
	}
	pthread_mutex_unlock(&my->mutex);

	return rcode;
}

/** Allocate a thread-safe pipe which can be used for both reads and writes.
 *
 *  Due to talloc issues with multiple threads, if the caller wants a bi-directional pipe, this function will
 *  need to be called twice.  That way a free in each context won't result in a race condition on two mutex
 *  locks.
 *
 *  For now, it's too difficult to emulate the pipe[2] behavior, where two identical "connected" things are
 *  returned, and either can be used for reading or for writing.
 *
 *  i.e. a pipe is really a mutex-protected memory buffer.  One side should call write (and never read).  The
 *  other side should call read (and never write).
 *
 *  The pipe should be freed only after both ends have set EOF.
 */
fr_bio_t *fr_bio_pipe_alloc(TALLOC_CTX *ctx, fr_bio_cb_funcs_t *cb, size_t buffer_size)
{
	fr_bio_pipe_t	*my;
	uint8_t		*buffer;

	if (!cb->read_resume  || !cb->write_resume) return NULL;
	if (!cb->read_blocked || !cb->write_blocked) return NULL;
	if (!cb->eof) return NULL;

	if (buffer_size < 1024)		buffer_size = 1024;
	if (buffer_size > (1 << 20))	buffer_size = (1 << 20);

	my = talloc_zero(ctx, fr_bio_pipe_t);
	if (!my) return NULL;

	buffer = talloc_array(my, uint8_t, buffer_size);
	if (!buffer) {
		talloc_free(my);
		return NULL;
	}

	my->cb = *cb;

	fr_bio_buf_init(&my->buf, buffer, buffer_size);

	pthread_mutex_init(&my->mutex, NULL);

	my->bio.read = fr_bio_pipe_read;
	my->bio.write = fr_bio_pipe_write;
	my->cb.shutdown = fr_bio_pipe_shutdown;
	my->priv_cb.eof = fr_bio_pipe_eof;

	talloc_set_destructor(my, fr_bio_pipe_destructor);
	return (fr_bio_t *) my;
}
