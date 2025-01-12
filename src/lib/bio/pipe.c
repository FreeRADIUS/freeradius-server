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
#include <freeradius-devel/bio/mem.h>

#include <freeradius-devel/bio/pipe.h>

#include <pthread.h>

/** The pipe bio
 *
 */
typedef struct {
	FR_BIO_COMMON;

	fr_bio_t	*next;

	bool		eof;		//!< are we at EOF?

	fr_bio_pipe_cb_funcs_t signal; //!< inform us that the pipe is readable

	pthread_mutex_t mutex;
} fr_bio_pipe_t;


static int fr_bio_pipe_destructor(fr_bio_pipe_t *my)
{
	pthread_mutex_destroy(&my->mutex);

	return 0;
}

/** Read from the pipe.
 *
 *  Once EOF is set, any pending data is read, and then EOF is returned.
 */
static ssize_t fr_bio_pipe_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);

	fr_assert(my->next != NULL);

	pthread_mutex_lock(&my->mutex);
	rcode = my->next->read(my->next, packet_ctx, buffer, size);
	if ((rcode == 0) && my->eof) {
		pthread_mutex_unlock(&my->mutex);

		/*
		 *	Don't call our EOF function.  But do tell the other BIOs that we're at EOF.
		 */
		my->priv_cb.eof = NULL;
		fr_bio_eof(bio);
		return 0;

	} else if (rcode > 0) {
		/*
		 *	There is room to write more data.
		 *
		 *	@todo - only signal when we transition from BLOCKED to unblocked.
		 */
		my->signal.writeable(&my->bio);
	}
	pthread_mutex_unlock(&my->mutex);

	return rcode;
}


/** Write to the pipe.
 *
 *  Once EOF is set, no further writes are possible.
 */
static ssize_t fr_bio_pipe_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	fr_assert(my->next != NULL);

	pthread_mutex_lock(&my->mutex);
	if (!my->eof) {
		rcode = my->next->write(my->next, packet_ctx, buffer, size);

		/*
		 *	There is more data to read.
		 *
		 *	@todo - only signal when we transition from no data to data.
		 */
		if (rcode > 0) {
			my->signal.readable(&my->bio);
		}

	} else {
		rcode = 0;
	}
	pthread_mutex_unlock(&my->mutex);

	return rcode;
}

/** Shutdown callback.
 *
 */
static void fr_bio_pipe_shutdown(fr_bio_t *bio)
{
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	fr_assert(my->next != NULL);

	pthread_mutex_lock(&my->mutex);
	fr_bio_shutdown(my->next);
	pthread_mutex_unlock(&my->mutex);
}

/** Set EOF.
 *
 *  Either side can set EOF, in which case pending reads are still processed.  Writes return EOF immediately.
 *  Readers return pending data, and then EOF.
 */
static int fr_bio_pipe_eof(fr_bio_t *bio)
{
	fr_bio_pipe_t *my = talloc_get_type_abort(bio, fr_bio_pipe_t);	

	pthread_mutex_lock(&my->mutex);
	my->eof = true;
	pthread_mutex_unlock(&my->mutex);

	/*
	 *	We don't know if the other end is at EOF, we have to do a read.  So we tell fr_bio_eof() to
	 *	stop processing.
	 */
	return 0;
}

/** Allocate a thread-safe pipe which can be used for both reads and writes.
 *
 *  Due to talloc issues with multiple threads, if the caller wants a bi-directional pipe, this function will
 *  need to be called twice.  That way a free in each context won't result in a race condition on two mutex
 *  locks.
 *
 *  For now, iqt's too difficult to emulate the pipe[2] behavior, where two identical "connected" things are
 *  returned, and either can be used for reading or for writing.
 *
 *  i.e. a pipe is really a mutex-protected memory buffer.  One side should call write (and never read).  The
 *  other side should call read (and never write).
 *
 *  The pipe should be freed only after both ends have set EOF.
 */
fr_bio_t *fr_bio_pipe_alloc(TALLOC_CTX *ctx, fr_bio_pipe_cb_funcs_t *cb, size_t buffer_size)
{
	fr_bio_pipe_t *my;

	if (!cb->readable || !cb->writeable) return NULL;

	if (buffer_size < 1024)		buffer_size = 1024;
	if (buffer_size > (1 << 20))	buffer_size = (1 << 20);

	my = talloc_zero(ctx, fr_bio_pipe_t);
	if (!my) return NULL;

	my->next = fr_bio_mem_sink_alloc(my, buffer_size);
	if (!my->next) {
		talloc_free(my);
		return NULL;
	}

	my->signal = *cb;

	pthread_mutex_init(&my->mutex, NULL);

	my->bio.read = fr_bio_pipe_read;
	my->bio.write = fr_bio_pipe_write;
	my->cb.shutdown = fr_bio_pipe_shutdown;
	my->priv_cb.eof = fr_bio_pipe_eof;

	talloc_set_destructor(my, fr_bio_pipe_destructor);
	return (fr_bio_t *) my;
}
