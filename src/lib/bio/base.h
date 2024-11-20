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
 * @file lib/bio/base.h
 * @brief Binary IO abstractions.
 *
 *  Create abstract binary input / output buffers.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_base_h, "$Id$")

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/dlist.h>

#ifdef NDEBUG
#define XDEBUG(_x)
#else
#define XDEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#endif

#ifdef _CONST
#  error _CONST can only be defined in the local header
#endif
#ifndef _BIO_PRIVATE
#  define _CONST const
#else
#  define _CONST
#endif

typedef enum {
	FR_BIO_ERROR_NONE = 0,
	FR_BIO_ERROR_IO_WOULD_BLOCK,     		//!< IO would block

	FR_BIO_ERROR_IO,				//!< IO error - check errno
	FR_BIO_ERROR_GENERIC,				//!< generic "failed" error - check fr_strerror()
	FR_BIO_ERROR_OOM,				//!< out of memory
	FR_BIO_ERROR_VERIFY,				//!< some packet verification error
	FR_BIO_ERROR_BUFFER_FULL,      			//!< the buffer is full
	FR_BIO_ERROR_BUFFER_TOO_SMALL,			//!< the output buffer is too small for the data
} fr_bio_error_type_t;

typedef struct fr_bio_s fr_bio_t;

/**  Do a raw read from a socket, or other data source
 *
 *  These functions should be careful about packet_ctx.  This handling depends on a number of factors.  Note
 *  that the packet_ctx may be NULL!
 *
 *  Stream sockets will generally ignore packet_ctx.
 *
 *  Datagram sockets generally write src/dst IP/port to the packet context.  This same packet_ctx is then
 *  passed to bio->write(), which can use it to send the data to the correct destination.
 *
 *  @param bio		the binary IO handler
 *  @param packet_ctx	where the function can store per-packet information, such as src/dst IP/port for datagram sockets
 *  @param buffer	where the function should store data it reads
 *  @param size		the maximum amount of data to read.
 *  @return
 *	- <0 for error
 *	- 0 for "no data available".  Note that this does NOT mean EOF!  It could mean "we do not have a full packet"
 *	- >0 for amount of data which was read.
 */
typedef ssize_t	(*fr_bio_read_t)(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size);
typedef ssize_t	(*fr_bio_write_t)(fr_bio_t *bio, void *packet_ctx, const void *buffer, size_t size);

typedef int (*fr_bio_io_t)(fr_bio_t *bio); /* read / write blocked callbacks */

typedef void (*fr_bio_callback_t)(fr_bio_t *bio); /* connected / shutdown callbacks */

typedef struct {
	fr_bio_callback_t	connected;		//!< called when the BIO is ready to be used
	fr_bio_callback_t	shutdown;		//!< called when the BIO is being shut down
	fr_bio_callback_t	eof;			//!< called when the BIO is at EOF
	fr_bio_callback_t	failed;			//!< called when the BIO fails

	fr_bio_io_t		read_blocked;
	fr_bio_io_t		write_blocked;		//!< returns 0 for "couldn't block", 1 for "did block".

	fr_bio_io_t		read_resume;		//!< "unblocked" is too similar to "blocked"
	fr_bio_io_t		write_resume;
} fr_bio_cb_funcs_t;

/** Accept a new connection on a bio
 *
 *  @param bio		the binary IO handler
 *  @param ctx		the talloc ctx for the new bio.
 *  @param[out] accepted the accepted bio
 *  @return
 *	- <0 on error
 *	- 0 for "we did nothing, and there is no new bio available"
 *	- 1 for "the accepted bio is available"
 */
typedef int (*fr_bio_accept_t)(fr_bio_t *bio, TALLOC_CTX *ctx, fr_bio_t **accepted);

struct fr_bio_s {
	void			*uctx;			//!< user ctx, caller can manually set it.

	fr_bio_read_t	_CONST	read;			//!< read from the underlying bio
	fr_bio_write_t	_CONST	write;			//!< write to the underlying bio

	fr_dlist_t	_CONST entry;			//!< in the linked list of multiple bios
};

static inline CC_HINT(nonnull) fr_bio_t *fr_bio_prev(fr_bio_t *bio)
{
	fr_dlist_t *prev = bio->entry.prev;

	if (!prev) return NULL;

	return fr_dlist_entry_to_item(offsetof(fr_bio_t, entry), prev);
}

static inline CC_HINT(nonnull) fr_bio_t *fr_bio_next(fr_bio_t *bio)
{
	fr_dlist_t *next = bio->entry.next;

	if (!next) return NULL;

	return fr_dlist_entry_to_item(offsetof(fr_bio_t, entry), next);
}

/** Read raw data from a bio
 *
 *  @param bio		the binary IO handler
 *  @param packet_ctx	packet-specific data associated with the buffer
 *  @param buffer	where to read the data
 *  @param size		amount of data to read.
 *  @return
 *	- <0 for error.  The return code will be fr_bio_error(ERROR_NAME)
 *	- 0 for "did not read any data".  EOF is a separate signal.
 */
static inline ssize_t CC_HINT(nonnull(1,3)) fr_bio_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	if (size == 0) return 0;

	/*
	 *	We cannot read from the middle of a chain.
	 */
	fr_assert(!fr_bio_prev(bio));

	return bio->read(bio, packet_ctx, buffer, size);
}

/** Write raw data to a bio
 *
 *  @param bio		the binary IO handler
 *  @param packet_ctx	packet-specific data associated with the buffer
 *  @param buffer	the data to write.  If NULL, will "flush" any pending data.
 *  @param size		amount of data to write.  For flush, it should be SIZE_MAX
 *  @return
 *	- <0 for error.  The return code will be fr_bio_error(ERROR_NAME)
 *	- 0 for "did not write any data"
 *	- >0 for amount of data written.  Should always be equal to size!
 */
static inline ssize_t CC_HINT(nonnull(1)) fr_bio_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	if (size == 0) return 0;

	/*
	 *	We cannot write to the middle of a chain.
	 */
	fr_assert(!fr_bio_prev(bio));

	return bio->write(bio, packet_ctx, buffer, size);
}

int	fr_bio_shutdown_intermediate(fr_bio_t *bio) CC_HINT(nonnull);

#ifndef NDEBUG
int	fr_bio_destructor(fr_bio_t *bio) CC_HINT(nonnull);
#else
#define fr_bio_destructor (NULL)
#endif

#define fr_bio_error(_x) (-(FR_BIO_ERROR_ ## _x))

int	fr_bio_shutdown(fr_bio_t *bio) CC_HINT(nonnull);

int	fr_bio_free(fr_bio_t *bio) CC_HINT(nonnull);

char const *fr_bio_strerror(ssize_t error);

void	fr_bio_cb_set(fr_bio_t *bio, fr_bio_cb_funcs_t const *cb) CC_HINT(nonnull(1));

#undef _CONST
