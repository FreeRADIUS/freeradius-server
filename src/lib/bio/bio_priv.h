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
 * @file lib/bio/bio_priv.h
 * @brief Binary IO private functions
 *
 *  Create abstract binary input / output buffers.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_bio_priv_h, "$Id$")

#define _BIO_PRIVATE 1
#include <freeradius-devel/bio/base.h>

typedef struct fr_bio_common_s fr_bio_common_t;

typedef struct {
	fr_bio_io_t		connected;
	fr_bio_io_t		shutdown;
	fr_bio_io_t		eof;
	fr_bio_callback_t	failed;

	fr_bio_io_t		read_blocked;
	fr_bio_io_t		write_blocked;

	fr_bio_io_t		read_resume;		//!< "unblocked" is too similar to "blocked"
	fr_bio_io_t		write_resume;
} fr_bio_priv_callback_t;

/** Common elements at the start of each private #fr_bio_t
 *
 */
#define FR_BIO_COMMON \
	fr_bio_t		bio; \
	fr_bio_cb_funcs_t	cb; \
	fr_bio_priv_callback_t	priv_cb

struct fr_bio_common_s {
	FR_BIO_COMMON;
};

/** Define a common destructor pattern.
 *
 *  Ensure that talloc_free() is safe no matter what.  The caller can free any BIO at any time.  If that
 *  happens, then the entire chain is shut down.  On successful shutdown, this BIO is removed from the chain.
 */
#define FR_BIO_DESTRUCTOR_COMMON \
do { \
	if (my->priv_cb.shutdown) {		   \
		int rcode;			   \
		rcode = fr_bio_shutdown(&my->bio); \
		if (rcode < 0) return rcode;	   \
	}					   \
	fr_bio_unchain(&my->bio);		   \
} while (0)


ssize_t fr_bio_next_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size);

ssize_t fr_bio_next_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size);

/** Chain one bio after another.
 *
 *  @todo - this likely needs to be public
 */
static inline void CC_HINT(nonnull) fr_bio_chain(fr_bio_t *first, fr_bio_t *second)
{
	fr_assert(first->entry.prev == NULL);
	fr_assert(first->entry.next == NULL);

	fr_assert(second->entry.prev == NULL);

	first->entry.next = &second->entry;
	second->entry.prev = &first->entry;
}

/** Remove a bio from a chain
 *
 *  And reset prev/next ptrs to NULL.
 *
 *  @todo - this likely needs to be public
 */
static inline void CC_HINT(nonnull) fr_bio_unchain(fr_bio_t *bio)
{
	fr_bio_t *prev = fr_bio_prev(bio);
	fr_bio_t *next = fr_bio_next(bio);

	fr_assert(prev || next);

	if (prev) prev->entry.next = &next->entry;

	if (next) next->entry.prev = &prev->entry;

	bio->entry.prev = bio->entry.next = NULL;
}

void	fr_bio_eof(fr_bio_t *bio) CC_HINT(nonnull);

int	fr_bio_write_blocked(fr_bio_t *bio) CC_HINT(nonnull);
