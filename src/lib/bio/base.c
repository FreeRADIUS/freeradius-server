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
 * @file lib/bio/base.c
 * @brief Binary IO abstractions.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */

#include <freeradius-devel/bio/bio_priv.h>
#include <freeradius-devel/bio/null.h>
#include <freeradius-devel/util/syserror.h>

#ifndef NDEBUG
/** Free this bio.
 *
 *  The bio can only be freed if it is not in any chain.
 */
int fr_bio_destructor(fr_bio_t *bio)
{
	fr_assert(!fr_bio_prev(bio));
	fr_assert(!fr_bio_next(bio));

	/*
	 *	It's safe to free this bio.
	 */
	return 0;
}
#endif

/** Internal bio function which just reads from the "next" bio.
 *
 *  It is mainly used when the current bio needs to modify the write
 *  path, but does not need to do anything on the read path.
 */
ssize_t fr_bio_next_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_t *next;

	next = fr_bio_next(bio);
	fr_assert(next != NULL);

	rcode = next->read(next, packet_ctx, buffer, size);
	if (rcode >= 0) return rcode;

	if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return rcode;

	bio->read = fr_bio_fail_read;
	bio->write = fr_bio_fail_write;
	return rcode;
}

/** Internal bio function which just writes to the "next" bio.
 *
 *  It is mainly used when the current bio needs to modify the read
 *  path, but does not need to do anything on the write path.
 */
ssize_t fr_bio_next_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	ssize_t rcode;
	fr_bio_t *next;

	next = fr_bio_next(bio);
	fr_assert(next != NULL);

	rcode = next->write(next, packet_ctx, buffer, size);
	if (rcode >= 0) return rcode;

	if (rcode == fr_bio_error(IO_WOULD_BLOCK)) return rcode;

	bio->read = fr_bio_fail_read;
	bio->write = fr_bio_fail_write;
	return rcode;
}

/** Free this bio, and everything it calls.
 *
 *  We unlink the bio chain, and then free it individually.  If there's an error, the bio chain is relinked.
 *  That way the error can be addressed (somehow) and this function can be called again.
 *
 *  Note that we do not support talloc_free() for the bio chain.  Each individual bio has to be unlinked from
 *  the chain before the destructor will allow it to be freed.  This functionality is by design.
 *
 *  We want to have an API where bios are created "bottom up", so that it is impossible for an application to
 *  create an incorrect chain.  However, creating the chain bottom up means that the lower bios not parented
 *  from the higher bios, and therefore talloc_free() won't free them.  As a result, we need an explicit
 *  bio_free() function.
 */
int fr_bio_free(fr_bio_t *bio)
{
	fr_bio_t *next = fr_bio_next(bio);

	/*
	 *	We cannot free a bio in the middle of a chain.  It has to be unlinked first.
	 */
	if (fr_bio_prev(bio)) return -1;

	/*
	 *	Unlink our bio, and recurse to free the next one.  If we can't free it, re-chain it, but reset
	 *	the read/write functions to do nothing.
	 */
	if (next) {
		next->entry.prev = NULL;
		if (fr_bio_free(next) < 0) {
			next->entry.prev = &bio->entry;
			bio->read = fr_bio_fail_read;
			bio->write = fr_bio_fail_write;
			return -1;
		}

		bio->entry.next = NULL;
	}

	/*
	 *	It's now safe to free this bio.
	 */
	return talloc_free(bio);
}

/** Shut down a set of BIOs
 *
 *  We shut down the BIOs from the top to the bottom.  This gives the TLS BIO an opportunity to
 *  call the SSL_shutdown() routine, which should then write to the FD BIO.
 */
int fr_bio_shutdown(fr_bio_t *bio)
{
	fr_bio_t *this, *first;
	fr_bio_common_t *my;

	fr_assert(!fr_bio_prev(bio));

	/*
	 *	Find the first bio in the chain.
	 */
	for (this = bio; fr_bio_prev(this) != NULL; this = fr_bio_prev(this)) {
		/* nothing */
	}
	first = this;

	/*
	 *	Walk back down the chain, calling the shutdown functions.
	 */
	for (/* nothing */; this != NULL; this = fr_bio_next(this)) {
		my = (fr_bio_common_t *) this;

		if (!my->priv_cb.shutdown) continue;

		/*
		 *	The EOF handler said it's NOT at EOF, so we stop processing here.
		 */
		my->priv_cb.shutdown(&my->bio);
		my->priv_cb.shutdown = NULL;
	}

	/*
	 *	Call the application shutdown routine
	 */
	my = (fr_bio_common_t *) first;

	if (my->cb.shutdown) my->cb.shutdown(first);
	my->cb.shutdown = NULL;

	return 0;
}

/** Like fr_bio_shutdown(), but can be called by anyone in the chain.
 *
 */
int fr_bio_shutdown_intermediate(fr_bio_t *bio)
{
	fr_bio_common_t *prev;

	while ((prev = (fr_bio_common_t *) fr_bio_prev(bio)) != NULL) {
		bio = (fr_bio_t *) prev;
	}

	return fr_bio_shutdown(bio);
}

char const *fr_bio_strerror(ssize_t error)
{
	switch (error) {
	case fr_bio_error(NONE):
		return "";

	case fr_bio_error(IO_WOULD_BLOCK):
		return "IO operation would block";

	case fr_bio_error(IO):
		return fr_syserror(errno);

	case fr_bio_error(GENERIC):
		return fr_strerror();

	case fr_bio_error(VERIFY):
		return "Packet fails verification";

	case fr_bio_error(BUFFER_FULL):
		return "Output buffer is full";

	case fr_bio_error(BUFFER_TOO_SMALL):
		return "Output buffer is too small to cache the data";

	default:
		return "<unknown>";
	}
}

void fr_bio_cb_set(fr_bio_t *bio, fr_bio_cb_funcs_t const *cb)
{
	fr_bio_common_t *my = (fr_bio_common_t *) bio;

	if (!cb) {
		memset(&my->cb, 0, sizeof(my->cb));
	} else {
		my->cb = *cb;
	}
}

/** Internal BIO function to run EOF callbacks.
 *
 *  When a BIO hits EOF, it MUST call this function.  This function will take care of changing the read()
 *  function to return nothing.  It will also take care of walking back up the hierarchy, and calling any
 *  BIO EOF callbacks.
 *
 *  Once all of the BIOs have been marked as blocked, it will call the application EOF callback.
 */
void fr_bio_eof(fr_bio_t *bio)
{
	fr_bio_common_t *this = (fr_bio_common_t *) bio;

	/*
	 *	This BIO is at EOF.  So we can't call read() any more.
	 */
	this->bio.read = fr_bio_null_read;

	while (true) {
		fr_bio_common_t *prev = (fr_bio_common_t *) fr_bio_prev(&this->bio);

		/*
		 *	There are no more BIOs. Tell the application that the entire BIO chain is at EOF.
		 */
		if (!prev) {
			if (this->cb.eof) {
				this->cb.eof(&this->bio);
				this->cb.eof = NULL;
			}
			break;
		}

		/*
		 *	Go to the previous BIO.  If it doesn't have an EOF handler, then keep going back up
		 *	the chain until we're at the top.
		 */
		this = prev;
		if (!this->priv_cb.eof) continue;

		/*
		 *	The EOF handler said it's NOT at EOF, so we stop processing here.
		 */
		if (this->priv_cb.eof((fr_bio_t *) this) == 0) break;

		/*
		 *	Don't run the EOF callback multiple times, and continue the loop.
		 */
		this->priv_cb.eof = NULL;
	}
}

/** Internal BIO function to tell all BIOs that it's blocked.
 *
 *  When a BIO blocks on write, it MUST call this function.  This function will take care of walking back up
 *  the hierarchy, and calling any write_blocked callbacks.
 *
 *  Once all of the BIOs have been marked as blocked, it will call the application write_blocked callback.
 */
int fr_bio_write_blocked(fr_bio_t *bio)
{
	fr_bio_common_t *this = (fr_bio_common_t *) bio;
	int is_blocked = 1;

	while (true) {
		fr_bio_common_t *prev = (fr_bio_common_t *) fr_bio_prev(&this->bio);
		int rcode;

		/*
		 *	There are no more BIOs. Tell the application that the entire BIO chain is blocked.
		 */
		if (!prev) {
			if (this->cb.write_blocked) {
				rcode = this->cb.write_blocked(&this->bio);
				if (rcode < 0) return rcode;
				is_blocked &= (rcode == 1);
			}
			break;
		}

		/*
		 *	Go to the previous BIO.  If it doesn't have a write_blocked handler, then keep going
		 *	back up the chain until we're at the top.
		 */
		this = prev;
		if (!this->priv_cb.write_blocked) continue;

		/*
		 *	The EOF handler said it's NOT at EOF, so we stop processing here.
		 */
		rcode = this->priv_cb.write_blocked((fr_bio_t *) this);
		if (rcode < 0) return rcode;
		is_blocked &= (rcode == 1);
	}

	return is_blocked;
}
