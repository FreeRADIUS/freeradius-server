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

/** Free this bio.
 *
 *  We allow talloc_free() to be called on just about anything in the
 *  bio chain.  But we ensure that the chain is always shut down in an
 *  orderly fashion.
 */
int fr_bio_destructor(fr_bio_t *bio)
{
	fr_bio_common_t *my = (fr_bio_common_t *) bio;

	FR_BIO_DESTRUCTOR_COMMON;

	return 0;
}

/** Internal bio function which just reads from the "next" bio.
 *
 *  It is mainly used when the current bio needs to modify the write
 *  path, but does not need to do anything on the read path.
 */
ssize_t fr_bio_next_read(fr_bio_t *bio, void *packet_ctx, void *buffer, size_t size)
{
	fr_bio_t *next;

	next = fr_bio_next(bio);
	fr_assert(next != NULL);

	return next->read(next, packet_ctx, buffer, size);
}

/** Internal bio function which just writes to the "next" bio.
 *
 *  It is mainly used when the current bio needs to modify the read
 *  path, but does not need to do anything on the write path.
 */
ssize_t fr_bio_next_write(fr_bio_t *bio, void *packet_ctx, void const *buffer, size_t size)
{
	fr_bio_t *next;

	next = fr_bio_next(bio);
	fr_assert(next != NULL);

	return next->write(next, packet_ctx, buffer, size);
}

ssize_t fr_bio_shutdown_read(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void *buffer, UNUSED size_t size)
{
	return fr_bio_error(SHUTDOWN);
}

ssize_t fr_bio_shutdown_write(UNUSED fr_bio_t *bio, UNUSED void *packet_ctx, UNUSED void const *buffer, UNUSED size_t size)
{
	return fr_bio_error(SHUTDOWN);
}

/** Shut down a set of BIOs
 *
 *  We shut down the BIOs from the top to the bottom.  This gives the
 *  TLS BIO an opportunity to call the SSL_shutdown() routine, which
 *  should then write to the FD BIO.  Once that write is completed,
 *  the FD BIO can then close its socket.
 *
 *  Any shutdown is "stop read / write", but is not "free all
 *  resources".  A shutdown can happen when one of the intermediary
 *  BIOs hits a fatal error.  It can't free the BIO, but it has to
 *  mark the entire BIO chain as being unusable.
 *
 *  A destructor will first shutdown the BIOs, and then free all resources.
 */
int fr_bio_shutdown(fr_bio_t *bio)
{
	int rcode;
	fr_bio_t *head, *this;
	fr_bio_common_t *my;

	/*
	 *	Find the first bio in the chain.
	 */
	head = fr_bio_head(bio);

	/*
	 *	We're in the process of shutting down, don't call ourselves recursively.
	 */
	my = (fr_bio_common_t *) head;
	if (my->bio.read == fr_bio_shutdown_read) return 0;

	/*
	 *	Walk back down the chain, calling the shutdown functions.
	 */
	for (this = head; this != NULL; this = fr_bio_next(this)) {
		my = (fr_bio_common_t *) this;

		if (my->priv_cb.shutdown) {
			rcode = my->priv_cb.shutdown(&my->bio);
			if (rcode < 0) return rcode;
			my->priv_cb.shutdown = NULL;
		}

		my->bio.read = fr_bio_shutdown_read;
		my->bio.write = fr_bio_shutdown_write;
		talloc_set_destructor(my, NULL);
	}

	/*
	 *	Call the application shutdown routine to tell it that
	 *	the BIO has been successfully shut down.
	 */
	my = (fr_bio_common_t *) head;

	if (my->cb.shutdown) {
		rcode = my->cb.shutdown(head);
		if (rcode < 0) return rcode;
		my->cb.shutdown = NULL;
	}

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

	case fr_bio_error(SHUTDOWN):
		return "The IO handler is not available.  It has been shut down due to a previous error";

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
		 *	The EOF handler said it's an error or NOT at EOF, so we stop processing here.
		 */
		if (this->priv_cb.eof((fr_bio_t *) this) <= 0) break;

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
