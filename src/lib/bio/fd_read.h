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
 * @file lib/bio/fd_read.h
 * @brief Common finalization code for the FD bio read functions.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_read_h, "$Id$")

#include <freeradius-devel/bio/fd_errno.h>

/** Common finalization code for the read functions.
 *
 *  The caller must not pass rcode==0.  A read of 0 means different things for datagram and stream sockets, so
 *  each caller deals with it before getting here.
 *
 *  @todo - do we want the callbacks to notify the _previous_ BIO in the chain?  That way the top-level
 *  BIO can notify the application.
 *
 * @param my			the FD bio.
 * @param[in,out] rcode_p	in: the read() return code.  out: what to return to the application.
 * @param[in,out] tries_p	how many times we have retried on EINTR.
 * @return
 *	- false		return *rcode_p to the application.
 *	- true		the read was interrupted, redo it.
 */
static inline CC_HINT(always_inline) bool fr_bio_fd_read_retry(fr_bio_fd_t *my, ssize_t *rcode_p, int *tries_p)
{
	if (*rcode_p > 0) {
		/*
		 *	We weren't blocked, so we're still not blocked.
		 */
		if (!my->info.read_blocked) return false;

		/*
		 *	We were blocked.  Since we just read data, we're now unblocked.
		 */
		my->info.read_blocked = false;

		/*
		 *	Call the "resume" function when we transition to being unblocked.
		 */
		if (my->cb.read_resume) {
			int error;

			error = my->cb.read_resume((fr_bio_t *) my);
			if (error < 0) *rcode_p = error;
		}

		return false;
	}

	fr_assert(*rcode_p < 0);

	return fr_bio_fd_errno_retry(my, rcode_p, tries_p, false);
}
