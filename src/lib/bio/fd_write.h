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
 * @file lib/bio/fd_write.h
 * @brief Common finalization code for the FD bio write functions.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_write_h, "$Id$")

#include <freeradius-devel/bio/fd_errno.h>

/** Common finalization code for the write functions.
 *
 *  @todo - do we want the callbacks to notify the _previous_ BIO in the chain?  That way the top-level
 *  BIO can notify the application.
 *
 * @param my			the FD bio.
 * @param[in,out] rcode_p	in: the write() return code.  out: what to return to the application.
 * @param[in,out] tries_p	how many times we have retried on EINTR.
 * @param size			how many bytes the application asked us to write.
 * @return
 *	- false		return *rcode_p to the application.
 *	- true		the write was interrupted, redo it.
 */
static inline CC_HINT(always_inline) bool fr_bio_fd_write_retry(fr_bio_fd_t *my, ssize_t *rcode_p, int *tries_p, size_t size)
{
	ssize_t rcode = *rcode_p;

	if (rcode > 0) {
		int error;

		/*
		 *	We weren't blocked, but we may be blocked now.
		 */
		if (!my->info.write_blocked) {
			if ((size_t) rcode == size) return false;

			fr_assert((size_t) rcode < size);

			/*
			 *	Set the flag, and tell the other BIOs that we're blocked.
			 */
			my->info.write_blocked = true;

			error = fr_bio_write_blocked((fr_bio_t *) my);
			if (error < 0) *rcode_p = error;

			return false;
		}

		/*
		 *	We were blocked.  We're still blocked if we wrote _less_ than the amount of requested data.
		 *	If we wrote all of the data which was requested, then we're unblocked.
		 */
		my->info.write_blocked = ((size_t) rcode < size);

		/*
		 *	Call the "resume" function if we transitioned to being unblocked.
		 */
		if (!my->info.write_blocked && my->cb.write_resume) {
			error = my->cb.write_resume((fr_bio_t *) my);
			if (error < 0) *rcode_p = error;
		}

		return false;
	}

	if (rcode == 0) return false;

	return fr_bio_fd_errno_retry(my, rcode_p, tries_p, true);
}
