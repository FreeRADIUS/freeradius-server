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
 * @file lib/bio/fd_errno.h
 * @brief Common errno handling for FD bio reads and writes.
 *
 * @copyright 2024 Network RADIUS SAS (legal@networkradius.com)
 */
RCSIDH(lib_bio_fd_errno_h, "$Id$")

#include <freeradius-devel/bio/fd_priv.h>

/** Turn a failed read / write into a bio return code.
 *
 *  Only called when the syscall failed, i.e. when rcode is negative.
 *
 * @param my			the FD bio.
 * @param[in,out] rcode_p	in: the failed syscall return code.  out: what to return to the application.
 * @param[in,out] tries_p	how many times we have retried on EINTR.
 * @param is_write		true for the write path, false for the read path.
 * @return
 *	- false		return *rcode_p to the application.
 *	- true		the syscall was interrupted, redo it.
 */
static inline CC_HINT(always_inline) bool fr_bio_fd_errno_retry(fr_bio_fd_t *my, ssize_t *rcode_p, int *tries_p, bool is_write)
{
	bool		*blocked = is_write ? &my->info.write_blocked : &my->info.read_blocked;
	fr_bio_io_t	blocked_cb = is_write ? my->cb.write_blocked : my->cb.read_blocked;

	switch (errno) {
	case EINTR:
		/*
		 *	Try a few times before giving up.
		 */
		(*tries_p)++;
		if (*tries_p <= my->max_tries) return true;

		*rcode_p = fr_bio_error(IO);
		return false;

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
	case EWOULDBLOCK:
#endif
	case EAGAIN:
		/*
		 *	The operation would block, return that.
		 */
		if (!*blocked) {
			*blocked = true;

			if (blocked_cb) {
				int error;

				error = blocked_cb((fr_bio_t *) my);
				if (error < 0) {
					*rcode_p = error;
					return false;
				}
			}
		}

		*rcode_p = fr_bio_error(IO_WOULD_BLOCK);
		return false;

		/*
		 *	We're reading / writing a connected UDP socket, and the other end has gone away.
		 */
	case ENOTCONN:

		/*
		 *	The other end of a socket has closed the connection.
		 */
	case ECONNRESET:

		/*
		 *	The other end of a pipe has closed the connection.
		 */
	case EPIPE:
		/*
		 *	The connection is no longer usable, close it.
		 */
		fr_bio_eof(&my->bio);
		*rcode_p = 0;
		return false;

		/*
		 *	PMTU has been exceeded.  Return a generic IO error.
		 *
		 *	Only a write can exceed the PMTU, so a read which somehow reports EMSGSIZE is fatal.
		 *
		 *	@todo - do this only for connected UDP sockets.
		 *
		 *	However, recvmsg() can also return EMSGSIZE, if the msg_iovlen field has a bad value.
		 */
	case EMSGSIZE:
		*rcode_p = fr_bio_error(IO);
		return false;

		/*
		 *	The underlying network has gone away.  This is a fatal error for connected sockets,
		 *	but a recoverable one for unconnected sockets.
		 */
	case ENETDOWN:
	case ENETUNREACH:
		*rcode_p = fr_bio_error(IO);
		return false;

	default:
		/*
		 *	Some other error, it's fatal.
		 */
		break;
	}

	/*
	 *	Shut down the BIO.  It's no longer useable.
	 */
	(void) fr_bio_shutdown(&my->bio);

	*rcode_p = fr_bio_error(IO);
	return false;
}

/*
 *	Common code to suppress network failures on sendto / sendfromto for unconnected UDP sockets.
 *
 *	If the destination network is down or is unreachable, we want to simply discard the packet.  The error
 *	isn't fatal, so we don't close the socket.
 */
#define FD_ENET_SUPPRESS \
	do { \
		if ((rcode == fr_bio_error(IO)) && ((errno == ENETDOWN) || (errno == ENETUNREACH))) return 0; \
	} while (0)
