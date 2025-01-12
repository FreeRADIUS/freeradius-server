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

/** Functions for a basic binary heaps
 *
 * @file src/lib/util/iovec.c
 *
 * @copyright 2023 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSID("$Id$")

#include <freeradius-devel/util/iovec.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

/** Concatenate an iovec into a dbuff
 *
 * @param[out] out	dbuff to write to.
 * @param[in] vector	to concatenate.
 * @param[in] iovcnt	length of vector array.
 * @return
 *	- >= 0 on success.
 *	- <0 on failure.
 */
fr_slen_t fr_concatv(fr_dbuff_t *out, struct iovec vector[], int iovcnt)
{
	int i;

	fr_dbuff_t our_out = FR_DBUFF(out);

	for (i = 0; i < iovcnt; i++) FR_DBUFF_IN_MEMCPY_RETURN(&our_out,
							       (uint8_t *)vector[i].iov_base, vector[i].iov_len);

	return fr_dbuff_set(out, &our_out);
}

/** Write out a vector to a file descriptor
 *
 * Wraps writev, calling it as necessary. If timeout is not NULL,
 * timeout is applied to each call that returns EAGAIN or EWOULDBLOCK
 *
 * @note Should only be used on nonblocking file descriptors.
 * @note Socket should likely be closed on timeout.
 * @note iovec may be modified in such a way that it's not reusable.
 * @note Leaves errno set to the last error that occurred.
 *
 * @param fd to write to.
 * @param vector to write.
 * @param iovcnt number of elements in iovec.
 * @param timeout how long to wait for fd to become writable before timing out.
 * @return
 *	- Number of bytes written.
 *	- -1 on failure.
 */
ssize_t fr_writev(int fd, struct iovec vector[], int iovcnt, fr_time_delta_t timeout)
{
	struct iovec *vector_p = vector;
	ssize_t total = 0;

	while (iovcnt > 0) {
		ssize_t wrote;

		wrote = writev(fd, vector_p, iovcnt);
		if (wrote > 0) {
			total += wrote;
			while (wrote > 0) {
				/*
				 *	An entire vector element was written
				 */
				if (wrote >= (ssize_t)vector_p->iov_len) {
					iovcnt--;
					wrote -= vector_p->iov_len;
					vector_p++;
					continue;
				}

				/*
				 *	Partial vector element was written
				 */
				vector_p->iov_len -= wrote;
				vector_p->iov_base = ((char *)vector_p->iov_base) + wrote;
				break;
			}
			continue;
		} else if (wrote == 0) {
			/* coverity[return_overflow] */
			return total;
		}

		switch (errno) {
		/* Write operation would block, use select() to implement a timeout */
#if EWOULDBLOCK != EAGAIN
		case EWOULDBLOCK:
		case EAGAIN:
#else
		case EAGAIN:
#endif
		{
			int	ret;
			fd_set	write_set;

			FD_ZERO(&write_set);
			FD_SET(fd, &write_set);

			/* Don't let signals mess up the select */
			do {
				ret = select(fd + 1, NULL, &write_set, NULL, &(fr_time_delta_to_timeval(timeout)));
			} while ((ret == -1) && (errno == EINTR));

			/* Select returned 0 which means it reached the timeout */
			if (ret == 0) {
				fr_strerror_const("Write timed out");
				return -1;
			}

			/* Other select error */
			if (ret < 0) {
				fr_strerror_printf("Failed waiting on socket: %s", fr_syserror(errno));
				return -1;
			}

			/* select said a file descriptor was ready for writing */
			if (!fr_cond_assert(FD_ISSET(fd, &write_set))) return -1;

			break;
		}

		default:
			return -1;
		}
	}

	return total;
}
