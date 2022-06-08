/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/** Various miscellaneous utility functions
 *
 * @file src/lib/util/misc.c
 *
 * @copyright 2000,2006 The FreeRADIUS server project
 */
RCSID("$Id$")

#include <freeradius-devel/util/dbuff.h>
#include <freeradius-devel/util/sbuff.h>
#include <freeradius-devel/util/syserror.h>

#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/uio.h>

#define FR_PUT_LE16(a, val)\
	do {\
		a[1] = ((uint16_t) (val)) >> 8;\
		a[0] = ((uint16_t) (val)) & 0xff;\
	} while (0)

/** Sets a signal handler using sigaction if available, else signal
 *
 * @param sig to set handler for.
 * @param func handler to set.
 */
int fr_set_signal(int sig, sig_t func)
{
#ifdef HAVE_SIGACTION
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	act.sa_handler = func;

	if (sigaction(sig, &act, NULL) < 0) {
		fr_strerror_printf("Failed setting signal %i handler via sigaction(): %s", sig, fr_syserror(errno));
		return -1;
	}
#else
	if (signal(sig, func) < 0) {
		fr_strerror_printf("Failed setting signal %i handler via signal(): %s", sig, fr_syserror(errno));
		return -1;
	}
#endif
	return 0;
}

/** Uninstall a signal for a specific handler
 *
 * man sigaction says these are fine to call from a signal handler.
 *
 * @param sig SIGNAL
 */
int fr_unset_signal(int sig)
{
#ifdef HAVE_SIGACTION
        struct sigaction act;

        memset(&act, 0, sizeof(act));
        act.sa_flags = 0;
        sigemptyset(&act.sa_mask);
        act.sa_handler = SIG_DFL;

        return sigaction(sig, &act, NULL);
#else
        return signal(sig, SIG_DFL);
#endif
}

#ifndef F_WRLCK
#error "missing definition for F_WRLCK, all file locks will fail"
#endif

/*
 *	cppcheck apparently can't pick this up from the system headers.
 */
#ifdef CPPCHECK
#define F_WRLCK
#endif

static int rad_lock(int fd, int lock_len, int cmd, int type)
{
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = type;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, cmd, (void *)&fl);
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 */
int rad_lockfd(int fd, int lock_len)
{
	return rad_lock(fd, lock_len, F_SETLKW, F_WRLCK);
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Nonblocking version.
 */
int rad_lockfd_nonblock(int fd, int lock_len)
{
	/*
	 *	Note that there's no "W" on SETLK
	 */
	return rad_lock(fd, lock_len, F_SETLK, F_WRLCK);
}

/*
 *	Internal wrapper for unlocking, to minimize the number of ifdef's
 *	in the source.
 */
int rad_unlockfd(int fd, int lock_len)
{
	/*
	 *	Note UNLOCK.
	 */
	return rad_lock(fd, lock_len, F_SETLK, F_UNLCK);
}

/** Consume the integer (or hex) portion of a value string
 *
 * Allows integer or hex representations of integers (but not octal,
 * as octal is deemed to be confusing).
 *
 * @param[out] out	Result of parsing string as unsigned 64bit integer.
 * @param[out] end	pointer to the first non numeric char.
 * @param[in] value	string to parse.
 *
 * @return integer value.
 */
int fr_strtoull(uint64_t *out, char **end, char const *value)
{
	errno = 0;	/* Explicitly clear errors, as glibc appears not to do this */

	if ((value[0] == '0') && (value[1] == 'x')) {
		*out = strtoull(value, end, 16);
		if (errno == ERANGE) {
		error:
			fr_strerror_printf("Unsigned integer value \"%s\" too large, would overflow", value);
			return -1;
		}
		return 0;
	}

	*out = strtoull(value, end, 10);
	if (errno == ERANGE) goto error;
	return 0;
}

/** Consume the integer (or hex) portion of a value string
 *
 * Allows integer or hex representations of integers (but not octal,
 * as octal is deemed to be confusing).
 *
 * @note Check for overflow with errno == ERANGE.
 *
 * @param[out] out	Result of parsing string as signed 64bit integer.
 * @param[out] end	pointer to the first non numeric char.
 * @param[in] value	string to parse.
 * @return integer value.
 */
int fr_strtoll(int64_t *out, char **end, char const *value)
{
	errno = 0;	/* Explicitly clear errors, as glibc appears not to do this */

	if ((value[0] == '0') && (value[1] == 'x')) {
		*out = strtoll(value, end, 16);
		if (errno == ERANGE) {
		error:
			fr_strerror_printf("Signed integer value \"%s\" too large, would overflow", value);
			return -1;
		}
		return 0;
	}

	*out = strtoll(value, end, 10);
	if (errno == ERANGE) goto error;
	return 0;
}

/** Trim whitespace from the end of a string
 *
 */
char *fr_trim(char const *str, size_t size)
{
	char *q;

	if (!str || !size) return NULL;

	memcpy(&q, &str, sizeof(q));
	for (q = q + size; q > str && isspace(*q); q--);

	return q;
}

#ifdef O_NONBLOCK
/** Set O_NONBLOCK on a socket
 *
 * @note O_NONBLOCK is POSIX.
 *
 * @param fd to set nonblocking flag on.
 * @return
 *	- Flags set on the socket.
 *	- -1 on failure.
 */
int fr_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)  {
		fr_strerror_printf("Failed getting socket flags: %s", fr_syserror(errno));
		return -1;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		fr_strerror_printf("Failed setting socket flags: %s", fr_syserror(errno));
		return -1;
	}

	return flags;
}

/** Unset O_NONBLOCK on a socket
 *
 * @note O_NONBLOCK is POSIX.
 *
 * @param fd to set nonblocking flag on.
 * @return
 *	- Flags set on the socket.
 *	- -1 on failure.
 */
int fr_blocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0)  {
		fr_strerror_printf("Failed getting socket flags: %s", fr_syserror(errno));
		return -1;
	}

	if (!(flags & O_NONBLOCK)) return flags;

	flags ^= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		fr_strerror_printf("Failed setting socket flags: %s", fr_syserror(errno));
		return -1;
	}

	return flags;
}
#else
int fr_nonblock(UNUSED int fd)
{
	fr_strerror_const("Non blocking sockets are not supported");
	return -1;
}
int fr_blocking(UNUSED int fd)
{
	fr_strerror_const("Non blocking sockets are not supported");
	return -1;
}
#endif

/** Write out a vector to a file descriptor
 *
 * Wraps writev, calling it as necessary. If timeout is not NULL,
 * timeout is applied to each call that returns EAGAIN or EWOULDBLOCK
 *
 * @note Should only be used on nonblocking file descriptors.
 * @note Socket should likely be closed on timeout.
 * @note iovec may be modified in such a way that it's not re-usable.
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
		} else if (wrote == 0) return total;

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

/** Convert UTF8 string to UCS2 encoding
 *
 * @note Borrowed from src/crypto/ms_funcs.c of wpa_supplicant project (http://hostap.epitest.fi/wpa_supplicant/)
 *
 * @param[out] out Where to write the ucs2 string.
 * @param[in] outlen Size of output buffer.
 * @param[in] in UTF8 string to convert.
 * @param[in] inlen length of UTF8 string.
 * @return the size of the UCS2 string written to the output buffer (in bytes).
 */
ssize_t fr_utf8_to_ucs2(uint8_t *out, size_t outlen, char const *in, size_t inlen)
{
	size_t i;
	uint8_t *start = out;

	for (i = 0; i < inlen; i++) {
		uint8_t c, c2, c3;

		c = in[i];
		if ((size_t)(out - start) >= outlen) {
			/* input too long */
			return -1;
		}

		/* One-byte encoding */
		if (c <= 0x7f) {
			out[0] = (uint8_t)c;
			out[1] = 0;
			out += 2;
			continue;
		} else if ((i == (inlen - 1)) || ((size_t)(out - start) >= (outlen - 1))) {
			/* Incomplete surrogate */
			return -1;
		}

		c2 = in[++i];
		/* Two-byte encoding */
		if ((c & 0xe0) == 0xc0) {
			FR_PUT_LE16(out, ((c & 0x1f) << 6) | (c2 & 0x3f));
			out += 2;
			continue;
		}
		if ((i == inlen) || ((size_t)(out - start) >= (outlen - 1))) {
			/* Incomplete surrogate */
			return -1;
		}

		/* Three-byte encoding */
		c3 = in[++i];
		FR_PUT_LE16(out, ((c & 0xf) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f));
		out += 2;
	}

	return out - start;
}

/** Write 128bit unsigned integer to buffer
 *
 * @author Alexey Frunze
 *
 * @param out where to write result to.
 * @param outlen size of out.
 * @param num 128 bit integer.
 */
size_t fr_snprint_uint128(char *out, size_t outlen, uint128_t const num)
{
	char buff[] = "00000000000000000000000000000000000000000000";
	uint64_t n[2];
	char *p = buff;
	int i;
#ifndef WORDS_BIGENDIAN
	size_t const l = 0;
	size_t const h = 1;
#else
	size_t const l = 1;
	size_t const h = 0;
#endif

	memcpy(n, &num, sizeof(n));

	for (i = 0; i < 128; i++) {
		ssize_t j;
		int carry;

		carry = (n[h] >= 0x8000000000000000);

		// Shift n[] left, doubling it
		n[h] = ((n[h] << 1) & 0xffffffffffffffff) + (n[l] >= 0x8000000000000000);
		n[l] = ((n[l] << 1) & 0xffffffffffffffff);

		// Add s[] to itself in float, doubling it
		for (j = sizeof(buff) - 2; j >= 0; j--) {
			buff[j] += buff[j] - '0' + carry;
			carry = (buff[j] > '9');
			if (carry) buff[j] -= 10;
		}
	}

	while ((*p == '0') && (p < &buff[sizeof(buff) - 2])) p++;

	return strlcpy(out, p, outlen);
}

/** Multiply with modulo wrap
 *
 * Avoids multiplication overflow.
 *
 * @param[in] lhs	First operand.
 * @param[in] rhs	Second operand.
 * @param[in] mod	Modulo.
 * @return
 *	- Result.
 */
uint64_t fr_multiply_mod(uint64_t lhs, uint64_t rhs, uint64_t mod)
{
	uint64_t res = 0;

	lhs %= mod;

	while (rhs > 0) {
		if (rhs & 0x01) res = (res + lhs) % mod;

		lhs = (lhs * 2) % mod;
		rhs /= 2;
	}

	return res % mod;
}

/** Compares two pointers
 *
 * @param a first pointer to compare.
 * @param b second pointer to compare.
 * @return
 *	- -1 if a < b.
 *	- +1 if b > a.
 *	- 0 if both equal.
 */
int8_t fr_pointer_cmp(void const *a, void const *b)
{
	return CMP(a, b);
}

/** Quick sort an array of pointers using a comparator
 *
 * @param to_sort array of pointers to sort.
 * @param start the lowest index (usually 0).
 * @param end the length of the array.
 * @param cmp the comparison function to use to sort the array elements.
 */
void fr_quick_sort(void const *to_sort[], int start, int end, fr_cmp_t cmp)
{
	int		i, pi;
	void const	*pivot;

	if (start >= end) return;

#define SWAP(_a, _b) \
	do { \
		void const *_tmp = to_sort[_a]; \
		to_sort[_a] = to_sort[_b]; \
		to_sort[_b] = _tmp; \
	} while (0)

	pivot = to_sort[end];
	for (pi = start, i = start; i < end; i++) {
		if (cmp(to_sort[i], pivot) < 0) {
			SWAP(i , pi);
			pi++;
		}
	}
	SWAP(end, pi);

	fr_quick_sort(to_sort, start, pi - 1, cmp);
	fr_quick_sort(to_sort, pi + 1, end, cmp);
}

#ifdef TALLOC_DEBUG
void fr_talloc_verify_cb(UNUSED const void *ptr, UNUSED int depth,
			 UNUSED int max_depth, UNUSED int is_ref,
			 UNUSED void *private_data)
{
	/* do nothing */
}
#endif


/** Do a comparison of two authentication digests by comparing the FULL data.
 *
 * Otherwise, the server can be subject to timing attacks.
 *
 * http://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf
 */
int fr_digest_cmp(uint8_t const *a, uint8_t const *b, size_t length)
{
	int result = 0;
	size_t i;

	for (i = 0; i < length; i++) result |= a[i] ^ b[i];

	return result;		/* 0 is OK, !0 is !OK, just like memcmp */
}
