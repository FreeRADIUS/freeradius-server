/*
 * misc.c	Various miscellaneous functions.
 *
 * Version:	$Id$
 *
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
 *
 * @copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/util/base.h>

#include <ctype.h>
#include <sys/file.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/uio.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>

/*
 *	Some versions of Linux don't have closefrom(), but they will
 *	have /proc.
 *
 *	BSD systems will generally have closefrom(), but not proc.
 *
 *	OSX doesn't have closefrom() or /proc/self/fd, but it does
 *	have /dev/fd
 */
#ifdef __linux__
#define CLOSEFROM_DIR "/proc/self/fd"
#elif defined(__APPLE__)
#define CLOSEFROM_DIR "/dev/fd"
#else
#undef HAVE_DIRENT_H
#endif

#endif

#define FR_PUT_LE16(a, val)\
	do {\
		a[1] = ((uint16_t) (val)) >> 8;\
		a[0] = ((uint16_t) (val)) & 0xff;\
	} while (0)

int	fr_debug_lvl = 0;

static char const *months[] = {
	"jan", "feb", "mar", "apr", "may", "jun",
	"jul", "aug", "sep", "oct", "nov", "dec" };

typedef struct fr_talloc_link  fr_talloc_link_t;

struct fr_talloc_link {		/* allocated in the context of the parent */
	fr_talloc_link_t **self;   /* allocated in the context of the child */
	TALLOC_CTX *child;		/* allocated in the context of the child */
};

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

/** Called when the parent CTX is freed
 *
 */
static int _link_ctx_link_free(fr_talloc_link_t *link)
{
	/*
	 *	This hasn't been freed yet.  Mark it as "about to be
	 *	freed", and then free it.
	 */
	if (link->self) {
		fr_talloc_link_t **self = link->self;

		link->self = NULL;
		talloc_free(self);
	}
	talloc_free(link->child);

	/* link is freed by talloc when this function returns */
	return 0;
}


/** Called when the child CTX is freed
 *
 */
static int _link_ctx_self_free(fr_talloc_link_t **link_p)
{
	fr_talloc_link_t *link = *link_p;

	/*
	 *	link->child is freed by talloc at some other point,
	 *	which results in this destructor being called.
	 */

	/* link->self is freed by talloc when this function returns */

	/*
	 *	If link->self is still pointing to us, the link is
	 *	still valid.  Mark it as "about to be freed", and free the link.
	 */
	if (link->self) {
		link->self = NULL;
		talloc_free(link);
	}

	return 0;
}

/** Link two different parent and child contexts, so the child is freed before the parent
 *
 * @note This is not thread safe. Do not free parent before threads are joined, do not call from a
 *	child thread.
 * @note It's OK to free the child before threads are joined, but this will leak memory until the
 *	parent is freed.
 *
 * @param parent who's fate the child should share.
 * @param child bound to parent's lifecycle.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_talloc_link_ctx(TALLOC_CTX *parent, TALLOC_CTX *child)
{
	fr_talloc_link_t *link;

	link = talloc(parent, fr_talloc_link_t);
	if (!link) return -1;

	link->self = talloc(child, fr_talloc_link_t *);
	if (!link->self) {
		talloc_free(link);
		return -1;
	}

	link->child = child;
	*(link->self) = link;

	talloc_set_destructor(link, _link_ctx_link_free);
	talloc_set_destructor(link->self, _link_ctx_self_free);

	return 0;
}

/*
 *	cppcheck apparently can't pick this up from the system headers.
 */
#ifdef CPPCHECK
#define F_WRLCK
#endif

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Use fcntl or error
 */
int rad_lockfd(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_SETLKW, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

/*
 *	Internal wrapper for locking, to minimize the number of ifdef's
 *
 *	Lock an fd, prefer lockf() over flock()
 *	Nonblocking version.
 */
int rad_lockfd_nonblock(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_SETLK, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

/*
 *	Internal wrapper for unlocking, to minimize the number of ifdef's
 *	in the source.
 *
 *	Unlock an fd, prefer lockf() over flock()
 */
int rad_unlockfd(int fd, int lock_len)
{
#ifdef F_WRLCK
	struct flock fl;

	fl.l_start = 0;
	fl.l_len = lock_len;
	fl.l_pid = getpid();
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_CUR;

	return fcntl(fd, F_UNLCK, (void *)&fl);
#else
#error "missing definition for F_WRLCK, all file locks will fail"

	return -1;
#endif
}

static char const hextab[] = "0123456789abcdef";

/** Convert hex strings to binary data
 *
 * @param bin Buffer to write output to.
 * @param outlen length of output buffer (or length of input string / 2).
 * @param hex input string.
 * @param inlen length of the input string
 * @return length of data written to buffer.
 */
size_t fr_hex2bin(uint8_t *bin, size_t outlen, char const *hex, size_t inlen)
{
	size_t i;
	size_t len;
	char *c1, *c2;

	/*
	 *	Smartly truncate output, caller should check number of bytes
	 *	written.
	 */
	len = inlen >> 1;
	if (len > outlen) len = outlen;

	for (i = 0; i < len; i++) {
		if(!(c1 = memchr(hextab, tolower((int) hex[i << 1]), sizeof(hextab))) ||
		   !(c2 = memchr(hextab, tolower((int) hex[(i << 1) + 1]), sizeof(hextab))))
			break;
		bin[i] = ((c1-hextab)<<4) + (c2-hextab);
	}

	return i;
}

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @warning If the output buffer isn't long enough, we have a buffer overflow.
 *
 * @param[out] hex Buffer to write hex output.
 * @param[in] bin input.
 * @param[in] inlen of bin input.
 * @return length of data written to buffer.
 */
size_t fr_bin2hex(char *hex, uint8_t const *bin, size_t inlen)
{
	size_t i;

	for (i = 0; i < inlen; i++) {
		hex[0] = hextab[((*bin) >> 4) & 0x0f];
		hex[1] = hextab[*bin & 0x0f];
		hex += 2;
		bin++;
	}

	*hex = '\0';
	return inlen * 2;
}

/** Convert binary data to a hex string
 *
 * Ascii encoded hex string will not be prefixed with '0x'
 *
 * @param[in] ctx to alloc buffer in.
 * @param[in] bin input.
 * @param[in] inlen of bin input.
 * @return length of data written to buffer.
 */
char *fr_abin2hex(TALLOC_CTX *ctx, uint8_t const *bin, size_t inlen)
{
	char *buff;

	buff = talloc_array(ctx, char, (inlen << 2));
	if (!buff) return NULL;

	fr_bin2hex(buff, bin, inlen);

	return buff;
}

/** Consume the integer (or hex) portion of a value string
 *
 * Allows integer or hex representations of integers (but not octal,
 * as octal is deemed to be confusing).
 *
 * @param[in] value	string to parse.
 * @param[out] end	pointer to the first non numeric char.
 * @return integer value.
 */
uint64_t fr_strtoull(char const *value, char **end)
{
	if ((value[0] == '0') && (value[1] == 'x')) {
		return strtoull(value, end, 16);
	}

	return strtoull(value, end, 10);
}

/** Consume the integer (or hex) portion of a value string
 *
 * Allows integer or hex representations of integers (but not octal,
 * as octal is deemed to be confusing).
 *
 * @param[in] value	string to parse.
 * @param[out] end	pointer to the first non numeric char.
 * @return integer value.
 */
int64_t fr_strtoll(char const *value, char **end)
{
	if ((value[0] == '0') && (value[1] == 'x')) {
		return strtoll(value, end, 16);
	}

	return strtoll(value, end, 10);
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

/*
 *	So we don't have ifdef's in the rest of the code
 */
#ifndef HAVE_CLOSEFROM
int closefrom(int fd)
{
	int i;
	int maxfd = 256;
#ifdef HAVE_DIRENT_H
	DIR *dir;
#endif

#ifdef F_CLOSEM
	if (fcntl(fd, F_CLOSEM) == 0) {
		return 0;
	}
#endif

#ifdef F_MAXFD
	maxfd = fcntl(fd, F_F_MAXFD);
	if (maxfd >= 0) goto do_close;
#endif

#ifdef _SC_OPEN_MAX
	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd < 0) {
		maxfd = 256;
	}
#endif

#ifdef HAVE_DIRENT_H
	/*
	 *	Use /proc/self/fd directory if it exists.
	 */
	dir = opendir(CLOSEFROM_DIR);
	if (dir != NULL) {
		long my_fd;
		char *endp;
		struct dirent *dp;

		while ((dp = readdir(dir)) != NULL) {
			my_fd = strtol(dp->d_name, &endp, 10);
			if (my_fd <= 0) continue;

			if (*endp) continue;

			if (my_fd == dirfd(dir)) continue;

			if ((my_fd >= fd) && (my_fd <= maxfd)) {
				(void) close((int) my_fd);
			}
		}
		(void) closedir(dir);
		return 0;
	}
#endif

#ifdef F_MAXFD
do_close:
#endif

	if (fd > maxfd) return 0;

	/*
	 *	FIXME: return EINTR?
	 */
	for (i = fd; i < maxfd; i++) {
		close(i);
	}

	return 0;
}
#endif

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
	fr_strerror_printf("Non blocking sockets are not supported");
	return -1;
}
int fr_blocking(UNUSED int fd)
{
	fr_strerror_printf("Non blocking sockets are not supported");
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
ssize_t fr_writev(int fd, struct iovec vector[], int iovcnt, struct timeval *timeout)
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
				ret = select(fd + 1, NULL, &write_set, NULL, timeout);
			} while ((ret == -1) && (errno == EINTR));

			/* Select returned 0 which means it reached the timeout */
			if (ret == 0) {
				fr_strerror_printf("Write timed out");
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

/*
 *	Sort of strtok/strsep function.
 */
static char *mystrtok(char **ptr, char const *sep)
{
	char	*res;

	if (**ptr == 0) {
		return NULL;
	}

	while (**ptr && strchr(sep, **ptr)) {
		(*ptr)++;
	}
	if (**ptr == 0) {
		return NULL;
	}

	res = *ptr;
	while (**ptr && strchr(sep, **ptr) == NULL) {
		(*ptr)++;
	}

	if (**ptr != 0) {
		*(*ptr)++ = 0;
	}
	return res;
}

/** Convert string in various formats to a time_t
 *
 * @param date_str input date string.
 * @param date time_t to write result to.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_time_from_str(time_t *date, char const *date_str)
{
	int		i;
	time_t		t;
	struct tm	*tm, s_tm;
	char		buf[64];
	char		*p;
	char		*f[4];
	char		*tail = NULL;

	/*
	 * Test for unix timestamp date
	 */
	*date = strtoul(date_str, &tail, 10);
	if (*tail == '\0') {
		return 0;
	}

	tm = &s_tm;
	memset(tm, 0, sizeof(*tm));
	tm->tm_isdst = -1;	/* don't know, and don't care about DST */

	strlcpy(buf, date_str, sizeof(buf));

	p = buf;
	f[0] = mystrtok(&p, " \t");
	f[1] = mystrtok(&p, " \t");
	f[2] = mystrtok(&p, " \t");
	f[3] = mystrtok(&p, " \t"); /* may, or may not, be present */
	if (!f[0] || !f[1] || !f[2]) return -1;

	/*
	 *	The time has a colon, where nothing else does.
	 *	So if we find it, bubble it to the back of the list.
	 */
	if (f[3]) {
		for (i = 0; i < 3; i++) {
			if (strchr(f[i], ':')) {
				p = f[3];
				f[3] = f[i];
				f[i] = p;
				break;
			}
		}
	}

	/*
	 *  The month is text, which allows us to find it easily.
	 */
	tm->tm_mon = 12;
	for (i = 0; i < 3; i++) {
		if (isalpha((int) *f[i])) {
			int j;

			/*
			 *  Bubble the month to the front of the list
			 */
			p = f[0];
			f[0] = f[i];
			f[i] = p;

			for (j = 0; j < 12; j++) {
				if (strncasecmp(months[j], f[0], 3) == 0) {
					tm->tm_mon = j;
					break;
				}
			}
		}
	}

	/* month not found? */
	if (tm->tm_mon == 12) return -1;

	/*
	 *  The year may be in f[1], or in f[2]
	 */
	tm->tm_year = atoi(f[1]);
	tm->tm_mday = atoi(f[2]);

	if (tm->tm_year >= 1900) {
		tm->tm_year -= 1900;

	} else {
		/*
		 *  We can't use 2-digit years any more, they make it
		 *  impossible to tell what's the day, and what's the year.
		 */
		if (tm->tm_mday < 1900) return -1;

		/*
		 *  Swap the year and the day.
		 */
		i = tm->tm_year;
		tm->tm_year = tm->tm_mday - 1900;
		tm->tm_mday = i;
	}

	/*
	 *  If the day is out of range, die.
	 */
	if ((tm->tm_mday < 1) || (tm->tm_mday > 31)) {
		return -1;
	}

	/*
	 *	There may be %H:%M:%S.  Parse it in a hacky way.
	 */
	if (f[3]) {
		f[0] = f[3];	/* HH */
		f[1] = strchr(f[0], ':'); /* find : separator */
		if (!f[1]) return -1;

		*(f[1]++) = '\0'; /* nuke it, and point to MM:SS */

		f[2] = strchr(f[1], ':'); /* find : separator */
		if (f[2]) {
		  *(f[2]++) = '\0';	/* nuke it, and point to SS */
		  tm->tm_sec = atoi(f[2]);
		}			/* else leave it as zero */

		tm->tm_hour = atoi(f[0]);
		tm->tm_min = atoi(f[1]);
	}

	/*
	 *  Returns -1 on failure.
	 */
	t = mktime(tm);
	if (t == (time_t) -1) return -1;

	*date = t;

	return 0;
}

#define USEC 1000000

/** Convert a time specified in milliseconds to a timeval
 *
 * @param[out] out	Where to write the result.
 * @param[in] ms	To convert to a timeval struct.
 */
void fr_timeval_from_ms(struct timeval *out, uint64_t ms)
{
	out->tv_sec = ms / 1000;
	out->tv_usec = (ms % 1000) * 1000;
}

/** Convert a time specified in microseconds to a timeval
 *
 * @param[out] out	Where to write the result.
 * @param[in] usec	To convert to a timeval struct.
 */
void fr_timeval_from_usec(struct timeval *out, uint64_t usec)
{
	out->tv_sec = usec / USEC;
	out->tv_usec = (usec % USEC) * USEC;
}

/** Subtract one timeval from another
 *
 * @param[out] out Where to write difference.
 * @param[in] end Time closest to the present.
 * @param[in] start Time furthest in the past.
 */
void fr_timeval_subtract(struct timeval *out, struct timeval const *end, struct timeval const *start)
{
	out->tv_sec = end->tv_sec - start->tv_sec;
	if (out->tv_sec > 0) {
		out->tv_sec--;
		out->tv_usec = USEC;
	} else {
		out->tv_usec = 0;
	}
	out->tv_usec += end->tv_usec;
	out->tv_usec -= start->tv_usec;

	if (out->tv_usec >= USEC) {
		out->tv_usec -= USEC;
		out->tv_sec++;
	}
}

/** Add one timeval to another
 *
 * @param[out] out Where to write the sum of the two times.
 * @param[in] a first time to sum.
 * @param[in] b second time to sum.
 */
void fr_timeval_add(struct timeval *out, struct timeval const *a, struct timeval const *b)
{
	uint64_t usec;

	out->tv_sec = a->tv_sec + b->tv_sec;

	usec = a->tv_usec + b->tv_usec;
	if (usec >= USEC) {
		out->tv_sec++;
		usec -= USEC;
	}
	out->tv_usec = usec;
}

/** Divide a timeval by a divisor
 *
 * @param[out] out where to write the result of dividing in by the divisor.
 * @param[in] in Timeval to divide.
 * @param[in] divisor Integer to divide timeval by.
 */
void fr_timeval_divide(struct timeval *out, struct timeval const *in, int divisor)
{
	uint64_t x;

	x = (((uint64_t)in->tv_sec * USEC) + in->tv_usec) / divisor;

	out->tv_sec = x / USEC;
	out->tv_usec = x % USEC;
}

/** Compare two timevals
 *
 * @param[in] a First timeval.
 * @param[in] b Second timeval.
 * @return
 *	- +1 if a > b.
 *	- -1 if a < b.
 *	- 0 if a == b.
 */
int fr_timeval_cmp(struct timeval const *a, struct timeval const *b)
{
	int ret;

	ret = (a->tv_sec > b->tv_sec) - (a->tv_sec < b->tv_sec);
	if (ret != 0) return ret;

	return (a->tv_usec > b->tv_usec) - (a->tv_usec < b->tv_usec);
}

/** Create timeval from a string
 *
 * @param[out] out Where to write timeval.
 * @param[in] in String to parse.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int fr_timeval_from_str(struct timeval *out, char const *in)
{
	int	sec;
	char	*end;
	struct	timeval tv;

	sec = strtoul(in, &end, 10);
	if (in == end) {
		fr_strerror_printf("Failed parsing \"%s\" as float", in);
		return -1;
	}
	tv.tv_sec = sec;
	tv.tv_usec = 0;
	if (*end == '.') {
		size_t len;

		len = strlen(end + 1);

		if (len > 6) {
			fr_strerror_printf("Too much precision for timeval");
			return -1;
		}

		/*
		 *	If they write "0.1", that means
		 *	"10000" microseconds.
		 */
		sec = strtoul(end + 1, &end, 10);
		if (in == end) {
			fr_strerror_printf("Failed parsing fractional component \"%s\" of float", in);
			return -1;
		}
		while (len < 6) {
			sec *= 10;
			len++;
		}
		tv.tv_usec = sec;
	}
	*out = tv;
	return 0;
}

bool fr_timeval_isset(struct timeval const *tv)
{
	if (tv->tv_sec || tv->tv_usec) return true;
	return false;
}

int fr_size_from_str(size_t *out, char const *str)
{
	char		*q = NULL;
	uint64_t	size;

	*out = 0;

	size = strtoull(str, &q, 10);
	switch (tolower(q[0])) {
	case 'n':		/* nibble */
		if (size & 0x01) {
			fr_strerror_printf("Sizes specified in nibbles must be an even number");
			return -1;
		}
		size /= 2;
		break;

	case '\0':
	case 'b':		/* byte */
		break;

	case 'k':		/* kilobyte */
		if (fr_multiply(&size, size, 1024)) {
		overflow:
			fr_strerror_printf("Value must be less than %zu", (size_t)SIZE_MAX);
			return -1;
		}
		break;

	case 'm':		/* megabyte */
		if (fr_multiply(&size, size, (1024 * 1024))) goto overflow;
		break;

	case 'g':		/* gigabyte */
		if (fr_multiply(&size, size, (1024 * 1024 * 1024))) goto overflow;
		break;

	case 't':		/* terabyte */
		if (fr_multiply(&size, size, ((uint64_t)1024 * 1024 * 1024 * 1024))) goto overflow;
		break;

	default:
		fr_strerror_printf("Unknown unit '%c'", *q);
		return -1;
	}

	if ((q[0] != '\0') && (q[1] != '\0')) {
		fr_strerror_printf("Trailing garbage in size string \"%s\"", str);
		return -1;
	}

	if (size > SIZE_MAX) {
		fr_strerror_printf("Value %" PRIu64 " is greater than the maximum "
				   "file/memory size of this system (%zu)", size, (size_t)SIZE_MAX);

		goto overflow;
	}

	*out = (size_t)size;

	return 0;
}

#define NSEC 1000000000
/** Subtract one timespec from another
 *
 * @param[out] out Where to write difference.
 * @param[in] end Time closest to the present.
 * @param[in] start Time furthest in the past.
 */
void fr_timespec_subtract(struct timespec *out, struct timespec const *end, struct timespec const *start)
{
	out->tv_sec = end->tv_sec - start->tv_sec;
	if (out->tv_sec > 0) {
		out->tv_sec--;
		out->tv_nsec = NSEC;
	} else {
		out->tv_nsec = 0;
	}
	out->tv_nsec += end->tv_nsec;
	out->tv_nsec -= start->tv_nsec;

	if (out->tv_nsec >= NSEC) {
		out->tv_nsec -= NSEC;
		out->tv_sec++;
	}
}

/** Multiple checking for overflow
 *
 * @param[out] result	of multiplication.
 * @param[in] lhs	First operand.
 * @param[in] rhs	Second operand.
 *
 * @return
 *	- true multiplication overflowed.
 *	- false multiplication did not overflow.
 */
bool fr_multiply(uint64_t *result, uint64_t lhs, uint64_t rhs)
{
        *result = lhs * rhs;

        return rhs > 0 && (UINT64_MAX / rhs) < lhs;
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
	return (a > b) - (a < b);
}

/** Quick sort an array of pointers using a comparator
 *
 * @param to_sort array of pointers to sort.
 * @param start the lowest index (usually 0).
 * @param len the length of the array.
 * @param cmp the comparison function to use to sort the array elements.
 */
void fr_quick_sort(void const *to_sort[], int start, int len, fr_cmp_t cmp)
{
	int i = start;
	int j = len;

	void const *pivot  = to_sort[(i + j) / 2];

	while (i < j) {
		void const *tmp;

		do ++i; while ((i < len) && (cmp(to_sort[i], pivot) < 0));
		do --j; while ((i > start) && (cmp(to_sort[j], pivot) > 0));

		if (i <= j) {
			tmp = to_sort[i];
			to_sort[i] = to_sort[j];
			to_sort[j] = tmp;

			i++;
			j--;
		}
	}

	if (start < j) fr_quick_sort(to_sort, start, j, cmp);
	if (i < len) fr_quick_sort(to_sort, i, len, cmp);
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
