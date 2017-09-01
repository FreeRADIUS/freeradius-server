/*
 * log.c	Functions in the library call radlib_log() which
 *		does internal logging.
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
 * Copyright 2000,2006  The FreeRADIUS server project
 */

RCSID("$Id$")

#include <freeradius-devel/libradius.h>

/*
 *	Are we using glibc or a close relative?
 */
#ifdef HAVE_FEATURES_H
#  include <features.h>
#endif

#define FR_STRERROR_BUFSIZE (2048)

fr_thread_local_setup(char *, fr_strerror_buffer)	/* macro */
fr_thread_local_setup(char *, fr_syserror_buffer)	/* macro */

#ifndef NDEBUG
/** POSIX-2008 errno macros
 *
 * Non-POSIX macros may be added, but you must check they're defined.
 */
static char const *fr_errno_macro_names[] = {
	[E2BIG] = "E2BIG",
	[EACCES] = "EACCES",
	[EADDRINUSE] = "EADDRINUSE",
	[EADDRNOTAVAIL] = "EADDRNOTAVAIL",
	[EAFNOSUPPORT] = "EAFNOSUPPORT",
#if EWOULDBLOCK == EAGAIN
	[EWOULDBLOCK] = "EWOULDBLOCK or EAGAIN",
#else
	[EAGAIN] = "EAGAIN",
	[EWOULDBLOCK] = "EWOULDBLOCK",
#endif
	[EALREADY] = "EALREADY",
	[EBADF] = "EBADF",
	[EBADMSG] = "EBADMSG",
	[EBUSY] = "EBUSY",
	[ECANCELED] = "ECANCELED",
	[ECHILD] = "ECHILD",
	[ECONNABORTED] = "ECONNABORTED",
	[ECONNREFUSED] = "ECONNREFUSED",
	[ECONNRESET] = "ECONNRESET",
	[EDEADLK] = "EDEADLK",
	[EDESTADDRREQ] = "EDESTADDRREQ",
	[EDOM] = "EDOM",
	[EDQUOT] = "EDQUOT",
	[EEXIST] = "EEXIST",
	[EFAULT] = "EFAULT",
	[EFBIG] = "EFBIG",
	[EHOSTUNREACH] = "EHOSTUNREACH",
	[EIDRM] = "EIDRM",
	[EILSEQ] = "EILSEQ",
	[EINPROGRESS] = "EINPROGRESS",
	[EINTR] = "EINTR",
	[EINVAL] = "EINVAL",
	[EIO] = "EIO",
	[EISCONN] = "EISCONN",
	[EISDIR] = "EISDIR",
	[ELOOP] = "ELOOP",
	[EMFILE] = "EMFILE",
	[EMLINK] = "EMLINK",
	[EMSGSIZE] = "EMSGSIZE",
	[EMULTIHOP] = "EMULTIHOP",
	[ENAMETOOLONG] = "ENAMETOOLONG",
	[ENETDOWN] = "ENETDOWN",
	[ENETRESET] = "ENETRESET",
	[ENETUNREACH] = "ENETUNREACH",
	[ENFILE] = "ENFILE",
	[ENOBUFS] = "ENOBUFS",
#ifdef ENODATA
	[ENODATA] = "ENODATA",
#endif
	[ENODEV] = "ENODEV",
	[ENOENT] = "ENOENT",
	[ENOEXEC] = "ENOEXEC",
	[ENOLCK] = "ENOLCK",
	[ENOLINK] = "ENOLINK",
	[ENOMEM] = "ENOMEM",
	[ENOMSG] = "ENOMSG",
	[ENOPROTOOPT] = "ENOPROTOOPT",
	[ENOSPC] = "ENOSPC",
#ifdef ENOSR
	[ENOSR] = "ENOSR",
#endif
#ifdef ENOSTR
	[ENOSTR] = "ENOSTR",
#endif
	[ENOSYS] = "ENOSYS",
	[ENOTCONN] = "ENOTCONN",
	[ENOTDIR] = "ENOTDIR",
	[ENOTEMPTY] = "ENOTEMPTY",
#ifdef ENOTRECOVERABLE
	[ENOTRECOVERABLE] = "ENOTRECOVERABLE",
#endif
	[ENOTSOCK] = "ENOTSOCK",
	[ENOTSUP] = "ENOTSUP",
#if ENOTSUP != EOPNOTSUPP
	[EOPNOTSUPP] = "EOPNOTSUPP",
#endif
	[ENOTTY] = "ENOTTY",
	[ENXIO] = "ENXIO",
	[EOVERFLOW] = "EOVERFLOW",
#ifdef EOWNERDEAD
	[EOWNERDEAD] = "EOWNERDEAD",
#endif
	[EPERM] = "EPERM",
	[EPIPE] = "EPIPE",
	[EPROTO] = "EPROTO",
	[EPROTONOSUPPORT] = "EPROTONOSUPPORT",
	[EPROTOTYPE] = "EPROTOTYPE",
	[ERANGE] = "ERANGE",
	[EROFS] = "EROFS",
	[ESPIPE] = "ESPIPE",
	[ESRCH] = "ESRCH",
	[ESTALE] = "ESTALE",
#ifdef ETIME
	[ETIME] = "ETIME",
#endif
	[ETIMEDOUT] = "ETIMEDOUT",
	[ETXTBSY] = "ETXTBSY",
	[EXDEV] = "EXDEV"
};
#endif

/*
 *	Explicitly cleanup the memory allocated to the error buffer,
 *	just in case valgrind complains about it.
 */
static void _fr_logging_free(void *arg)
{
	free(arg);
}

/** Log to thread local error buffer
 *
 * @param fmt printf style format string. If NULL sets the 'new' byte to false,
 *	  effectively clearing the last message.
 */
void fr_strerror_printf(char const *fmt, ...)
{
	va_list ap;

	char *buffer;

	buffer = fr_thread_local_init(fr_strerror_buffer, _fr_logging_free);
	if (!buffer) {
		int ret;

		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = calloc((FR_STRERROR_BUFSIZE * 2) + 1, sizeof(char));	/* One byte extra for status */
		if (!buffer) {
			fr_perror("Failed allocating memory for libradius error buffer");
			return;
		}

		ret = fr_thread_local_set(fr_strerror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for libradius error buffer: %s", fr_syserror(ret));
			free(buffer);
			return;
		}
	}

	/*
	 *	NULL has a special meaning, setting the new bit to false.
	 */
	if (!fmt) {
		buffer[FR_STRERROR_BUFSIZE * 2] &= 0x06;
		return;
	}

	va_start(ap, fmt);
	/*
	 *	Alternate where we write the message, so we can do:
	 *	fr_strerror_printf("Additional error: %s", fr_strerror());
	 */
	switch (buffer[FR_STRERROR_BUFSIZE * 2] & 0x06) {
	default:
		vsnprintf(buffer + FR_STRERROR_BUFSIZE, FR_STRERROR_BUFSIZE, fmt, ap);
		buffer[FR_STRERROR_BUFSIZE * 2] = 0x05;			/* Flip the 'new' bit to true */
		break;

	case 0x04:
		vsnprintf(buffer, FR_STRERROR_BUFSIZE, fmt, ap);
		buffer[FR_STRERROR_BUFSIZE * 2] = 0x03;			/* Flip the 'new' bit to true */
		break;
	}
	va_end(ap);
}

/** Get the last library error
 *
 * Will only return the last library error once, after which it will return a zero length string.
 *
 * @return library error or zero length string
 */
char const *fr_strerror(void)
{
	char *buffer;

	buffer = fr_thread_local_get(fr_strerror_buffer);
	if (!buffer) return "";

	switch (buffer[FR_STRERROR_BUFSIZE * 2]) {
	default:
		return "";

	case 0x03:
		buffer[FR_STRERROR_BUFSIZE * 2] &= 0x06;		/* Flip the 'new' bit to false */
		return buffer;

	case 0x05:
		buffer[FR_STRERROR_BUFSIZE * 2] &= 0x06;		/* Flip the 'new' bit to false */
		return buffer + FR_STRERROR_BUFSIZE;
	}
}

/** Guaranteed to be thread-safe version of strerror
 *
 * @param num errno as returned by function or from global errno.
 * @return local specific error string relating to errno.
 */
char const *fr_syserror(int num)
{
	char *buffer, *p, *end;
	int ret;

	buffer = fr_thread_local_init(fr_syserror_buffer, _fr_logging_free);
	if (!buffer) {
		/*
		 *	malloc is thread safe, talloc is not
		 */
		buffer = malloc(sizeof(char) * FR_STRERROR_BUFSIZE);
		if (!buffer) {
			fr_perror("Failed allocating memory for system error buffer");
			return NULL;
		}

		ret = fr_thread_local_set(fr_syserror_buffer, buffer);
		if (ret != 0) {
			fr_perror("Failed setting up TLS for system error buffer: %s", fr_syserror(ret));
			free(buffer);
			return NULL;
		}
	}

	if (!num) return "No error";

	p = buffer;
	end = p + FR_STRERROR_BUFSIZE;

#ifndef NDEBUG
	/*
	 *	Prefix system errors with the macro name and number
	 *	if we're debugging.
	 */
	if (num < (int)(sizeof(fr_errno_macro_names) / sizeof(*fr_errno_macro_names))) {
		p += snprintf(p, end - p, "%s: ", fr_errno_macro_names[num]);
	} else {
		p += snprintf(p, end - p, "errno %i: ", num);
	}
	if (p >= end) return p;
#endif

	/*
	 *	XSI-Compliant version
	 */
#if !defined(HAVE_FEATURES_H) || !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 500) && ! _GNU_SOURCE)
	ret = strerror_r(num, p, end - p);
	if (ret != 0) {
#  ifndef NDEBUG
		fprintf(stderr, "strerror_r() failed to write error for errno %i to buffer %p (%zu bytes), "
			"returned %i: %s\n", num, buffer, (size_t) FR_STRERROR_BUFSIZE, ret, strerror(ret));
#  endif
		buffer[0] = '\0';
	}
	return buffer;
	/*
	 *	GNU Specific version
	 *
	 *	The GNU Specific version returns a char pointer. That pointer may point
	 *	the buffer you just passed in, or to an immutable static string.
	 */
#else
	{
		p = strerror_r(num, p, end - p);
		if (!p) {
#  ifndef NDEBUG
			fprintf(stderr, "strerror_r() failed to write error for errno %i to buffer %p "
				"(%zu bytes): %s\n", num, buffer, (size_t) FR_STRERROR_BUFSIZE, strerror(errno));
#  endif
			buffer[0] = '\0';
			return buffer;
		}

		return p;
	}
#endif

}

void fr_perror(char const *fmt, ...)
{
	char const *error;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);

	error = fr_strerror();
	if (error && (error[0] != '\0')) {
		fprintf(stderr, ": %s\n", error);
	} else {
		fputs("\n", stderr);
	}

	va_end(ap);
}
