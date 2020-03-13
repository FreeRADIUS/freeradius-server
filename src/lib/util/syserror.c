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

/** Support functions to allow libraries to get system errors in a threadsafe and easily debuggable way
 *
 * @file src/lib/util/syserror.c
 *
 * @copyright 2017 The FreeRADIUS server project
 * @copyright 2017 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSID("$Id$")

#include <freeradius-devel/util/log.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>
#include <freeradius-devel/util/thread_local.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <talloc.h>

#define FR_SYSERROR_BUFSIZE (2048)

static _Thread_local char *fr_syserror_buffer;
static _Thread_local bool logging_stop;	//!< Due to ordering issues we may get errors being
					///< logged from within other thread local destructors
					///< which cause a crash on exit if the logging buffer
					///< has already been freed.

#define HAVE_DEFINITION(_errno) ((_errno) < (int)(NUM_ELEMENTS(fr_syserror_macro_names)))

/*
 *	Explicitly cleanup the memory allocated to the error buffer,
 *	just in case valgrind complains about it.
 */
static void _fr_logging_free(UNUSED void *arg)
{
	TALLOC_FREE(fr_syserror_buffer);
	logging_stop = true;
}

/** POSIX-2008 errno macros
 *
 * Non-POSIX macros may be added, but you must check they're defined.
 */
static char const *fr_syserror_macro_names[] = {
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
#if ENOTSUP == EOPNOTSUPP
	[ENOTSUP] = "ENOTSUP or EOPNOTSUPP",
#else
	[ENOTSUP] = "ENOTSUP",
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

/** Guaranteed to be thread-safe version of strerror
 *
 * @param num errno as returned by function or from global errno.
 * @return local specific error string relating to errno.
 */
char const *fr_syserror(int num)
{
	char *buffer, *p, *end;

	buffer = fr_syserror_buffer;
	if (!buffer) {
		/*
		 *	Try and produce something useful,
		 *	even if the thread is exiting.
		 */
		if (logging_stop) {
			if (HAVE_DEFINITION(num)) return fr_syserror_macro_names[num];
			return "";
		}

		buffer = talloc_array(NULL, char, FR_SYSERROR_BUFSIZE);
		if (!buffer) {
			fr_perror("Failed allocating memory for system error buffer");
			return NULL;
		}
 		fr_thread_local_set_destructor(fr_syserror_buffer, _fr_logging_free, buffer);
	}

	if (num == 0) return "No additional error information";

	p = buffer;
	end = p + FR_SYSERROR_BUFSIZE;

	/*
	 *	Prefix system errors with the macro name and number
	 *	if we're debugging.
	 */
	if (HAVE_DEFINITION(num)) {
		p += snprintf(p, end - p, "%s: ", fr_syserror_macro_names[num]);
	} else {
		p += snprintf(p, end - p, "errno %i: ", num);
	}
	if (p >= end) return p;

	/*
	 *	XSI-Compliant version
	 */
#if !defined(HAVE_FEATURES_H) || !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 500) && ! _GNU_SOURCE)
	{
		int ret;

		ret = strerror_r(num, p, end - p);
		if (ret != 0) {
#  ifndef NDEBUG
			fprintf(stderr, "strerror_r() failed to write error for errno %i to buffer %p (%zu bytes), "
				"returned %i: %s\n", num, buffer, (size_t)FR_SYSERROR_BUFSIZE, ret, strerror(ret));
#  endif
			buffer[0] = '\0';
		}
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
		char *q;

		q = strerror_r(num, p, end - p);
		if (!q) {
#  ifndef NDEBUG
			fprintf(stderr, "strerror_r() failed to write error for errno %i to buffer %p "
				"(%zu bytes): %s\n", num, buffer, (size_t)FR_SYSERROR_BUFSIZE, strerror(errno));
#  endif
			buffer[0] = '\0';
			return buffer;
		}

		/*
		 *	If strerror_r used a static string, copy it to the buffer
		 */
		if (q != p) {
			size_t len;

			len = strlen(q) + 1;
			if (len >= (size_t)(end - p)) len = end - p;

			strlcpy(p, q, len);
		}

		return buffer;
	}
#endif
}
