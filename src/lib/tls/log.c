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
 *
 * @file tls/log.c
 * @brief Retrieve errors and log messages from OpenSSL's overly complex log system.
 *
 * @copyright 2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/rad_assert.h>

DIAG_OFF(format-nonliteral)
/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out errors.
 *
 * @param[in] request	The current request (may be NULL).
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ap	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
static int tls_log_error_va(REQUEST *request, char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p;
	int		in_stack = 0;
	char		buffer[256];

	int		line;
	char const	*file;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_line(&file, &line);

	if (msg) {
		p = talloc_vasprintf(request, msg, ap);

		/*
		 *	Single line mode (there's only one error)
		 */
		if (error && !ERR_peek_error()) {
			ERR_error_string_n(error, buffer, sizeof(buffer));

			/* Extra verbose */
			if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
				ROPTIONAL(REDEBUG, ERROR, "%s: %s[%i]:%s", p, file, line, buffer);
			} else {
				ROPTIONAL(REDEBUG, ERROR, "%s: %s", p, buffer);
			}

			talloc_free(p);

			return 1;
		}

		/*
		 *	Print the error we were given, irrespective
		 *	of whether there were any OpenSSL errors.
		 */
		ROPTIONAL(RERROR, ERROR, "%s", p);
		talloc_free(p);
	}

	/*
	 *	Stack mode (there are multiple errors)
	 */
	if (!error) return 0;
	do {
		ERR_error_string_n(error, buffer, sizeof(buffer));
		/* Extra verbose */
		if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
			ROPTIONAL(REDEBUG, ERROR, "%s[%i]:%s", file, line, buffer);
		} else {
			ROPTIONAL(REDEBUG, ERROR, "%s", buffer);
		}
		in_stack++;
	} while ((error = ERR_get_error_line(&file, &line)));

	return in_stack;
}
DIAG_ON(format-nonliteral)

/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out errors.
 *
 * @param[in] request	The current request (may be NULL).
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
int tls_log_error(REQUEST *request, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = tls_log_error_va(request, msg, ap);
	va_end(ap);

	return ret;
}

DIAG_OFF(format-nonliteral)
/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out the first error
 * storing it in libfreeradius's error buffer.
 *
 * @param[in] drain_all	drain all errors in TLS stack.
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ap	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
static int tls_strerror_printf_va(bool drain_all, char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p = NULL;
	int		drained = 0;
	char		buffer[256];

	int		line;
	char const	*file;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_line(&file, &line);

	if (msg) {
		/*
		 *	Print the error we were passed, and
		 *	OpenSSL's error.
		 */
		p = talloc_vasprintf(NULL, msg, ap);
		if (error) {
			ERR_error_string_n(error, buffer, sizeof(buffer));
			fr_strerror_printf("%s: %s", p, buffer);
			talloc_free(p);
			drained++;
		/*
		 *	Print the error we were given, irrespective
		 *	of whether there were any OpenSSL errors.
		 */
		} else {
			fr_strerror_printf("%s", p);
			talloc_free(p);
		}
	} else if (error) {
		ERR_error_string_n(error, buffer, sizeof(buffer));
		fr_strerror_printf("%s", buffer);
		drained++;
	} else {
		return 0;
	}

	if (!drain_all) return drained;

	while ((error = ERR_get_error_line(&file, &line))) drained++;

	return drained;
}
DIAG_ON(format-nonliteral)

/** Wrapper around fr_strerror_printf to log error messages for library functions calling libssl
 *
 * @note Will only drain the first error.
 *
 * @param[in] drain_all	drain all errors in TLS stack.
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
int tls_strerror_printf(bool drain_all, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = tls_strerror_printf_va(drain_all, msg, ap);
	va_end(ap);

	return ret;
}

/** Print errors raised by OpenSSL I/O functions
 *
 * Drains the thread local OpenSSL error queue, and prints out errors
 * based on the SSL handle and the return code of the I/O  function.
 *
 * OpenSSL lists I/O functions to be:
 *   - SSL_connect
 *   - SSL_accept
 *   - SSL_do_handshake
 *   - SSL_read
 *   - SSL_peek
 *   - SSL_write
 *
 * @param request	The current request (may be NULL).
 * @param session	The current tls_session.
 * @param ret		from the I/O operation.
 * @param msg		Error message describing the operation being attempted.
 * @param ...		Arguments for msg.
 * @return
 *	- 0 TLS session cannot continue.
 *	- 1 TLS session may still be viable.
 */
int tls_log_io_error(REQUEST *request, tls_session_t *session, int ret, char const *msg, ...)
{
	int	error;
	va_list	ap;

	if (ERR_peek_error()) {
		va_start(ap, msg);
		tls_log_error_va(request, msg, ap);
		va_end(ap);
	}

	error = SSL_get_error(session->ssl, ret);
	switch (error) {
	/*
	 *	These seem to be harmless and already "dealt
	 *	with" by our non-blocking environment. NB:
	 *	"ZERO_RETURN" is the clean "error"
	 *	indicating a successfully closed SSL
	 *	tunnel. We let this happen because our IO
	 *	loop should not appear to have broken on
	 *	this condition - and outside the IO loop, the
	 *	"shutdown" state is checked.
	 *
	 *	Don't print anything if we ignore the error.
	 */
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_X509_LOOKUP:
	case SSL_ERROR_ZERO_RETURN:
		break;

	/*
	 *	These seem to be indications of a genuine
	 *	error that should result in the SSL tunnel
	 *	being regarded as "dead".
	 */
	case SSL_ERROR_SYSCALL:
		ROPTIONAL(REDEBUG, ERROR, "System call (I/O) error (%i)", ret);
		return 0;

	case SSL_ERROR_SSL:
		ROPTIONAL(REDEBUG, ERROR, "TLS protocol error (%i)", ret);
		return 0;

	/*
	 *	For any other errors that (a) exist, and (b)
	 *	crop up - we need to interpret what to do with
	 *	them - so "politely inform" the caller that
	 *	the code needs updating here.
	 */
	default:
		ROPTIONAL(REDEBUG, ERROR, "TLS session error %i (%i)", error, ret);
		return 0;
	}

	return 1;
}
#endif /* WITH_TLS */
