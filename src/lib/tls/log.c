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
 * @copyright 2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 * @copyright 2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/rad_assert.h>

#include "base.h"
#include "missing.h"

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
static int fr_tls_log_error_va(REQUEST *request, char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p;
	int		in_stack = 0;
	char		buffer[256];

	int		line;
	char const	*file;
	char const	*data;
	int		flags = 0;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_line_data(&file, &line, &data, &flags);
	if (!(flags & ERR_TXT_STRING)) data = NULL;

	if (msg) {
		p = talloc_vasprintf(request, msg, ap);

		/*
		 *	Single line mode (there's only one error)
		 */
		if (error && !ERR_peek_error()) {
			ERR_error_string_n(error, buffer, sizeof(buffer));

			/* Extra verbose */
			if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
				ROPTIONAL(REDEBUG, ERROR, "%s: %s[%i]:%s%c%s", p, file, line, buffer,
					  data ? ':' : '\0', data ? data : "");
			} else {
				ROPTIONAL(REDEBUG, ERROR, "%s: %s%c%s", p, buffer,
					  data ? ':' : '\0', data ? data : "");
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
		if (!(flags & ERR_TXT_STRING)) data = NULL;

		ERR_error_string_n(error, buffer, sizeof(buffer));
		/* Extra verbose */
		if ((request && RDEBUG_ENABLED3) || DEBUG_ENABLED3) {
			ROPTIONAL(REDEBUG, ERROR, "%s[%i]:%s%c%s", file, line, buffer,
				  data ? ':' : '\0', data ? data : "");
		} else {
			ROPTIONAL(REDEBUG, ERROR, "%s%c%s", buffer,
				  data ? ':' : '\0', data ? data : "");
		}
		in_stack++;
	} while ((error = ERR_get_error_line_data(&file, &line, &data, &flags)));

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
int fr_tls_log_error(REQUEST *request, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = fr_tls_log_error_va(request, msg, ap);
	va_end(ap);

	return ret;
}

/** Clear errors in the TLS thread local error stack
 *
 */
void tls_log_clear(void)
{
	while (ERR_get_error() != 0);
}

DIAG_OFF(format-nonliteral)
/** Print errors in the TLS thread local error stack
 *
 * Drains the thread local OpenSSL error queue, and prints out the first error
 * storing it in libfreeradius's error buffer.
 *
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ap	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
static int tls_strerror_vasprintf(char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p = NULL;
	int		drained = 0;
	char		buffer[256];

	int		line;
	char const	*file;
	char const	*data;
	int		flags = 0;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_line_data(&file, &line, &data, &flags);
	if (!(flags & ERR_TXT_STRING)) data = NULL;

	if (msg) {
		/*
		 *	Print the error we were passed, and
		 *	OpenSSL's error.
		 */
		p = talloc_vasprintf(NULL, msg, ap);
		if (error) {
			ERR_error_string_n(error, buffer, sizeof(buffer));
			fr_strerror_printf("%s: %s%c%s", p, buffer, data ? ':' : '\0', data ? data : "");
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
		fr_strerror_printf("%s%c%s", buffer, data ? ':' : '\0', data ? data : "");
		drained++;
	} else {
		return 0;
	}

	while ((error = ERR_get_error_line_data(&file, &line, &data, &flags))) {
		if (!(flags & ERR_TXT_STRING)) data = NULL;

		ERR_error_string_n(error, buffer, sizeof(buffer));
		fr_strerror_printf_push("%s%c%s", buffer, data ? ':' : '\0', data ? data : "");
		drained++;
	}

	return drained;
}
DIAG_ON(format-nonliteral)

/** Wrapper around fr_strerror_printf to log error messages for library functions calling libssl
 *
 * @note Will only drain the first error.
 *
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
int tls_strerror_printf(char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = tls_strerror_vasprintf(msg, ap);
	va_end(ap);

	return ret;
}

static void _tls_ctx_print_cert_line(char const *file, int line,
				     REQUEST *request, int index, X509 *cert)
{
	char		subject[1024];

	X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	if (request) {
		log_request(L_DBG, fr_debug_lvl, request, file, line,
			    "[%i] %s %s", index, fr_tls_utils_x509_pkey_type(cert), subject);
	} else {
		fr_log(LOG_DST, fr_debug_lvl, file, line,
		       "[%i] %s %s", index, fr_tls_utils_x509_pkey_type(cert), subject);
	}
}

/** Print out the current stack of certs
 *
 * @param[in] file	File where this function is being called.
 * @param[in] line	Line where this function is being called.
 * @param[in] request	Current request, may be NULL.
 * @param[in] chain	The certificate chain.
 * @param[in] cert	The leaf certificate.
 */
void _fr_tls_log_certificate_chain(char const *file, int line,
				REQUEST *request, STACK_OF(X509) *chain, X509 *cert)
{
	int i;

	for (i = sk_X509_num(chain); i > 0 ; i--) {
		_tls_ctx_print_cert_line(file, line, request, i, sk_X509_value(chain, i - 1));
	}
	_tls_ctx_print_cert_line(file, line, request, i, cert);
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
 *	- 0 TLS session may still be viable.
 *	- -1 TLS session cannot continue.
 */
int fr_tls_log_io_error(REQUEST *request, fr_tls_session_t *session, int ret, char const *msg, ...)
{
	int	error;
	va_list	ap;

	if (ERR_peek_error()) {
		va_start(ap, msg);
		fr_tls_log_error_va(request, msg, ap);
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
		return -1;

	case SSL_ERROR_SSL:
		ROPTIONAL(REDEBUG, ERROR, "TLS protocol error (%i)", ret);
		return -1;

	/*
	 *	For any other errors that (a) exist, and (b)
	 *	crop up - we need to interpret what to do with
	 *	them - so "politely inform" the caller that
	 *	the code needs updating here.
	 */
	default:
		ROPTIONAL(REDEBUG, ERROR, "TLS session error %i (%i)", error, ret);
		return -1;
	}

	return 0;
}
#endif /* WITH_TLS */
