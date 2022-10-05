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
 * @file tls/strerror.c
 * @brief Convert the contents of OpenSSL's error stack to our thread local error stack
 *
 * @copyright 2022 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#define LOG_PREFIX "tls"

#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>
#include <stdatomic.h>

#include "strerror.h"
#include "utils.h"

#if OPENSSL_VERSION_NUMBER < 0x30000000L
static inline unsigned long ERR_get_error_all(const char **file, int *line,
					      const char **func,
					      const char **data, int *flags)
{
	if (func != NULL) *func = "";

	return ERR_get_error_line_data(file, line, data, flags);
}
#endif

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* fix spurious warnings for sk macros */
static void _tls_cert_line_push(char const *file, int line, int idx, X509 *cert)
{
	char		subject[1024];

	X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	_fr_strerror_printf_push(file, line, "[%i] %s %s", idx, fr_tls_utils_x509_pkey_type(cert), subject);
}

static void _tls_cert_line_marker_push(char const *file, int line,
				       int idx, X509 *cert, bool marker)
{
	char		subject[1024];

	X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	_fr_strerror_printf_push(file, line, "%s [%i] %s %s", marker ? ">" : " ",
				 idx, fr_tls_utils_x509_pkey_type(cert), subject);
}

static void _tls_cert_line_marker_no_idx_push(char const *file, int line, X509 *cert)
{
	char		subject[1024];

	X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	_fr_strerror_printf_push(file, line, "%s %s", fr_tls_utils_x509_pkey_type(cert), subject);
}

/** Print out the current stack of certs to the thread local error buffer
 *
 * @param[in] file	File where this function is being called.
 * @param[in] line	Line where this function is being called.
 * @param[in] chain	The certificate chain.
 * @param[in] cert	The leaf certificate.
 */
void _fr_tls_strerror_push_chain(char const *file, int line, STACK_OF(X509) *chain, X509 *cert)
{
	int i;

	for (i = sk_X509_num(chain); i > 0 ; i--) {
		_tls_cert_line_push(file, line, i, sk_X509_value(chain, i - 1));
	}
	if (cert) _tls_cert_line_push(file, line, i, cert);
}

/** Print out the current stack of certs to the thread local error buffer
 *
 * @param[in] file	File where this function is being called.
 * @param[in] line	Line where this function is being called.
 * @param[in] chain	The certificate chain.
 * @param[in] cert	The leaf certificate.
 * @param[in] marker	The certificate we want to mark.
 */
void _fr_tls_strerror_push_chain_marker(char const *file, int line,
			       STACK_OF(X509) *chain, X509 *cert, X509 *marker)
{
	int i;

	for (i = sk_X509_num(chain); i > 0 ; i--) {
		X509 *selected = sk_X509_value(chain, i - 1);
		_tls_cert_line_marker_push(file, line, i, selected, (selected == marker));
	}
	if (cert) _tls_cert_line_marker_push(file, line, i, cert, (cert == marker));
}

/** Print out the current stack of X509 objects (certificates only)
 *
 * @param[in] file		File where this function is being called.
 * @param[in] line		Line where this function is being called.
 * @param[in] objects		A stack of X509 objects
 */
void _fr_tls_strerror_push_x509_objects(char const *file, int line, STACK_OF(X509_OBJECT) *objects)
{
	int i;

	for (i = sk_X509_OBJECT_num(objects); i > 0 ; i--) {
		X509_OBJECT *obj = sk_X509_OBJECT_value(objects, i - 1);

		switch (X509_OBJECT_get_type(obj)) {
		case X509_LU_X509:	/* X509 certificate */
			/*
			 *	Dump to the thread local buffer
			 */
			_tls_cert_line_marker_no_idx_push(file, line, X509_OBJECT_get0_X509(obj));
			break;

		case X509_LU_CRL:	/* Certificate revocation list */
			continue;

		default:
			continue;
		}
	}
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
int _fr_tls_strerror_vprintf(char const *file, int line, char const *msg, va_list ap)
{
	unsigned long	error;
	char		*p = NULL;
	int		drained = 0;
	char		buffer[256];

	int		openssl_line;
	char const	*openssl_file;
	char const	*func;
	char const	*data;
	int		flags = 0;

	/*
	 *	Pop the first error, so ERR_peek_error()
	 *	can be used to determine if there are
	 *	multiple errors.
	 */
	error = ERR_get_error_all(&openssl_file, &openssl_line, &func, &data, &flags);
	if (!(flags & ERR_TXT_STRING)) data = NULL;

	if (msg) {
		/*
		 *	Print the error we were passed, and
		 *	OpenSSL's error.
		 */
		if (error) {
			p = talloc_vasprintf(NULL, msg, ap);
			ERR_error_string_n(error, buffer, sizeof(buffer));
			_fr_strerror_printf(openssl_file, openssl_line,
					    "%s: %s%c%s", p, buffer, data ? ':' : '\0', data ? data : "");
			talloc_free(p);
			drained++;
		/*
		 *	Print the error we were given, irrespective
		 *	of whether there were any OpenSSL errors.
		 */
		} else {
			va_list	our_ap;

			va_copy(our_ap, ap);
			_fr_strerror_vprintf(file, line, msg, our_ap);
			va_end(our_ap);
		}
	} else if (error) {
		ERR_error_string_n(error, buffer, sizeof(buffer));
		_fr_strerror_printf(openssl_file, openssl_line, "%s%c%s", buffer, data ? ':' : '\0', data ? data : "");
		drained++;
	} else {
		return 0;
	}

	while ((error = ERR_get_error_all(&openssl_file, &openssl_line, &func, &data, &flags))) {
		if (!(flags & ERR_TXT_STRING)) data = NULL;

		ERR_error_string_n(error, buffer, sizeof(buffer));

		_fr_strerror_printf_push(openssl_file, openssl_line, "%s%c%s", buffer, data ? ':' : '\0', data ? data : "");
		drained++;
	}

	return drained;
}
DIAG_ON(format-nonliteral)
#endif /* WITH_TLS */
