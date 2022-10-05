#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifdef WITH_TLS
/**
 * $Id$
 *
 * @file lib/tls/strerror.h
 * @brief Prototypes for TLS strerror
 *
 * @copyright 2022 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tls_strerror_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/x509.h>
#include <stdint.h>

#include "base.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Push a representation of a certificate chain onto the thread local error stack
 *
 * @param[in] _chain	A stack of X509 certificates representing the chain.
 * @param[in] _leaf	The leaf certificate.  May be NULL.
 * @param[in] _marker	The certificate to emit a marker for.
 */
#define		fr_tls_strerror_push_chain(_chain, _leaf) \
			_fr_tls_strerror_push_chain( __FILE__, __LINE__, _chain, _leaf)
void		_fr_tls_strerror_push_chain(char const *file, int line, STACK_OF(X509) *chain, X509 *cert);

/** Push a representation of a certificate chain with a marker onto the thread local error stack
 *
 * @param[in] _chain	A stack of X509 certificates representing the chain.
 * @param[in] _leaf	The leaf certificate.  May be NULL.
 * @param[in] _marker	The certificate to emit a marker for.
 */
#define		fr_tls_strerror_push_chain_marker(_chain, _leaf, _marker) \
			_fr_tls_strerror_push_chain( __FILE__, __LINE__, _chain, _leaf, _marker)
void		_fr_tls_strerror_push_chain_marker(char const *file, int line,
					  STACK_OF(X509) *chain, X509 *cert, X509 *marker);

/** Push a collection of X509 objects into the thread local error stack
 *
 * @param[in] _objects	to push onto the thread local error stack
 */
#define		fr_tls_strerror_push_x509_objects(_objects) \
			_fr_tls_strerror_push_x509_objects( __FILE__, __LINE__,  _objects)
void		_fr_tls_strerror_push_x509_objects(char const *file, int line,
					  STACK_OF(X509_OBJECT) *objects);

#define		fr_tls_strerror_vprintf(_msg, _ap) \
			_fr_tls_strerror_vprintf(__FILE__, __LINE__, _msg, _ap)
int		_fr_tls_strerror_vprintf(char const *file, int line, char const *msg, va_list ap);

/** Wrapper around fr_strerror_printf to log error messages for library functions calling libssl
 *
 * @note Will only drain the first error.
 *
 * @param[in] msg	Error message describing the operation being attempted.
 * @param[in] ...	Arguments for msg.
 * @return the number of errors drained from the stack.
 */
#define		fr_tls_strerror_printf(_msg, ...) \
			_fr_tls_strerror_printf(__FILE__, __LINE__, _msg, ##__VA_ARGS__)

static inline CC_HINT(format (printf, 3, 4))
int		_fr_tls_strerror_printf(char const *file, int line, char const *msg, ...)
{
	va_list ap;
	int ret;

	va_start(ap, msg);
	ret = _fr_tls_strerror_vprintf(file, line, msg, ap);
	va_end(ap);

	return ret;
}
#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
