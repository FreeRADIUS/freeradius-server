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
 * @file lib/tls/log.h
 * @brief Prototypes for TLS logging functions
 *
 * @copyright 2017 The FreeRADIUS project
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(tls_log_h, "$Id$")

#include "openssl_user_macros.h"

#include <stdbool.h>
#include <stdint.h>

#include <freeradius-devel/server/request.h>
#include <openssl/bio.h>

#include "base.h"

/** Write out a certificate chain to the request or global log
 *
 * @param[in] _request	The current request or NULL if you want to write to the global log.
 * @param[in] _log_type	Type of log message to create.
 * @param[in] _chain	A stack of X509 certificates representing the chain.
 * @param[in] _leaf	The leaf certificate.  May be NULL.
 */
#define		fr_tls_chain_log(_request, _log_type, _chain, _leaf) \
			_fr_tls_chain_log( __FILE__, __LINE__, _request, _log_type, _chain, _leaf)
void		_fr_tls_chain_log(char const *file, int line,
				  request_t *request, fr_log_type_t log_type, STACK_OF(X509) *chain, X509 *leaf);

/** Write out a certificate chain with a marker to the request or global log
 *
 * @param[in] _request	The current request or NULL if you want to write to the global log.
 * @param[in] _log_type	Type of log message to create.
 * @param[in] _chain	A stack of X509 certificates representing the chain.
 * @param[in] _leaf	The leaf certificate.  May be NULL.
 * @param[in] _marker	Emit a marker for this certificate.
 */
#define		fr_tls_chain_marker_log(_request, _log_type, _chain, _leaf, _marker) \
			_fr_tls_chain_marker_log( __FILE__, __LINE__, _request, _log_type, _chain, _leaf, _marker)
void		_fr_tls_chain_marker_log(char const *file, int line,
					 request_t *request, fr_log_type_t log_type, STACK_OF(X509) *chain, X509 *leaf,
					 X509 *marker);

/** Write out a collection of X509 objects to the request or global log
 *
 * @param[in] _request	The current request or NULL if you want to write to the global log.
 * @param[in] _log_type	Type of log message to create.
 * @param[in] _objects	to print to the log
 */
#define		fr_tls_x509_objects_log(_request, _log_type, _objects) \
			_fr_tls_x509_objects_log( __FILE__, __LINE__, _request, _log_type, _objects)
void		_fr_tls_x509_objects_log(char const *file, int line,
					 request_t *request, fr_log_type_t log_type,
					 STACK_OF(X509_OBJECT) *objects);

int		fr_tls_log_io_error(request_t *request, int err, char const *msg, ...)
				    CC_HINT(format (printf, 3, 4));

int		fr_tls_log(request_t *request, char const *msg, ...)  CC_HINT(format (printf, 2, 3));

void		fr_tls_log_clear(void);

/** Return a BIO that writes to the log of the specified request
 *
 * @note BIO should be considered invalid if the request yields
 *
 * @param[in] _request	to associate with the logging BIO.
 * @param[in] _type	of log messages.
 * @param[in] _lvl	to print log messages at.
 * @return A BIO.
 */
#define		fr_tls_request_log_bio(_request, _type, _lvl) \
			_fr_tls_request_log_bio(__FILE__, __LINE__, _request, _type, _lvl)
BIO		*_fr_tls_request_log_bio(char const *file, int line, request_t *request,
					 fr_log_type_t type, fr_log_lvl_t lvl) CC_HINT(nonnull);

/** Return a BIO that writes to the global log
 *
 * @note BIO should be considered invalid if the request yields
 *
 * @param[in] _type	of log messages.
 * @param[in] _lvl	to print log messages at.
 * @return A BIO.
 */
#define		fr_tls_global_log_bio(_type, _lvl) \
			_fr_tls_global_log_bio(__FILE__, __LINE__, _type, _lvl)
BIO		*_fr_tls_global_log_bio(char const *file, int line, fr_log_type_t type, fr_log_lvl_t lvl);

int		fr_tls_log_init(void);	/* Called from fr_openssl_init() */

void		fr_tls_log_free(void);	/* Called from fr_openssl_init() */
#endif
