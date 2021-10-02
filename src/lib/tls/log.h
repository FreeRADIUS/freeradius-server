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

#include <stdbool.h>
#include <stdint.h>

#include <freeradius-devel/server/request.h>
#include <openssl/bio.h>

#include "base.h"

#define		fr_tls_log_certificate_chain(_request, _log_type, _chain, _cert) \
			_fr_tls_log_certificate_chain( __FILE__, __LINE__, _request, _log_type, _chain, _cert)
void		_fr_tls_log_certificate_chain(char const *file, int line,
					      request_t *request, fr_log_type_t log_type, STACK_OF(X509) *chain, X509 *cert);

int		fr_tls_log_io_error(request_t *request, int err, char const *msg, ...)
				    CC_HINT(format (printf, 3, 4));

int		fr_tls_log_error(request_t *request, char const *msg, ...) CC_HINT(format (printf, 2, 3));

int		fr_tls_log_strerror_printf(char const *msg, ...) CC_HINT(format (printf, 1, 2));

void		tls_log_clear(void);

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
