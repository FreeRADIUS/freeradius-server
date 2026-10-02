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

/** Print the OpenSSL error stack, under a message of our own
 *
 * For a failure which an OpenSSL call reported.  The stack holds why, and
 * this drains it, so use it whenever an OpenSSL call has just returned an
 * error.  Draining also keeps a stale entry from surfacing under some later,
 * unrelated message.
 *
 * Use fr_tls_log_error() instead for a failure the server found for itself,
 * where the stack holds nothing to drain.
 */
int		fr_tls_log_perror(request_t *request, char const *msg, ...)  CC_HINT(format (printf, 2, 3));

/** Print the OpenSSL error stack, for a call unrelated to any TLS connection
 *
 * The same as fr_tls_log_perror(), without the `(TLS) ` prefix.  Use it
 * wherever OpenSSL is called for something which is not a TLS connection:
 * signing a value, hashing a password, reading a key from disk.  Calling
 * those TLS would send a reader looking for a connection which is not there.
 *
 * RPERROR_SSL() is how a module reaches this.
 */
int		fr_openssl_log_perror(request_t *request, char const *msg, ...)  CC_HINT(format (printf, 2, 3));

/** Print the OpenSSL error stack for the current request
 *
 * For a module which called an OpenSSL function unrelated to any TLS
 * connection.  Takes `request` from the enclosing scope, as every R* macro
 * does, and a NULL `request` logs globally.
 *
 * @param[in] _fmt	printf style format string.
 * @param[in] ...	printf arguments.
 */
#define		RPERROR_SSL(_fmt, ...) fr_openssl_log_perror(request, _fmt, ## __VA_ARGS__)

/** Log an error which the server found for itself
 *
 * For a check the server made, rather than something an OpenSSL call
 * reported: a configuration which cannot work, a policy section which could
 * not be pushed, a peer which offered the wrong thing.  The OpenSSL error
 * stack holds nothing for these, so there is nothing to drain, and
 * fr_tls_log_perror() would print an empty line where the reason should be.
 *
 * Every message carries a `(TLS) ` prefix.  LOG_PREFIX supplies `tls - ` only
 * when there is no request, so without this prefix the messages which matter
 * most, the ones attached to a request, are the ones with nothing to say
 * where they came from.
 *
 * Needs a `request` in scope, as every R* macro does.  A NULL `request` logs
 * globally.
 *
 * @param[in] _fmt	printf style format string.
 * @param[in] ...	printf arguments.
 */
#define		fr_tls_log_error(_fmt, ...) ROPTIONAL(RERROR, ERROR, "(TLS) " _fmt, ## __VA_ARGS__)

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
