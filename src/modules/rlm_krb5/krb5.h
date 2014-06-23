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
 * @file krb5.h
 * @brief types and function signatures for rlm_krb5.
 *
 * @copyright 2013  The FreeRADIUS server project
 * @copyright 2013  Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */
RCSIDH(krb5_h, "$Id$")

#if defined(KRB5_IS_THREAD_SAFE) && !defined(HAVE_PTHREAD_H)
#  undef KRB5_IS_THREAD_SAFE
#endif

/* krb5 includes */
USES_APPLE_DEPRECATED_API
#include <krb5.h>

typedef struct rlm_krb5_handle {
	krb5_context	context;
	krb5_keytab	keytab;

#ifdef HEIMDAL_KRB5
	krb5_ccache	ccache;
	krb5_verify_opt options;
#endif
} rlm_krb5_handle_t;

/** Instance configuration for rlm_krb5
 *
 * Holds the configuration and preparsed data for a instance of rlm_krb5.
 */
typedef struct rlm_krb5_t {
#ifdef KRB5_IS_THREAD_SAFE
	fr_connection_pool_t	*pool;		//!< Connection pool instance.
#else
	rlm_krb5_handle_t	*conn;
#endif

	char const		*xlat_name;	//!< This module's instance name.
	char const		*keytabname;	//!< The keytab to resolve the service in.
	char const		*service_princ;	//!< The service name provided by the
						//!< config parser.

	char			*hostname;	//!< The hostname component of
						//!< service_princ, or NULL.
	char			*service;	//!< The service component of service_princ, or NULL.

	krb5_context context;			//!< The kerberos context (cloned once per request).

#ifndef HEIMDAL_KRB5
	krb5_get_init_creds_opt		*gic_options;	//!< Options to pass to the get_initial_credentials
							//!< function.
	krb5_verify_init_creds_opt	*vic_options;	//!< Options to pass to the validate_initial_creds
							//!< function.

	krb5_principal server;			//!< A structure representing the parsed
						//!< service_princ.
#endif
} rlm_krb5_t;

/*
 *	MIT Kerberos uses comm_err, so the macro just expands to a call
 *	to error_message.
 */
#ifndef HAVE_KRB5_GET_ERROR_MESSAGE
#  ifdef ET_COMM_ERR
#    include <et/com_err.h>
#  else
#    include <com_err.h>
#  endif
#  define rlm_krb5_error(_x, _y) error_message(_y)
#else
char const *rlm_krb5_error(krb5_context context, krb5_error_code code);
#endif

void *mod_conn_create(TALLOC_CTX *ctx, void *instance);
