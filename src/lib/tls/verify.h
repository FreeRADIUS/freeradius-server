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
 * @file lib/tls/validate.h
 * @brief Structures for session-resumption management.
 *
 * @copyright 2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(validate_h, "$Id$")

#include "openssl_user_macros.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Certificate validation states
 *
 */
typedef enum {
	FR_TLS_VALIDATION_INIT = 0,			//!< OpenSSL hasn't requested certificate validation.
	FR_TLS_VALIDATION_REQUESTED,			//!< OpenSSL requested validation.
	FR_TLS_VALIDATION_SUCCESS,			//!< Certificate chain was validate.
	FR_TLS_VALIDATION_FAILED			//!< Certificate validation failed.
} fr_tls_validation_state_t;

typedef enum {
	FR_TLS_VERIFY_MODE_DISABLED = 0,		//!< Don't convert any pairs for verification.
	FR_TLS_VERIFY_MODE_LEAF = 0x01,			//!< Convert the client certificate.
	FR_TLS_VERIFY_MODE_ISSUER = 0x02,		//!< Convert the issuer of the client certificate.
	FR_TLS_VERIFY_MODE_UNTRUSTED = 0x04,		//!< Convert any "untrusted" certificates.
	FR_TLS_VERIFY_MODE_ALL =			//!< Convert the entire certificate chain.
		FR_TLS_VERIFY_MODE_LEAF |
		FR_TLS_VERIFY_MODE_ISSUER |
		FR_TLS_VERIFY_MODE_UNTRUSTED
} fr_tls_verify_mode_t;

/** Certificate validation state
 *
 */
typedef struct {
	rlm_rcode_t			rcode;
	fr_tls_validation_state_t	state;		//!< Whether OpenSSL has requested
							///< certificate validation.

	bool				resumed;	//!< Whether we're validating a resumed session.
} fr_tls_verify_t;

#ifdef __cplusplus
}
#endif

#include "session.h"

#ifdef __cplusplus
extern "C" {
#endif

int		fr_tls_verify_cert_cb(int ok, X509_STORE_CTX *ctx);

int		fr_tls_verify_cert_chain(request_t *request, SSL *ssl);

bool		fr_tls_verify_cert_result(fr_tls_session_t *tls_session);

void		fr_tls_verify_cert_reset(fr_tls_session_t *tls_session);

void		fr_tls_verify_cert_request(fr_tls_session_t *tls_session, bool resumed);

unlang_action_t fr_tls_verify_cert_pending_push(request_t *request, fr_tls_session_t *tls_session);

#ifdef __cplusplus
}
#endif
#endif /* WITH_TLS */
