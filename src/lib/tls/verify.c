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
 * @file tls/validate.c
 * @brief Expose certificate OIDs as attributes, and call validation virtual
 *	server to check cert is valid.
 *
 * @copyright 2001 hereUare Communications, Inc. (raghud@hereuare.com)
 * @copyright 2003 Alan DeKok (aland@freeradius.org)
 * @copyright 2006-2016 The FreeRADIUS server project
 */
#ifdef WITH_TLS
#define LOG_PREFIX "tls - "

#include <freeradius-devel/server/exec.h>
#include <freeradius-devel/server/pair.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/subrequest.h>
#include <freeradius-devel/util/debug.h>
#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#include "attrs.h"
#include "base.h"

/** Check to see if a verification operation should apply to a certificate
 *
 * @param[in] depth	starting at 0.
 *			Certificate 0 is the leaf cert (i.e. the client or server cert);
 * @param[in] untrusted	The number of untrusted certificates.
 * @param[in] mode	to check
 * @return
 *	- true if a given validation check should apply.
 **     - false if a validation check should not apply.
 */
static inline CC_HINT(always_inline)
bool verify_applies(fr_tls_verify_mode_t mode, int depth, int untrusted)
{
	if (mode == FR_TLS_VERIFY_MODE_ALL) return true;
	if (mode == FR_TLS_VERIFY_MODE_DISABLED) return false;

	if ((mode & FR_TLS_VERIFY_MODE_LEAF) && (depth == 0)) return true;
	if ((mode & FR_TLS_VERIFY_MODE_ISSUER) && (depth == 1)) return true;
	if ((mode & FR_TLS_VERIFY_MODE_UNTRUSTED) && (depth < untrusted)) return true;

	return false;
}

DIAG_OFF(DIAG_UNKNOWN_PRAGMAS)
DIAG_OFF(used-but-marked-unused)	/* fix spurious warnings for sk macros */
/** Validates a certificate using custom logic
 *
 * Before trusting a certificate, we make sure that the certificate is
 * 'valid'. There are several checks we perform to verify its validity.
 *
 *   1. Verify the certificate's signature, and verifying that the certificate has
 *      been issued by a trusted Certificate Authority (this is done for us by OpenSSL).
 *
 *   2. Verify that the certificate is valid for the present date (i.e. it is being
 *      presented within its validity dates).
 *
 *   3. Verify that the certificate has not been revoked by its issuing Certificate
 *      Authority, by checking with respect to a Certificate Revocation List (CRL).
 *
 * @note This callback will be called multiple times based on the depth of the root
 *	certificate chain.
 *
 * @note As a byproduct of validation, various OIDs will be extracted from the
 *	certificates, and inserted into the session-state: list as fr_pair_t.
 *
 * @param ok		preverify ok.  1 if true, 0 if false.
 * @param x509_ctx	containing certs to verify.
 * @return
 *	- 0 if not valid.
 *	- 1 if valid.
 */
int fr_tls_verify_cert_cb(int ok, X509_STORE_CTX *x509_ctx)
{
	X509			*cert;
	SSL			*ssl;
	fr_tls_session_t	*tls_session;
	int			err, depth;
	fr_tls_conf_t		*conf;
	int			my_ok = ok;
	int			untrusted;

	request_t		*request;
	fr_pair_t		*container = NULL;

	cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	err = X509_STORE_CTX_get_error(x509_ctx);
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);
	untrusted = X509_STORE_CTX_get_num_untrusted(x509_ctx);

	/*
	 *	Retrieve the pointer to the SSL of the connection currently treated
	 *	and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = fr_tls_session_conf(ssl);
	tls_session = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
	request = fr_tls_session_request(tls_session->ssl);

	if (RDEBUG_ENABLED3) {
		char		subject[2048];
		STACK_OF(X509)	*our_chain = X509_STORE_CTX_get_chain(x509_ctx);
		int		i;

		RDEBUG3("Certificate chain - %i cert(s) untrusted", untrusted);
		for (i = sk_X509_num(our_chain); i > 0 ; i--) {
			X509 *this_cert = sk_X509_value(our_chain, i - 1);

			X509_NAME_oneline(X509_get_subject_name(this_cert), subject, sizeof(subject));
			subject[sizeof(subject) - 1] = '\0';

			RDEBUG3("%s [%i] %s", this_cert == cert ? ">" : " ", i - 1, subject);
		}
	}

	/*
	 *	See if the user has disabled verification for
	 *      this certificate.  If they have, force verification
	 *	to succeed.
	 */
	if (!my_ok) {
		char const *p = X509_verify_cert_error_string(err);
		if (!verify_applies(conf->verify.mode, depth, untrusted) ||
		    ((conf->verify.allow_expired_crl) && (err == X509_V_ERR_CRL_HAS_EXPIRED))) {
			RDEBUG2("Ignoring verification error - %s (%i)", p, err);
			my_ok = 1;
			X509_STORE_CTX_set_error(x509_ctx, 0);
		} else {
			RERROR("Verification error - %s (%i)", p, err);
			goto done;
		}
	}

	if (verify_applies(conf->verify.pair_mode, depth, untrusted) &&
	    (!(container = fr_pair_find_by_da(&request->session_state_pairs, attr_tls_cert, depth)) ||
	     fr_pair_list_empty(&container->vp_group))) {
	     	if (!container) {
	    	     	unsigned int i;

			/*
			 *	Build a stack of container attributes.
			 *
			 *	OpenSSL passes us the deepest certificate
			 *      first, so we need to build out sufficient
			 *      TLS-Cert container TLVs so the TLS-Cert
			 *	indexes match the attribute depth.
			 */
			for (i = fr_pair_count_by_da(&request->session_state_pairs, attr_tls_cert);
			     i <= (unsigned int)depth;
			     i++) {
				MEM(container = fr_pair_afrom_da(request->session_state_ctx, attr_tls_cert));
				fr_pair_append(&request->session_state_pairs, container);
			}
	     	}

#ifdef __clang_analyzer__
		/*
		 *	Container can never be NULL, because if container
		 *	was previously NULL, i will be <= depth.
		 */
		if (!fr_cond_assert(container)) {
			my_ok = 0;
			goto done;
		}
#endif
		/*
		 *	If we fail to populate the cert attributes,
		 *	trash all instances in the session-state list
		 *	and cause validation to fail.
		 */
		if (fr_tls_session_pairs_from_x509_cert(&container->vp_group, container,
							request, cert) < 0) {
			fr_pair_delete_by_da(&request->session_state_pairs, attr_tls_cert);
			my_ok = 0;
			goto done;
		}

		log_request_pair(L_DBG_LVL_2, request, NULL, container, "&session-state.");
	}
done:
	/*
	 *	This is a client cert
	 */
	if (depth == 0) tls_session->client_cert_ok = (my_ok > 0);

	RDEBUG2("[verify] = %s", my_ok ? "ok" : "invalid");

	return my_ok;
}
DIAG_ON(used-but-marked-unused)
DIAG_ON(DIAG_UNKNOWN_PRAGMAS)

/** Revalidates the client's certificate chain
 *
 * Wraps the fr_tls_verify_cert_cb callback, allowing us to use the same
 * validation logic whenever we need to.
 *
 * @note Only use so far is forcing the chain to be re-validated on session
 *	resumption.
 *
 * @return
 *	- 1 if the chain could be validated.
 *	- 0 if the chain failed validation.
 */
int fr_tls_verify_client_cert_chain(SSL *ssl)
{
	int		err;
	int		verify;
	int		ret = 1;

	STACK_OF(X509)	*chain;
	X509		*cert;
	X509_STORE	*store;
	X509_STORE_CTX	*store_ctx;

	request_t	*request = fr_tls_session_request(ssl);

	/*
	 *	If there's no client certificate, we just return OK.
	 */
	cert = SSL_get_peer_certificate(ssl);			/* Increases ref count */
	if (!cert) return 1;

	store_ctx = X509_STORE_CTX_new();
	chain = SSL_get_peer_cert_chain(ssl);			/* Does not increase ref count */
	store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));	/* Does not increase ref count */

	X509_STORE_CTX_init(store_ctx, store, cert, chain);
	X509_STORE_CTX_set_ex_data(store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), ssl);
	X509_STORE_CTX_set_verify_cb(store_ctx, fr_tls_verify_cert_cb);

	verify = X509_verify_cert(store_ctx);
	if (verify != 1) {
		err = X509_STORE_CTX_get_error(store_ctx);

		if (err != X509_V_OK) {
			REDEBUG("Failed re-validating resumed session: %s", X509_verify_cert_error_string(err));
			ret = 0;
		}
	}

	X509_free(cert);
	X509_STORE_CTX_free(store_ctx);

	return ret;
}

/** Process the result of `verify certificate { ... }`
 *
 */
static unlang_action_t tls_verify_client_cert_result(UNUSED rlm_rcode_t *p_result, UNUSED int *priority,
						     request_t *request, void *uctx)
{
	fr_tls_session_t	*tls_session = talloc_get_type_abort(uctx, fr_tls_session_t);
	fr_pair_t		*vp;

	fr_assert(tls_session->validate.state == FR_TLS_VALIDATION_REQUESTED);

	vp = fr_pair_find_by_da(&request->reply_pairs, attr_tls_packet_type, 0);
	if (!vp || (vp->vp_uint32 != enum_tls_packet_type_success->vb_uint32)) {
		REDEBUG("Failed (re-)validating certificates");
		tls_session->validate.state = FR_TLS_VALIDATION_FAILED;
		return UNLANG_ACTION_CALCULATE_RESULT;
	}

	tls_session->validate.state = FR_TLS_VALIDATION_SUCCESS;

	RDEBUG2("Certificates (re-)validated");

	return UNLANG_ACTION_CALCULATE_RESULT;
}

/** Push a `verify certificate { ... }` call into the current request, using a subrequest
 *
 * @param[in] request		The current request.
 * @Param[in] tls_session	The current TLS session.
 * @return
 *      - UNLANG_ACTION_CALCULATE_RESULT on noop.
 *	- UNLANG_ACTION_PUSHED_CHILD on success.
 *      - UNLANG_ACTION_FAIL on failure.
 */
static unlang_action_t tls_verify_client_cert_push(request_t *request, fr_tls_session_t *tls_session)
{
	fr_tls_conf_t		*conf = fr_tls_session_conf(tls_session->ssl);
	request_t		*child;
	fr_pair_t		*vp;
	unlang_action_t		ua;

	MEM(child = unlang_subrequest_alloc(request, dict_tls));
	request = child;

	/*
	 *	Add extra pairs to the subrequest
	 */
	fr_tls_session_extra_pairs_copy_to_child(child, tls_session);

	/*
	 *	Setup the child request for loading
	 *	session resumption data.
	 */
	MEM(pair_prepend_request(&vp, attr_tls_packet_type) >= 0);
	vp->vp_uint32 = enum_tls_packet_type_certificate_validate->vb_uint32;

	/*
	 *	Allocate a child, and set it up to call
	 *      the TLS virtual server.
	 */
	ua = fr_tls_call_push(child, tls_verify_client_cert_result, conf, tls_session);
	if (ua < 0) {
	        PERROR("Failed calling TLS virtual server");
		talloc_free(child);
		return UNLANG_ACTION_FAIL;
	}

	return ua;
}

/** Check we validated the client cert successfully
 *
 */
bool fr_tls_verify_client_cert_successful(fr_tls_session_t *tls_session)
{
	return tls_session->validate.state == FR_TLS_VALIDATION_SUCCESS;
}

/** Setup a validation request
 *
 */
void fr_tls_verify_client_cert_request(fr_tls_session_t *tls_session)
{
	fr_assert(tls_session->validate.state == FR_TLS_VALIDATION_INIT);

	tls_session->validate.state = FR_TLS_VALIDATION_REQUESTED;
}

/** Push a `verify certificate { ... }` section
 *
 * @param[in] request		The current request.
 * @Param[in] tls_session	The current TLS session.
 * @return
 *	- UNLANG_ACTION_CALCULATE_RESULT	- No pending actions
 *	- UNLANG_ACTION_PUSHED_CHILD		- Pending operations to evaluate.
 */
unlang_action_t fr_tls_verify_client_cert_pending_push(request_t *request, fr_tls_session_t *tls_session)
{
	if (tls_session->validate.state == FR_TLS_VALIDATION_REQUESTED) {
		return tls_verify_client_cert_push(request, tls_session);
	}

	return UNLANG_ACTION_CALCULATE_RESULT;
}
#endif /* WITH_TLS */
