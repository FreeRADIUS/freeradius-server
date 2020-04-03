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
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/strerror.h>
#include <freeradius-devel/util/syserror.h>

#include "attrs.h"
#include "base.h"
#include "missing.h"

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
 *   4. Verify that the credentials presented by the certificate fulfill additional
 *      requirements specific to the application, such as with respect to access control
 *      lists or with respect to OCSP (Online Certificate Status Processing).
 *
 * @note This callback will be called multiple times based on the depth of the root
 *	certificate chain.
 *
 * @note As a byproduct of validation, various OIDs will be extracted from the
 *	certificates, and inserted into the session-state: list as VALUE_PAIR.
 *
 * @param ok		preverify ok.  1 if true, 0 if false.
 * @param x509_ctx	containing certs to verify.
 * @return
 *	- 0 if not valid.
 *	- 1 if valid.
 */
int fr_tls_validate_cert_cb(int ok, X509_STORE_CTX *x509_ctx)
{
	X509		*cert;
	SSL		*ssl;
	fr_tls_session_t	*tls_session;
	int		err, depth;
	fr_tls_conf_t	*conf;
	int		my_ok = ok;

	VALUE_PAIR	*cert_vps = NULL;
	fr_cursor_t	cursor;

	char const	**identity_p;
	char const	*identity = NULL;

	char		subject[1024];
	char		common_name[1024];
	char		issuer[1024];

	REQUEST		*request;

	cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	err = X509_STORE_CTX_get_error(x509_ctx);
	depth = X509_STORE_CTX_get_error_depth(x509_ctx);

	/*
	 *	Retrieve the pointer to the SSL of the connection currently treated
	 *	and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(x509_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conf = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_CONF), fr_tls_conf_t);
	tls_session = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_TLS_SESSION), fr_tls_session_t);
	request = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST), REQUEST);

	identity_p = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_IDENTITY);
	if (identity_p && *identity_p) identity = talloc_get_type_abort_const(*identity_p, char);

	if (RDEBUG_ENABLED3) {
		STACK_OF(X509)	*our_chain = X509_STORE_CTX_get_chain(x509_ctx);
		int		i;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		RDEBUG3("Certificate chain - %i cert(s) untrusted", X509_STORE_CTX_get_num_untrusted(x509_ctx));
#else
		RDEBUG3("Certificate chain");
#endif

		for (i = sk_X509_num(our_chain); i > 0 ; i--) {
			X509 *this_cert = sk_X509_value(our_chain, i - 1);

			X509_NAME_oneline(X509_get_subject_name(this_cert), subject, sizeof(subject));
			subject[sizeof(subject) - 1] = '\0';

			RDEBUG3("%s [%i] %s", this_cert == cert ? ">" : " ", i - 1, subject);
		}
	}

	/*
	 *	For this next bit, we create the attributes *only* if
	 *	we're at the client or issuing certificate, AND we
	 *	have a user identity.  i.e. we don't create the
	 *	attributes for RadSec connections.
	 *
	 *	We do not repopulate the attribute list with cert
	 *	attributes as these should have been cached previously.
	 *
	 *	If we do not have a copy of the cert that issued the
	 *	client's cert in SSL_CTX's X509_STORE.
	 */
	if (identity && (depth <= 1) && !SSL_session_reused(ssl)) {
		fr_cursor_init(&cursor, &cert_vps);
		fr_tls_session_pairs_from_x509_cert(&cursor, request, tls_session, cert, depth);

		/*
		 *	Add a copy of the cert_vps to session state.
		 *
		 *	Both PVS studio and Coverity detect the condition
		 *	below as logically dead code unless we explicitly
		 *	set cert_vps.  This is because they're too dumb
		 *	to realise that the cursor argument passed to
		 *	fr_tls_session_pairs_from_x509_cert contains a
		 *	reference to cert_vps.
		 */
		cert_vps = fr_cursor_head(&cursor);
		if (cert_vps) {
			RDEBUG2("Adding certificate attributes to session-state");

			/*
			 *	Print out all the pairs we have so far
			 */
			log_request_pair_list(L_DBG_LVL_2, request, cert_vps, "&session-state:");

			/*
			 *	cert_vps have a different talloc parent, so we
			 *	can't just reference them.
			 */
			MEM(fr_pair_list_copy(request->state_ctx, &request->state, cert_vps) >= 0);
			fr_pair_list_free(&cert_vps);
		}
	}

	/*
	 *	Get the Subject & Issuer
	 */
	subject[0] = issuer[0] = '\0';
	X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
	subject[sizeof(subject) - 1] = '\0';

	X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
	issuer[sizeof(issuer) - 1] = '\0';

	/*
	 *	Get the Common Name, if there is a subject.
	 */
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert),
				  NID_commonName, common_name, sizeof(common_name));
	common_name[sizeof(common_name) - 1] = '\0';

	/*
	 *	If the CRL has expired, that might still be OK.
	 */
	if (!my_ok && (conf->allow_expired_crl) && (err == X509_V_ERR_CRL_HAS_EXPIRED)) {
		my_ok = 1;
		X509_STORE_CTX_set_error(x509_ctx, 0);
	}

	if (!my_ok) {
		char const *p = X509_verify_cert_error_string(err);
		RERROR("TLS error: %s (%i)", p, err);
		return my_ok;
	}

	switch (X509_STORE_CTX_get_error(x509_ctx)) {
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		RERROR("issuer=%s", issuer);
		break;

	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		RERROR("notBefore=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notBefore(x509_ctx->current_cert));
#endif
		break;

	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		RERROR("notAfter=");
#if 0
		ASN1_TIME_print(bio_err, X509_get_notAfter(x509_ctx->current_cert));
#endif
		break;
	}

	/*
	 *	Stop checking if this is an intermediary.
	 *
	 *	Client certificates get better OCSP checks.
	 */
	if (depth > 0) {
		RDEBUG2("[verify chain] = %s", my_ok ? "ok" : "invalid");
		return my_ok;
	}

	/*
	 *	If the conf tells us to, check cert issuer
	 *	against the specified value and fail
	 *	verification if they don't match.
	 */
	if (conf->check_cert_issuer && (strcmp(issuer, conf->check_cert_issuer) != 0)) {
		REDEBUG("Certificate issuer (%s) does not match specified value (%s)!",
			issuer, conf->check_cert_issuer);
		my_ok = 0;
	}

	/*
	 *	If the conf tells us to, check the CN in the
	 *	cert against xlat'ed value, but only if the
	 *	previous checks passed.
	 */
	if (my_ok && conf->check_cert_cn) {
		char cn_str[1024];

		if (xlat_eval(cn_str, sizeof(cn_str), request, conf->check_cert_cn, NULL, NULL) < 0) {
			/* if this fails, fail the verification */
			my_ok = 0;
		} else {
			RDEBUG2("checking certificate CN (%s) with xlat'ed value (%s)", common_name, cn_str);
			if (strcmp(cn_str, common_name) != 0) {
				REDEBUG("Certificate CN (%s) does not match specified value (%s)!",
					common_name, cn_str);
				my_ok = 0;
			}
		}
	} /* check_cert_cn */

	while (conf->verify_client_cert_cmd) {
		char		filename[256];
		int		fd;
		FILE		*fp;
		VALUE_PAIR	*vp;

		snprintf(filename, sizeof(filename), "%s/client.XXXXXXXX", conf->verify_tmp_dir);

#ifdef __COVERITY__
		/*
		 *	POSIX-2008 requires that mkstemp creates the file
		 *	with 0600 permissions.  So setting umask is pointless
		 *	and although it won't cause crashes, will cause
		 *	race conditions in threaded environments.
		 */
		umask(0600);
#endif
		fd = mkstemp(filename);
		if (fd < 0) {
			RDEBUG2("Failed creating file in %s: %s",
			        conf->verify_tmp_dir, fr_syserror(errno));
			break;
		}

		fp = fdopen(fd, "w");
		if (!fp) {
			close(fd);
			REDEBUG("Failed opening file \"%s\": %s", filename, fr_syserror(errno));
			break;
		}

		if (!PEM_write_X509(fp, cert)) {
			fclose(fp);
			REDEBUG("Failed writing certificate to file");
			goto do_unlink;
		}
		fclose(fp);

		MEM(pair_update_request(&vp, attr_tls_client_cert_filename) >= 0);
		fr_pair_value_strcpy(vp, filename);

		RDEBUG2("Verifying client certificate with cmd");
		if (radius_exec_program(request, NULL, 0, NULL, request, conf->verify_client_cert_cmd,
					request->packet->vps, true, true, fr_time_delta_from_sec(EXEC_TIMEOUT)) != 0) {
			REDEBUG("Client certificate CN \"%s\" failed external verification", common_name);
			my_ok = 0;
		} else {
			RDEBUG2("Client certificate CN \"%s\" passed external validation", common_name);
		}

	do_unlink:
		unlink(filename);
		break;
	}

#ifdef HAVE_OPENSSL_OCSP_H
	/*
	 *	Do OCSP last, so we have the complete set of attributes
	 *	available for the virtual server.
	 *
	 *	Fixme: Do we want to store the matching TLS-Client-cert-Filename?
	 */
	if (my_ok && conf->ocsp.enable){
		X509	*issuer_cert;

		RDEBUG2("Starting OCSP Request");

		/*
		 *	If we don't have an issuer, then we can't send
		 *	and OCSP request, but pass the NULL issuer in
		 *	so fr_tls_ocsp_check can decide on the correct
		 *	return code.
		 */
		issuer_cert = X509_STORE_CTX_get0_current_issuer(x509_ctx);
		my_ok = fr_tls_ocsp_check(request, ssl, conf->ocsp.store, issuer_cert, cert, &(conf->ocsp), false);
	}
#endif

	RDEBUG2("[verify client] = %s", my_ok ? "ok" : "invalid");
	return my_ok;
}

/** Revalidates the client's certificate chain
 *
 * Wraps the fr_tls_validate_cert_cb callback, allowing us to use the same
 * validation logic whenever we need to.
 *
 * @note Only use so far is forcing the chain to be re-validated on session
 *	resumption.
 *
 * @return
 *	- 1 if the chain could be validated.
 *	- 0 if the chain failed validation.
 */
int fr_tls_validate_client_cert_chain(SSL *ssl)
{
	int		err;
	int		verify;
	int		ret = 1;

	STACK_OF(X509)	*chain;
	X509		*cert;
	X509_STORE	*store;
	X509_STORE_CTX	*store_ctx;

	REQUEST		*request;

	request = talloc_get_type_abort(SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST), REQUEST);

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
	X509_STORE_CTX_set_verify_cb(store_ctx, fr_tls_validate_cert_cb);

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
#endif /* WITH_TLS */
