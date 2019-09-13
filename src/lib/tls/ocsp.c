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
 * @file tls/ocsp.c
 * @brief Validate client certificates using an OCSP service.
 *
 * @copyright 2006-2016 The FreeRADIUS server project
 */
RCSID("$Id$")
USES_APPLE_DEPRECATED_API	/* OpenSSL API has been deprecated by Apple */

#ifdef WITH_TLS
#ifdef HAVE_OPENSSL_OCSP_H
#define LOG_PREFIX "tls - ocsp - "

#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/rad_assert.h>

#include <freeradius-devel/util/misc.h>

#include <freeradius-devel/unlang/compile.h>

#include <openssl/ocsp.h>

#include "attrs.h"
#include "base.h"
#include "missing.h"

/** Rcodes returned by the OCSP check function
 */
typedef enum {
	OCSP_STATUS_FAILED	= 0,
	OCSP_STATUS_OK		= 1,
	OCSP_STATUS_SKIPPED	= 2,
} ocsp_status_t;

/** Maximum leeway in validity period of OCSP response
 *
 * Default 5 minutes.
 */
#define OCSP_MAX_VALIDITY_PERIOD (5 * 60)

/** Extract components of OCSP responser URL from a certificate
 *
 * @param[in] cert to extract URL from.
 * @param[out] host_out Portion of the URL (must be freed with free()).
 * @param[out] port_out Port portion of the URL (must be freed with free()).
 * @param[out] path_out Path portion of the URL (must be freed with free()).
 * @param[out] is_https Whether the responder should be contacted using https.
 * @return
 *	- 0 if no valid URL is contained in the certificate.
 *	- 1 if a URL was found and parsed.
 *	- -1 if at least one URL was found, but none could be parsed.
 */
static int ocsp_cert_url_parse(X509 *cert, char **host_out, char **port_out, char **path_out, int *is_https)
{
	int			i;
	bool			found_uri = false;

	AUTHORITY_INFO_ACCESS	*aia;
	ACCESS_DESCRIPTION	*ad;

	aia = X509_get_ext_d2i(cert, NID_info_access, NULL, NULL);

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(aia, i);
		if (OBJ_obj2nid(ad->method) != NID_ad_OCSP) continue;
		if (ad->location->type != GEN_URI) continue;
		found_uri = true;

		if (OCSP_parse_url((char *) ad->location->d.ia5->data, host_out,
				   port_out, path_out, is_https)) return 1;
	}
	return found_uri ? -1 : 0;
}

/** Set the OCSP TLS stapling extension for a SSL session, from cached response data
 *
 * @param ssl		The current SSL session.
 * @param vp		containing the response.
 * @return
 *	- -1 on error.
 *	- 0 on success.
 */
static int ocsp_staple_from_pair(REQUEST *request, SSL *ssl, VALUE_PAIR *vp)
{
	uint8_t *p;

	/*
	 *	OpenSSL should free the buffer itself.
	 */
	p = OPENSSL_malloc(vp->vp_length);
	if (!p) return -1;

	memcpy(p, vp->vp_octets, vp->vp_length);

	RDEBUG2("Adding OCSP stapling extension");
	if (SSL_set_tlsext_status_ocsp_resp(ssl, p, vp->vp_length) == 0) {
		OPENSSL_free(p);
		return -1;
	}

	return 0;
}

/** Store OCSP response as a TLS-OCSP-Response attribute
 *
 * @note Adds &request:TLS-OCSP-Response to the current request, and adds
 *	stapling data to the current SSL session.
 *
 * @param out		Where to write the TLS-OCSP-Response attribute.  Will also
 *			have been added to the request list of the current request.
 * @param request 	The current request.
 * @param resp		to serialize.
 * @return
 *	- -1 on error.
 *	- 0 on success.
 */
static int ocsp_staple_to_pair(VALUE_PAIR **out, REQUEST *request, OCSP_RESPONSE *resp)
{
	VALUE_PAIR	*vp;
	size_t		len;
	uint8_t		*buff, *p;

	if (!resp) {
		REDEBUG("No OCSP response available");
		return -1;
	}

	len = i2d_OCSP_RESPONSE(resp, NULL);
	if (len <= 0) {
		REDEBUG("Failed getting OCSP response length");
		return -1;
	}

	MEM(p = buff = talloc_array(request, uint8_t, len));	/* Alloc in context of request - steal later */
	len = i2d_OCSP_RESPONSE(resp, &p);
	if (len <= 0) {
		REDEBUG("Failed serialising OCSP response");
		return -1;
	}
	MEM(pair_update_request(&vp, attr_tls_ocsp_response) >= 0);
	fr_pair_value_memsteal(vp, buff, true);

	RDEBUG2("Serializing OCSP response");
	RINDENT();
	RDEBUG2("&%pP", vp);
	REXDENT();

	*out = vp;

	return 0;
}

/** Callback used to get stapling data for the current server cert
 *
 * @param ssl	Current SSL session.
 * @param data	OCSP configuration.
 */
int tls_ocsp_staple_cb(SSL *ssl, void *data)
{
	fr_tls_ocsp_conf_t	*conf = data;	/* Alloced as part of fr_tls_conf_t (not talloced) */
	REQUEST			*request = SSL_get_ex_data(ssl, FR_TLS_EX_INDEX_REQUEST);

	X509			*cert;
	X509			*issuer_cert;
	X509_STORE		*server_store;
	X509_STORE_CTX		*server_store_ctx = NULL;

	int			ret;

	cert = SSL_get_certificate(ssl);
	if (!cert) {
		tls_log_error(request, "No server certificate found in SSL session");
	error:
		X509_STORE_CTX_free(server_store_ctx);
		return conf->softfail ? SSL_TLSEXT_ERR_NOACK : SSL_TLSEXT_ERR_ALERT_FATAL;
	}

	/*
	 *	OpenSSL people appear to have removed SSL_get_cert_store.
	 *
	 *	So if we dynamically set the server cert at runtime, we
	 *	don't have access to the chain.
	 */
	server_store = SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl));
	if (!server_store) {
		tls_log_error(request, "Failed retrieving SSL session cert store");
		goto error;
	}

	MEM(server_store_ctx = X509_STORE_CTX_new());	/* Die if OOM */

	/*
	 *	This is what OpenSSL uses to construct SSL chains
	 *	for validation.  We just need to use it to find
	 *	who issued our server certificate.
	 *
	 *	This isn't what we pass to tls_ocsp_check.  That store
	 *	is used to validate the OCSP server's response.
	 */
	if (X509_STORE_CTX_init(server_store_ctx, server_store, NULL, NULL) == 0) {
		tls_log_error(request, "Failed initialising SSL session cert store ctx");
		goto error;
	}

	/*
	 *	Print out the current chain in the certificate store
	 *	to help with debugging issues where we can't find the
	 *	server cert.
	 */
	if (RDEBUG_ENABLED3) {
		STACK_OF(X509)	*chain;

		RDEBUG3("Current SSL session cert store contents");
		chain = X509_STORE_CTX_get_chain(server_store_ctx);
		RINDENT();
		tls_log_certificate_chain(request, chain, cert);
		REXDENT();
	}

	ret = X509_STORE_CTX_get1_issuer(&issuer_cert, server_store_ctx, cert);
	if (ret != 1) {
		X509_NAME	*subject;
		X509_NAME	*issuer = X509_get_issuer_name(cert);
		char		*subject_str;
		char		*issuer_str;

 		subject = X509_get_subject_name(cert);
		if (!subject) {
			tls_log_error(request, "Couldn't retrieve subject name of SSL session cert");
			goto error;
		}
		MEM(subject_str = X509_NAME_oneline(subject, NULL, 0));

		issuer = X509_get_issuer_name(cert);
		if (!issuer) {
			tls_log_error(request, "Couldn't retrieve issuer name of SSL session cert");
			OPENSSL_free(subject_str);
			goto error;
		}
		MEM(issuer_str = X509_NAME_oneline(issuer, NULL, 0));

		switch (ret) {
		case 0:
			tls_log_error(request, "Issuer \"%s\" of \"%s\" not found in certificate store",
				      issuer_str, subject_str);
			break;
		default:
			tls_log_error(request, "Error retrieving issuer \"%s\" of \"%s\" from certificate store",
				      issuer_str, subject_str);
			break;
		}

		OPENSSL_free(subject_str);
		OPENSSL_free(issuer_str);
		goto error;
	}

	rad_assert(issuer_cert);

	ret = tls_ocsp_check(request, ssl, server_store, issuer_cert, cert, conf, true);
	switch (ret) {
	default:
	case 0:	/* server cert is invalid */
		ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		break;

	case 1:	/* yes */
		ret = SSL_TLSEXT_ERR_OK;
		break;

	case 2:	/* skipped */
		ret = SSL_TLSEXT_ERR_NOACK;
		break;
	}

	X509_free(issuer_cert);	/* Decrement reference count on issuer cert */
	X509_STORE_CTX_free(server_store_ctx);

	return ret;
}

/** Sends a OCSP request to a defined OCSP responder
 *
 */
int tls_ocsp_check(REQUEST *request, SSL *ssl,
		   X509_STORE *store, X509 *issuer_cert, X509 *client_cert,
		   fr_tls_ocsp_conf_t *conf, bool staple_response)
{
	OCSP_CERTID	*certid;
	OCSP_REQUEST	*req = NULL;
	OCSP_RESPONSE	*resp = NULL;
	OCSP_BASICRESP	*bresp = NULL;
	char		*host = NULL;
	char		*port = NULL;
	char		*path = NULL;
	char		host_header[1024];
	int		use_ssl = -1;
	long		this_fudge = OCSP_MAX_VALIDITY_PERIOD, this_max_age = -1;
	BIO		*conn = NULL, *ssl_log = NULL;
	ocsp_status_t   ocsp_status = OCSP_STATUS_FAILED;
	ocsp_status_t	status;
	ASN1_GENERALIZEDTIME *rev, *this_update, *next_update;
	int		reason;
	OCSP_REQ_CTX	*ctx;
	int		rc;

	fr_time_t	start;
	VALUE_PAIR	*vp;

	if (conf->cache_server) switch (tls_cache_process(request, conf->cache.load)) {
	case RLM_MODULE_REJECT:
		REDEBUG("Told to force OCSP validation failure from cached response");
		return OCSP_STATUS_FAILED;

	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
	/*
	 *	These are fine for OCSP too, we don't *expect* to always
	 *	have a cached OCSP status.
	 */
	case RLM_MODULE_NOTFOUND:
	case RLM_MODULE_NOOP:
		break;

	default:
		RWDEBUG("Failed retrieving cached OCSP status");
		break;
	}

	/*
	 *	Allow us to cache the OCSP verified state externally
	 */
	vp = fr_pair_find_by_da(request->control, attr_tls_ocsp_cert_valid, TAG_ANY);
	if (vp) switch (vp->vp_uint32) {
	case 0:	/* no */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = no, forcing OCSP failure");
		return OCSP_STATUS_FAILED;

	case 1: /* yes */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = yes, forcing OCSP success");

		/*
		 *	If this fails, and an OCSP stapled response is required,
		 *	we need to run the full OCSP check.
		 */
		if (staple_response) {
			vp = fr_pair_find_by_da(request->control, attr_tls_ocsp_response, TAG_ANY);
			if (!vp) {
				RDEBUG2("No &control:TLS-OCSP-Response attribute found, performing full OCSP check");
				break;
			}
			if (ocsp_staple_from_pair(request, ssl, vp) < 0) {
				RWDEBUG("Failed setting OCSP staple response in SSL session");
				return OCSP_STATUS_FAILED;
			}
		}

		return OCSP_STATUS_OK;

	case 2: /* skipped */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = skipped, skipping OCSP check");
		return conf->softfail ? OCSP_STATUS_OK : OCSP_STATUS_FAILED;

	case 3: /* unknown */
	default:
		break;
	}

	if (issuer_cert == NULL) {
		RWDEBUG("Could not get issuer certificate");
		goto skipped;
	}

	/*
	 *	Setup logging for this OCSP operation
	 */
	ssl_log = BIO_new(BIO_s_mem());
	if (!ssl_log) {
		REDEBUG("Failed creating log queue");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	/*
	 *	Create OCSP Request
	 */
	certid = OCSP_cert_to_id(NULL, client_cert, issuer_cert);
	req = OCSP_REQUEST_new();
	OCSP_request_add0_id(req, certid);
	if (conf->use_nonce) OCSP_request_add1_nonce(req, NULL, 8);

	/*
	 *	Send OCSP Request and get OCSP Response
	 */

	/* Get OCSP responder URL */
	if (conf->override_url) {
		char *url;

	use_url:
		memcpy(&url, &conf->url, sizeof(url));
		/* Reading the libssl src, they do a strdup on the URL, so it could of been const *sigh* */
		OCSP_parse_url(url, &host, &port, &path, &use_ssl);
		if (!host || !port || !path) {
			RWDEBUG("Host or port or path missing from configured URL \"%s\".  Not doing OCSP", url);
			goto skipped;
		}
	} else {
		int ret;

		ret = ocsp_cert_url_parse(client_cert, &host, &port, &path, &use_ssl);
		switch (ret) {
		case -1:
			RWDEBUG("Invalid URL in certificate.  Not doing OCSP");
			break;

		case 0:
			if (conf->url) {
				RWDEBUG("No OCSP URL in certificate, falling back to configured URL");
				goto use_url;
			}
			RWDEBUG("No OCSP URL in certificate.  Not doing OCSP");
			goto skipped;

		case 1:
			rad_assert(host && port && path);
			break;
		}
	}

	RDEBUG2("Using responder URL \"http://%s:%s%s\"", host, port, path);

	/* Check host and port length are sane, then create Host: HTTP header */
	if ((strlen(host) + strlen(port) + 2) > sizeof(host_header)) {
		RWDEBUG("Host and port too long");
		goto skipped;
	}
	snprintf(host_header, sizeof(host_header), "%s:%s", host, port);

	/* Setup BIO socket to OCSP responder */
	conn = BIO_new_connect(host);
	BIO_set_conn_port(conn, port);

	if (conf->timeout) BIO_set_nbio(conn, 1);

	rc = BIO_do_connect(conn);
	if ((rc <= 0) && ((!conf->timeout) || !BIO_should_retry(conn))) {
		REDEBUG("Couldn't connect to OCSP responder");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	ctx = OCSP_sendreq_new(conn, path, NULL, -1);
	if (!ctx) {
		REDEBUG("Couldn't create OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host_header)) {
		REDEBUG("Couldn't set Host header");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
		REDEBUG("Couldn't add data to OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	start = fr_time();
	do {
		rc = OCSP_sendreq_nbio(&resp, ctx);
		if (conf->timeout) {
			if (conf->timeout > (fr_time() - start)) break;
		}
	} while ((rc == -1) && BIO_should_retry(conn));

	if (conf->timeout && (rc == -1) && BIO_should_retry(conn)) {
		REDEBUG("Response timed out");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	OCSP_REQ_CTX_free(ctx);

	if (rc == 0) {
		REDEBUG("Couldn't get OCSP response");
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "", ssl_log);
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	/* Verify OCSP response status */
	status = OCSP_response_status(resp);
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		REDEBUG("Response status: %s", OCSP_response_status_str(status));
		goto finish;
	}
	bresp = OCSP_response_get1_basic(resp);
	if (conf->use_nonce && OCSP_check_nonce(req, bresp) != 1) {
		REDEBUG("Response has wrong nonce value");
		goto finish;
	}
	if (OCSP_basic_verify(bresp, NULL, store, 0) != 1){
		REDEBUG("Couldn't verify OCSP basic response");
		goto finish;
	}

	/*	Verify OCSP cert status */
	if (!OCSP_resp_find_status(bresp, certid, (int *)&status, &reason, &rev, &this_update, &next_update)) {
		REDEBUG("No Status found");
		goto finish;
	}

	/*
	 *	Here we check the fields 'thisUpdate' and 'nextUpdate'
	 *	from the OCSP response against the server's time.
	 *
	 *	this_fudge is the number of seconds +- between the current
	 *	time and this_update.
	 *
	 *	The default for this_fudge is 300, defined by OCSP_MAX_VALIDITY_PERIOD.
	 */
	if (!OCSP_check_validity(this_update, next_update, this_fudge, this_max_age)) {
		/*
		 *	We want this to show up in the global log
		 *	so someone will fix it...
		 */
		RATE_LIMIT(RERROR("Delta +/- between OCSP response time and our time is greater than %li "
				  "seconds.  Check servers are synchronised to a common time source",
				  this_fudge));
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "", ssl_log);
		goto finish;
	}

	/*
	 *	Print any messages we may have accumulated
	 */
	SSL_DRAIN_ERROR_QUEUE(RDEBUG2, "", ssl_log);
	if (RDEBUG_ENABLED) {
		RDEBUG2("OCSP response valid from:");
		ASN1_GENERALIZEDTIME_print(ssl_log, this_update);
		RINDENT();
		SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
		REXDENT();

		if (next_update) {
			RDEBUG2("New information available at:");
			ASN1_GENERALIZEDTIME_print(ssl_log, next_update);
			RINDENT();
			SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
			REXDENT();
		}
	}

	/*
	 *	When an OCSP validation command is used with OpenSSL
	 *	next_update is NULL.
	 */
	if (next_update) {
		fr_time_t	now;
		time_t		next;

		/*
		 *	Sometimes we already know what 'now' is depending
		 *	on the code path, other times we don't.
		 */
		now = fr_time();

		if (tls_utils_asn1time_to_epoch(&next, next_update) < 0) {
			RPEDEBUG("Failed parsing next_update time");
			ocsp_status = OCSP_STATUS_SKIPPED;
			goto finish;
		}
		if (fr_time_to_sec(now) < next){
			RDEBUG2("Adding OCSP TTL attribute");

			MEM(pair_update_request(&vp, attr_tls_ocsp_next_update) >= 0);
			vp->vp_uint32 = next - fr_time_to_sec(now);
			RINDENT();
			RDEBUG2("&%pP", vp);
			REXDENT();
		} else {
			RDEBUG2("Update time is in the past.  Not adding &TLS-OCSP-Next-Update");
		}
	} else {
		RDEBUG2("Update time not provided.  Not adding &TLS-OCSP-Next-Update");
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		RDEBUG2("Cert status: good");
		ocsp_status = OCSP_STATUS_OK;
		break;

	default:
		/* REVOKED / UNKNOWN */
		REDEBUG("Cert status: %s", OCSP_cert_status_str(status));
		if (reason != -1) REDEBUG("Reason: %s", OCSP_crl_reason_str(reason));

		/*
		 *	Print any messages we may have accumulated
		 */
		SSL_DRAIN_LOG_QUEUE(RDEBUG, "", ssl_log);
		if (RDEBUG_ENABLED2) {
			RDEBUG2("Revocation time:");
			ASN1_GENERALIZEDTIME_print(ssl_log, rev);
			RINDENT();
			SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
			REXDENT();
		}
		break;
	}

finish:
	switch (ocsp_status) {
	case OCSP_STATUS_OK:
		RDEBUG2("Certificate is valid");

		if (staple_response) {
			/*
			 *	Convert the OCSP response to a VALUE_PAIR
			 *	and add it to the current request.
			 */
			if (ocsp_staple_to_pair(&vp, request, resp) < 0) goto skipped;

			/*
			 *	Set the stapled response for the current
			 *	SSL session.
			 */
			if (ocsp_staple_from_pair(request, ssl, vp) < 0) return -1;
			vp = NULL;	/* It's in the request, don't need to free it! */
		}

		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = 1;	/* yes */
		ocsp_status = OCSP_STATUS_OK;

		break;

	case OCSP_STATUS_SKIPPED:
	skipped:
		SSL_DRAIN_ERROR_QUEUE(RWDEBUG, "", ssl_log);
		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = 2;	/* skipped */
		if (conf->softfail) {
			RWDEBUG("Unable to check certificate: %s",
				staple_response ?
					"Cannot provide TLS client with stapled OCSP response":
					"TLS clients presenting revoked certificates may be granted access");

			ocsp_status = OCSP_STATUS_OK;

			/* Remove OpenSSL errors from queue or handshake will fail */
			while (ERR_get_error());	/* Not always debugging */
		} else {
			REDEBUG("Unable to check certificate, failing");
			ocsp_status = OCSP_STATUS_FAILED;
		}
		break;

	default:
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "", ssl_log);
		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = 0;	/* no */
		REDEBUG("Failed to validate certificate");
		break;
	}

	if (conf->cache_server) switch (tls_cache_process(request, conf->cache.store)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	default:
		RWDEBUG("Failed writing cached OCSP status");
		break;
	}

	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_BASICRESP_free(bresp);
	OCSP_RESPONSE_free(resp);
	OPENSSL_free(host);
	OPENSSL_free(port);
	OPENSSL_free(path);
	BIO_free_all(conn);
	BIO_free(ssl_log);

	return ocsp_status;
}

#define CACHE_SECTION(_out, _verb, _name) \
do { \
	CONF_SECTION *_tmp; \
	_tmp = cf_section_find(server_cs, _verb, _name); \
	if (_tmp) { \
		if (unlang_compile(_tmp, MOD_AUTHORIZE, NULL) < 0) return -1; \
		found = true; \
	} \
	if (actions) _out = _tmp; \
} while (0)

/** Pre-compile unlang cache actions and store pointers to them
 *
 * @param[out] actions		Structure to hold pointers to actions.
 * @param[in] server_cs		to lookup actions for.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int tls_ocsp_state_cache_compile(fr_tls_cache_t *actions, CONF_SECTION *server_cs)
{
	bool found = false;

	if (!fr_cond_assert(server_cs)) return -1;

	CACHE_SECTION(actions->load, "load", "ocsp-state");
	CACHE_SECTION(actions->store, "store", "ocsp-state");

	/*
	 *	Warn if we couldn't find any actions.
	 */
	if (!found) {
		cf_log_warn(server_cs, "No ocsp-state cache actions found in virtual server \"%s\"",
			    cf_section_name2(server_cs));
	}

	return 0;
}

/** Pre-compile unlang cache actions and store pointers to them
 *
 * @param[out] actions		Structure to hold pointers to actions.
 * @param[in] server_cs		to lookup actions for.
 * @return
 *	- -1 on failure.
 *	- 0 on success.
 */
int tls_ocsp_staple_cache_compile(fr_tls_cache_t *actions, CONF_SECTION *server_cs)
{
	bool found = false;

	if (!fr_cond_assert(server_cs)) return -1;

	CACHE_SECTION(actions->load, "load", "ocsp-staple");
	CACHE_SECTION(actions->store, "store", "ocsp-staple");

	/*
	 *	Warn if we couldn't find any actions.
	 */
	if (!found) {
		cf_log_warn(server_cs, "No ocsp-staple cache actions found in virtual server \"%s\"",
			    cf_section_name2(server_cs));
	}

	return 0;
}
#endif /* HAVE_OPENSSL_OCSP_H */
#endif /* WITH_TLS */
