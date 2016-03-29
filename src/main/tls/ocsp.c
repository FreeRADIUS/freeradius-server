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
#define LOG_PREFIX "tls - "

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>
#include <openssl/ocsp.h>

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

/** Convert OpenSSL's ASN1_TIME to an epoch time
 *
 * @param[out] out	Where to write the time_t.
 * @param[in] asn1	The ASN1_TIME to convert.
 * @return
 *	- 0 success.
 *	- -1 on failure.
 */
static time_t ocsp_asn1time_to_epoch(time_t *out, ASN1_TIME const *asn1){
	struct		tm t;
	char const	*p = (char const *)asn1->data, *end = p + strlen(p);

	memset(&t, 0, sizeof(t));

	if (asn1->type == V_ASN1_UTCTIME) {/* two digit year */
		if ((end - p) < 2) {
			fr_strerror_printf("ASN1 date string too short, expected 2 additional bytes, got %zu bytes",
					   end - p);
			return -1;
		}

		t.tm_year = (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		if (t.tm_year < 70) t.tm_year += 100;
	} else if (asn1->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		if ((end - p) < 4) {
			fr_strerror_printf("ASN1 string too short, expected 4 additional bytes, got %zu bytes",
					   end - p);
			return -1;
		}

		t.tm_year = (*(p++) - '0') * 1000;
		t.tm_year += (*(p++) - '0') * 100;
		t.tm_year += (*(p++) - '0') * 10;
		t.tm_year += (*(p++) - '0');
		t.tm_year -= 1900;
	}

	if ((end - p) < 10) {
		fr_strerror_printf("ASN1 string too short, expected 10 additional bytes, got %zu bytes",
				   end - p);
		return -1;
	}

	t.tm_mon = (*(p++) - '0') * 10;
	t.tm_mon += (*(p++) - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (*(p++) - '0') * 10;
	t.tm_mday += (*(p++) - '0');
	t.tm_hour = (*(p++) - '0') * 10;
	t.tm_hour += (*(p++) - '0');
	t.tm_min = (*(p++) - '0') * 10;
	t.tm_min += (*(p++) - '0');
	t.tm_sec = (*(p++) - '0') * 10;
	t.tm_sec += (*(p++) - '0');

	/* Apparently OpenSSL converts all timestamps to UTC? Maybe? */
	*out = mktime(&t);
	return 0;
}

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

/** Sends a OCSP request to a defined OCSP responder
 *
 */
int tls_ocsp_check(REQUEST *request, X509_STORE *store,
		   X509 *issuer_cert, X509 *client_cert,
		   fr_tls_conf_t *conf)
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
#if OPENSSL_VERSION_NUMBER >= 0x1000003f
	OCSP_REQ_CTX	*ctx;
	int		rc;
	struct timeval	when;
#endif
	struct timeval	now = { 0, 0 };
	time_t		next;
	VALUE_PAIR	*vp;

	if (conf->ocsp_cache_server) switch (tls_cache_process(request, conf->ocsp_cache_server,
							   CACHE_ACTION_OCSP_READ)) {
	case RLM_MODULE_REJECT:
		REDEBUG("Told to force OCSP validation failure by virtual server");
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
	vp = fr_pair_find_by_num(request->control, 0, PW_TLS_OCSP_CERT_VALID, TAG_ANY);
	if (vp) switch (vp->vp_integer) {
	case 0:	/* no */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = no, forcing OCSP failure");
		return OCSP_STATUS_FAILED;

	case 1: /* yes */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = yes, forcing OCSP success");
		return OCSP_STATUS_OK;

	case 2: /* skipped */
		RDEBUG2("Found &control:TLS-OCSP-Cert-Valid = skipped, skipping OCSP check");
		return conf->ocsp_softfail ? OCSP_STATUS_OK : OCSP_STATUS_FAILED;

	case 3: /* unknown */
	default:
		break;
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
	if (conf->ocsp_use_nonce) OCSP_request_add1_nonce(req, NULL, 8);

	/*
	 *	Send OCSP Request and get OCSP Response
	 */

	/* Get OCSP responder URL */
	if (conf->ocsp_override_url) {
		char *url;

	use_ocsp_url:
		memcpy(&url, &conf->ocsp_url, sizeof(url));
		/* Reading the libssl src, they do a strdup on the URL, so it could of been const *sigh* */
		OCSP_parse_url(url, &host, &port, &path, &use_ssl);
		if (!host || !port || !path) {
			RWDEBUG("ocsp: Host or port or path missing from configured URL \"%s\".  Not doing OCSP", url);
			goto skipped;
		}
	} else {
		int ret;

		ret = ocsp_cert_url_parse(client_cert, &host, &port, &path, &use_ssl);
		switch (ret) {
		case -1:
			RWDEBUG("ocsp: Invalid URL in certificate.  Not doing OCSP");
			break;

		case 0:
			if (conf->ocsp_url) {
				RWDEBUG("ocsp: No OCSP URL in certificate, falling back to configured URL");
				goto use_ocsp_url;
			}
			RWDEBUG("ocsp: No OCSP URL in certificate.  Not doing OCSP");
			goto skipped;

		case 1:
			rad_assert(host && port && path);
			break;
		}
	}

	RDEBUG2("ocsp: Using responder URL \"http://%s:%s%s\"", host, port, path);

	/* Check host and port length are sane, then create Host: HTTP header */
	if ((strlen(host) + strlen(port) + 2) > sizeof(host_header)) {
		RWDEBUG("ocsp: Host and port too long");
		goto skipped;
	}
	snprintf(host_header, sizeof(host_header), "%s:%s", host, port);

	/* Setup BIO socket to OCSP responder */
	conn = BIO_new_connect(host);
	BIO_set_conn_port(conn, port);

#if OPENSSL_VERSION_NUMBER < 0x1000003f
	BIO_do_connect(conn);

	/* Send OCSP request and wait for response */
	resp = OCSP_sendreq_bio(conn, path, req);
	if (!resp) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}
#else
	if (conf->ocsp_timeout) BIO_set_nbio(conn, 1);

	rc = BIO_do_connect(conn);
	if ((rc <= 0) && ((!conf->ocsp_timeout) || !BIO_should_retry(conn))) {
		REDEBUG("ocsp: Couldn't connect to OCSP responder");
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	ctx = OCSP_sendreq_new(conn, path, NULL, -1);
	if (!ctx) {
		REDEBUG("ocsp: Couldn't create OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host_header)) {
		REDEBUG("ocsp: Couldn't set Host header");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	if (!OCSP_REQ_CTX_set1_req(ctx, req)) {
		REDEBUG("ocsp: Couldn't add data to OCSP request");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	gettimeofday(&when, NULL);
	when.tv_sec += conf->ocsp_timeout;

	do {
		rc = OCSP_sendreq_nbio(&resp, ctx);
		if (conf->ocsp_timeout) {
			gettimeofday(&now, NULL);
			if (!timercmp(&now, &when, <)) break;
		}
	} while ((rc == -1) && BIO_should_retry(conn));

	if (conf->ocsp_timeout && (rc == -1) && BIO_should_retry(conn)) {
		REDEBUG("ocsp: Response timed out");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	OCSP_REQ_CTX_free(ctx);

	if (rc == 0) {
		REDEBUG("ocsp: Couldn't get OCSP response");
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}
#endif /* OPENSSL_VERSION_NUMBER < 0x1000003f */

	/* Verify OCSP response status */
	status = OCSP_response_status(resp);
	if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		REDEBUG("ocsp: Response status: %s", OCSP_response_status_str(status));
		goto finish;
	}
	bresp = OCSP_response_get1_basic(resp);
	if (conf->ocsp_use_nonce && OCSP_check_nonce(req, bresp)!=1) {
		REDEBUG("ocsp: Response has wrong nonce value");
		goto finish;
	}
	if (OCSP_basic_verify(bresp, NULL, store, 0)!=1){
		REDEBUG("ocsp: Couldn't verify OCSP basic response");
		goto finish;
	}

	/*	Verify OCSP cert status */
	if (!OCSP_resp_find_status(bresp, certid, (int *)&status, &reason, &rev, &this_update, &next_update)) {
		REDEBUG("ocsp: No Status found");
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
		RATE_LIMIT(RERROR("ocsp: Delta +/- between OCSP response time and our time is greater than %li "
				  "seconds.  Check servers are synchronised to a common time source",
				  this_fudge));
		SSL_DRAIN_ERROR_QUEUE(REDEBUG, "ocsp: ", ssl_log);
		goto finish;
	}

	/*
	 *	Print any messages we may have accumulated
	 */
	SSL_DRAIN_ERROR_QUEUE(REDEBUG, "ocsp: ", ssl_log);
	if (RDEBUG_ENABLED) {
		RDEBUG2("ocsp: OCSP response valid from:");
		ASN1_GENERALIZEDTIME_print(ssl_log, this_update);
		RINDENT();
		SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
		REXDENT();

		if (next_update) {
			RDEBUG2("ocsp: New information available at:");
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
		/*
		 *	Sometimes we already know what 'now' is depending
		 *	on the code path, other times we don't.
		 */
		if (now.tv_sec == 0) gettimeofday(&now, NULL);
		if (ocsp_asn1time_to_epoch(&next, next_update) < 0) {
			REDEBUG("ocsp: Failed parsing next_update time: %s", fr_strerror());
			ocsp_status = OCSP_STATUS_SKIPPED;
			goto finish;
		}
		if (now.tv_sec < next){
			RDEBUG2("ocsp: Adding OCSP TTL attribute");
			RINDENT();
			vp = pair_make_request("TLS-OCSP-Next-Update", NULL, T_OP_SET);
			vp->vp_integer = next - now.tv_sec;
			rdebug_pair(L_DBG_LVL_2, request, vp, NULL);
			REXDENT();
		} else {
			RDEBUG2("ocsp: Update time is in the past.  Not adding &TLS-OCSP-Next-Update");
		}
	} else {
		RDEBUG2("ocsp: Update time not provided.  Not adding &TLS-OCSP-Next-Update");
	}

	switch (status) {
	case V_OCSP_CERTSTATUS_GOOD:
		RDEBUG2("ocsp: Cert status: good");
		ocsp_status = OCSP_STATUS_OK;
		break;

	default:
		/* REVOKED / UNKNOWN */
		REDEBUG("ocsp: Cert status: %s", OCSP_cert_status_str(status));
		if (reason != -1) REDEBUG("ocsp: Reason: %s", OCSP_crl_reason_str(reason));

		/*
		 *	Print any messages we may have accumulated
		 */
		SSL_DRAIN_LOG_QUEUE(RDEBUG, "ocsp: ", ssl_log);
		if (RDEBUG_ENABLED) {
			RDEBUG2("ocsp: Revocation time:");
			ASN1_GENERALIZEDTIME_print(ssl_log, rev);
			RINDENT();
			SSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
			REXDENT();
		}
		break;
	}

finish:
	/* Free OCSP Stuff */
	OCSP_REQUEST_free(req);
	OCSP_RESPONSE_free(resp);
	free(host);
	free(port);
	free(path);
	BIO_free_all(conn);
	BIO_free(ssl_log);
	OCSP_BASICRESP_free(bresp);

	switch (ocsp_status) {
	case OCSP_STATUS_OK:
		RDEBUG2("ocsp: Certificate is valid");
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 1;	/* yes */
		ocsp_status = OCSP_STATUS_OK;
		break;

	case OCSP_STATUS_SKIPPED:
	skipped:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 2;	/* skipped */
		if (conf->ocsp_softfail) {
			RWDEBUG("ocsp: Unable to check certificate, assuming it's valid");
			RWDEBUG("ocsp: This may be insecure");
			ocsp_status = OCSP_STATUS_OK;

			/* Remove OpenSSL errors from queue or handshake will fail */
			while (ERR_get_error());
		} else {
			REDEBUG("ocsp: Unable to check certificate, failing");
			ocsp_status = OCSP_STATUS_FAILED;
		}
		break;

	default:
		vp = pair_make_request("TLS-OCSP-Cert-Valid", NULL, T_OP_SET);
		vp->vp_integer = 0;	/* no */
		REDEBUG("ocsp: Failed to validate certificate");
		break;
	}

	if (conf->ocsp_cache_server) switch (tls_cache_process(request, conf->ocsp_cache_server, CACHE_ACTION_OCSP_WRITE)) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		break;

	default:
		RWDEBUG("Failed writing cached OCSP status");
		break;
	}

	return ocsp_status;
}
#endif /* HAVE_OPENSSL_OCSP_H */
#endif /* WITH_TLS */
