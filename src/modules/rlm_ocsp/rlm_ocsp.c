/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version.
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
 * @file rlm_ocsp.c
 * @brief Check a certificate against an OCSP responder.
 *
 * @copyright 2026 Network RADIUS SAS (legal@networkradius.com)
 */
RCSID("$Id$")

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/curl/base.h>
#include <freeradius-devel/server/module_rlm.h>

#include <freeradius-devel/tls/bio.h>
#include <freeradius-devel/tls/log.h>
#include <freeradius-devel/tls/strerror.h>
#include <freeradius-devel/tls/utils.h>
#include <freeradius-devel/util/slab.h>

#ifdef WITH_TLS
#include <openssl/ocsp.h>
#endif

typedef struct {
	bool			override_url;			//!< Always use the configured OCSP URL even if the
								//!< certificate contains one.
	char const		*url;				//!< Override / fallback OCSP URL.
	bool			use_nonce;			//!< Include a nonce in OCSP requests/
	bool			softfail;			//!< Should the module soft fail if the responder is not available.

	int			leeway;				//!< Seconds of leeway allowed in checking response `thisUpdate`
	int			max_age;			//!< Maximum age of `thisUpdate` allowed in response checks.

	bool			verifycert;			//!< Should the certificate in responses be verified.
	char const		*ca_file;			//!< File containing certs for verifying OCSP responses.
	char const		*ca_path;			//!< Directory containing certs for verifying OCSP responses.

	uint64_t		max_body_in;			//!< Largest response we accept.
	fr_curl_conn_config_t	conn_config;			//!< Reusable CURL handle config
} rlm_ocsp_t;

FR_SLAB_TYPES(ocsp, fr_curl_io_request_t)
FR_SLAB_FUNCS(ocsp, fr_curl_io_request_t)

#define REST_BODY_ALLOC_CHUNK		1024

typedef enum {
	WRITE_STATE_INIT = 0,
	WRITE_STATE_PARSE_HEADERS,
	WRITE_STATE_PARSE_CONTENT,
	WRITE_STATE_DISCARD,
} write_state_t;

typedef enum {
	OCSP_STATUS_FAILED	= 0,
	OCSP_STATUS_OK		= 1,
	OCSP_STATUS_SKIPPED	= 2,
} ocsp_status_t;

/*
 *	Curl inbound data context (passed to CURLOPT_WRITEFUNCTION and
 *	CURLOPT_HEADERFUNCTION as CURLOPT_WRITEDATA and CURLOPT_HEADERDATA)
 */
typedef struct {
	rlm_ocsp_t const	*inst;		//!< Module instance.
	request_t		*request;	//!< Current request.
	write_state_t		state;		//!< Decoder state.

	char 			*buffer;	//!< Raw incoming HTTP data.
	size_t		 	alloc;		//!< Space allocated for buffer.
	size_t		 	used;		//!< Space used in buffer.

	int		 	code;		//!< HTTP Status Code.
} rlm_ocsp_response_t;


typedef struct {
	struct curl_slist	*headers;	//!< Any HTTP headers which will be sent with the
						//!< request.

	char			*body;		//!< Pointer to the buffer which contains body data

	rlm_ocsp_response_t	response;	//!< Response context data.
} rlm_ocsp_curl_context_t;

static conf_parser_t module_config[] = {
	{ FR_CONF_OFFSET("override_cert_url", rlm_ocsp_t, override_url), .dflt = "no" },
	{ FR_CONF_OFFSET("url", rlm_ocsp_t, url) },
	{ FR_CONF_OFFSET("use_nonce", rlm_ocsp_t, use_nonce), .dflt = "yes" },
	{ FR_CONF_OFFSET("softfail", rlm_ocsp_t, softfail), .dflt = "no" },
	{ FR_CONF_OFFSET("leeway", rlm_ocsp_t, leeway), .dflt = "300" },
	{ FR_CONF_OFFSET("max_age", rlm_ocsp_t, max_age), .dflt = "-1" },
	{ FR_CONF_OFFSET("verifycert", rlm_ocsp_t, verifycert), .dflt = "yes" },
	{ FR_CONF_OFFSET_FLAGS("ca_path", CONF_FLAG_FILE_READABLE, rlm_ocsp_t, ca_path) },
	{ FR_CONF_OFFSET_FLAGS("ca_file", CONF_FLAG_FILE_READABLE, rlm_ocsp_t, ca_file) },
	{ FR_CONF_OFFSET("max_body_in", rlm_ocsp_t, max_body_in) },
	{ FR_CONF_OFFSET_SUBSECTION("connection", 0, rlm_ocsp_t, conn_config, fr_curl_conn_config) },

	CONF_PARSER_TERMINATOR
};

typedef struct {
	fr_value_box_t		certuri;		//!< Certificate provided OCSP endpoint
	fr_value_box_t		certid;			//!< The certificate ID being checked.
} rlm_ocsp_env_t;

static fr_dict_t const *dict_freeradius;

extern fr_dict_autoload_t rlm_ocsp_dict[];
fr_dict_autoload_t rlm_ocsp_dict[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	DICT_AUTOLOAD_TERMINATOR
};

static fr_dict_attr_t const *attr_tls_ocsp_cert_valid;
static fr_dict_attr_t const *attr_tls_ocsp_next_update;

extern fr_dict_attr_autoload_t rlm_ocsp_dict_attr[];
fr_dict_attr_autoload_t rlm_ocsp_dict_attr[] = {
	{ .out = &attr_tls_ocsp_cert_valid, .name = "TLS-OCSP-Cert-Valid", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	{ .out = &attr_tls_ocsp_next_update, .name = "TLS-OCSP-Next-Update", .type = FR_TYPE_UINT32, .dict = &dict_freeradius },
	DICT_AUTOLOAD_TERMINATOR
};

#ifdef WITH_TLS
typedef struct {
	ocsp_slab_list_t	*slab;
	fr_curl_handle_t	*mhandle;
	X509_STORE		*store;
} rlm_ocsp_thread_t;

typedef struct {
	OCSP_CERTID		*cert_id;
	OCSP_REQUEST		*req;
	uint8_t			*reqasn1;
	int			req_size;
	fr_curl_io_request_t	*handle;
} rlm_ocsp_rctx_t;

static const call_env_method_t ocsp_env = {
	FR_CALL_ENV_METHOD_OUT(rlm_ocsp_env_t),
	.env = (call_env_parser_t[]){
		{ FR_CALL_ENV_OFFSET("certuri", FR_TYPE_STRING, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_SINGLE | CALL_ENV_FLAG_NULLABLE, rlm_ocsp_env_t, certuri),
					 .pair.dflt = "session-state.TLS-Certificate.OCSP-Uri", .pair.dflt_quote = T_BARE_WORD },
		{ FR_CALL_ENV_OFFSET("certid", FR_TYPE_OCTETS, CALL_ENV_FLAG_ATTRIBUTE | CALL_ENV_FLAG_REQUIRED | CALL_ENV_FLAG_SINGLE, rlm_ocsp_env_t, certid),
					 .pair.dflt = "session-state.TLS-Certificate.OCSP-Cert-Id", .pair.dflt_quote = T_BARE_WORD },
		CALL_ENV_TERMINATOR
	},
};

/** Processes incoming HTTP header data from libcurl.
 *
 * Processes the status line, and Content-Type headers from the incoming HTTP
 * response.
 *
 * Matches prototype for CURLOPT_HEADERFUNCTION, and will be called directly
 * by libcurl.
 *
 * A simplified version of the equivalent function in modules/rlm_rest/rest.c
 *
 * @param[in] in	Char buffer where inbound header data is written.
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_ocsp_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t ocsp_response_header(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_ocsp_response_t	*ctx = userdata;
	request_t		*request = ctx->request; /* Used by RDEBUG */

	char const		*start = (char *)in, *p = start, *end = p + (size * nmemb);
	char const		*q;
	size_t			len;

	if (((end - p) == 2) && ((p[0] == '\r') && (p[1] == '\n'))) {
		if (ctx->code == 100) {
			RDEBUG2("Continuing...");
			ctx->state = WRITE_STATE_INIT;
		}

		return (end - start);
	}

	switch (ctx->state) {
	case WRITE_STATE_INIT:
		RDEBUG2("Processing response header");

		/*
		 *  HTTP/<version> <reason_code>[ <reason_phrase>]\r\n
		 *
		 *  "HTTP/1.1 " (9) + "100" (3) + "\r\n" (2) = 14
		 *  "HTTP/2 " (7) + "100" (3) + "\r\n" (2) = 12
		 */
		if ((end - p) < 12) {
			REDEBUG("Malformed HTTP header: Status line too short");
		malformed:
			REDEBUG("Received %zu bytes of invalid header data: %pV",
				(end - start), fr_box_strvalue_len(in, (end - start)));
			ctx->code = 0;

			return (end - start);
		}

		if (strncasecmp("HTTP/", p, 5) != 0) {
			REDEBUG("Malformed HTTP header: Missing HTTP version");
			goto malformed;
		}
		p += 5;

		/*
		 *  Skip the version field, next space should mark start of reason_code.
		 */
		q = memchr(p, ' ', (end - p));
		if (!q) {
			REDEBUG("Malformed HTTP header: Missing reason code");
			goto malformed;
		}

		p = q;

		/*
		 *  Process reason_code.
		 *
		 *  " 100" (4) + "\r\n" (2) = 6
		 */
		if ((end - p) < 6) {
			REDEBUG("Malformed HTTP header: Reason code too short");
			goto malformed;
		}
		p++;

		/*
		 *  "xxx( |\r)" status code and terminator.
		 */
		if (!isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2]) || !((p[3] == ' ') || (p[3] == '\r'))) {
			REDEBUG("Malformed HTTP header: Reason code malformed. "
				"Expected three digits then space or end of header, got \"%pV\"",
				fr_box_strvalue_len(p, 4));
			goto malformed;
		}

		/*
		 *  Convert status code into an integer value.  strtoul needs
		 *  a writable endptr, so shadow q in a local scope.
		 */
		{
			char *qq = NULL;

			ctx->code = (int)strtoul(p, &qq, 10);
			fr_assert(qq == (p + 3));	/* We check this above */
			p = qq;
		}

		/*
		 *  Process reason_phrase (if present).
		 */
		RINDENT();
		if (*p == ' ') {
			p++;
			q = memchr(p, '\r', (end - p));
			if (!q) goto malformed;
			RDEBUG2("Status : %i (%pV)", ctx->code, fr_box_strvalue_len(p, q - p));
		} else {
			RDEBUG2("Status : %i", ctx->code);
		}
		REXDENT();

		ctx->state = WRITE_STATE_PARSE_HEADERS;

		break;

	case WRITE_STATE_PARSE_HEADERS:
		if (((end - p) >= 14) &&
		    (strncasecmp("Content-Type: ", p, 14) == 0)) {
			p += 14;

			/*
			 *  Check to see if there's a parameter separator.
			 */
			q = memchr(p, ';', (end - p));

			/*
			 *  If there's not, find the end of this header.
			 */
			if (!q) q = memchr(p, '\r', (end - p));

			len = (size_t)(!q ? (end - p) : (q - p));
			if (strncmp(p, "application/ocsp-response", len) != 0) {
				REDEBUG("Expected Content-Type application/ocsp-response, got %pV", fr_box_strvalue_len(p, len));
			}
		}
		break;

	default:
		break;
	}

	return (end - start);
}

/** Processes incoming HTTP body data from libcurl.
 *
 * Writes incoming body data to an intermediary buffer for later parsing
 *
 * @param[in] in	Char buffer where inbound header data is written
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_ocsp_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t ocsp_response_body(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_ocsp_response_t	*ctx = userdata;
	request_t		*request = ctx->request; /* Used by RDEBUG */

	char const		*start = in, *p = start, *end = p + (size * nmemb);
	char			*out_p;
	size_t			needed;

	if (start == end) return 0; 	/* Nothing to process */

	/*
	 *  Any post processing of headers should go here...
	 */
	if (ctx->state == WRITE_STATE_PARSE_HEADERS) ctx->state = WRITE_STATE_PARSE_CONTENT;

	if ((ctx->inst->max_body_in > 0) && ((ctx->used + (end - p)) > ctx->inst->max_body_in)) {
		REDEBUG("Incoming data (%zu bytes) exceeds max_body_in (%"PRIu64" bytes).",
			ctx->used + (end - p), ctx->inst->max_body_in);
		TALLOC_FREE(ctx->buffer);
		goto finish;
	}

	needed = ROUND_UP(ctx->used + (end - p), REST_BODY_ALLOC_CHUNK);
	if (needed > ctx->alloc) {
		MEM(ctx->buffer = talloc_bstr_realloc(NULL, ctx->buffer, needed));
		ctx->alloc = needed;
	}

	out_p = ctx->buffer + ctx->used;
	memcpy(out_p, p, (end - p));
	out_p += (end - p);
	*out_p = '\0';
	ctx->used += (end - p);

finish:
	return (end - start);
}

static int ocsp_request_config(module_ctx_t const *mctx, request_t *request, fr_curl_io_request_t *randle,
			       uint8_t *body, size_t body_len, char const *uri)
{
	rlm_ocsp_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ocsp_t);
	rlm_ocsp_curl_context_t	*uctx = talloc_get_type_abort(randle->uctx, rlm_ocsp_curl_context_t);
	fr_time_delta_t		timeout = inst->conn_config.connect_timeout;
	struct curl_slist	*headers;

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, uri);
#if CURL_AT_LEAST_VERSION(7,85,0)
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS_STR, "http,https");
#else
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_NOSIGNAL, 1L);

	RDEBUG3("Connect timeout is %pVs", fr_box_time_delta(timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(timeout));

	uctx->body = (char *)body;
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_POST, 1L);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_POSTFIELDS, uctx->body);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_POSTFIELDSIZE, body_len);

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HEADERFUNCTION, ocsp_response_header);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HEADERDATA, &uctx->response);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEFUNCTION, ocsp_response_body);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEDATA, &uctx->response);

	headers = curl_slist_append(uctx->headers, "Content-Type: application/ocsp-request");
	if (unlikely(!headers)) {
		REDEBUG("Failed to add Content-Type header");
		goto error;
	}
	uctx->headers = headers;

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, uctx->headers);

	TALLOC_FREE(uctx->response.buffer);
	uctx->response = (rlm_ocsp_response_t) {
		.inst = inst,
		.request = request,
		.state = WRITE_STATE_INIT
	};

	return 0;

error:
	return -1;
}

static int rlm_ocsp_rctx_free(rlm_ocsp_rctx_t *to_free)
{
	OCSP_REQUEST_free(to_free->req);
	OPENSSL_free(to_free->reqasn1);
	if (to_free->handle) ocsp_slab_release(to_free->handle);
	return 0;
}

static unlang_action_t mod_ocsp_resume(unlang_result_t *p_result, module_ctx_t const *mctx, request_t *request)
{
	rlm_ocsp_t const	*inst = talloc_get_type_abort_const(mctx->mi->data, rlm_ocsp_t);
	rlm_ocsp_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_ocsp_thread_t);
	rlm_ocsp_rctx_t		*rctx = talloc_get_type_abort(mctx->rctx, rlm_ocsp_rctx_t);
	fr_curl_io_request_t	*handle = rctx->handle;
	rlm_ocsp_curl_context_t	*uctx = talloc_get_type_abort(handle->uctx, rlm_ocsp_curl_context_t);
	BIO			*ssl_log = NULL;
	OCSP_RESPONSE		*resp = NULL;
	OCSP_BASICRESP		*bresp = NULL;
	uint8_t const		*buffer = (uint8_t *)uctx->response.buffer;
	int			status, reason;
	ASN1_GENERALIZEDTIME	*rev, *this_update, *next_update;
	ocsp_status_t		ocsp_status = OCSP_STATUS_FAILED;
	fr_pair_t		*vp;
	rlm_rcode_t		rcode = RLM_MODULE_FAIL;

	if (uctx->response.code != 200) {
		RERROR("Invalid HTTP response code");
		ocsp_status = OCSP_STATUS_SKIPPED;
		goto finish;
	}

	resp = d2i_OCSP_RESPONSE(NULL, &buffer, uctx->response.used);
	if (!resp) {
		RPERROR("Failed parsing response body as an OCSP response");
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
	if (inst->use_nonce && OCSP_check_nonce(rctx->req, bresp) != 1) {
		REDEBUG("Response has wrong nonce value");
		goto finish;
	}

	if (inst->verifycert) {
		if (OCSP_basic_verify(bresp, NULL, thread->store, 0) != 1){
			REDEBUG("Couldn't verify OCSP basic response");
			goto finish;
		}
        }

	/*	Verify OCSP cert status */
	if (!OCSP_resp_find_status(bresp, rctx->cert_id, (int *)&status, &reason, &rev, &this_update, &next_update)) {
		REDEBUG("No Status found");
		goto finish;
	}

	/*
	 *	Here we check the fields 'thisUpdate' and 'nextUpdate'
	 *	from the OCSP response against the server's time.
	 *
	 *	leewaysec is the number of seconds +- between the current
	 *	time and this_update.
	 */
	if (!OCSP_check_validity(this_update, next_update, inst->leeway, inst->max_age)) {
		/*
		 *	We want this to show up in the global log
		 *	so someone will fix it...
		 */
		RATE_LIMIT_GLOBAL(RERROR, "Delta +/- between OCSP response time and our time is greater than %i "
				  "seconds.  Check servers are synchronised to a common time source",
				  inst->leeway);
		goto finish;
	}

	ssl_log = BIO_new(BIO_s_mem());
	if (RDEBUG_ENABLED) {
		RDEBUG2("OCSP response valid from:");
		ASN1_GENERALIZEDTIME_print(ssl_log, this_update);
		RINDENT();
		FR_OPENSSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
		REXDENT();

		if (next_update) {
			RDEBUG2("New information available at:");
			ASN1_GENERALIZEDTIME_print(ssl_log, next_update);
			RINDENT();
			FR_OPENSSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
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

		now = fr_time();

		if (fr_tls_utils_asn1time_to_epoch(&next, next_update) < 0) {
			RPEDEBUG("Failed parsing next_update time");
			ocsp_status = OCSP_STATUS_SKIPPED;
			goto finish;
		}
		if (fr_time_to_sec(now) < next){
			RDEBUG2("Adding OCSP TTL attribute");

			MEM(pair_update_request(&vp, attr_tls_ocsp_next_update) >= 0);
			vp->vp_uint32 = next - fr_time_to_sec(now);
			RINDENT();
			RDEBUG2("%pP", vp);
			REXDENT();
		} else {
			RDEBUG2("Update time is in the past.  Not adding TLS-OCSP-Next-Update");
		}
	} else {
		RDEBUG2("Update time not provided.  Not adding TLS-OCSP-Next-Update");
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
		FR_OPENSSL_DRAIN_LOG_QUEUE(RDEBUG, "", ssl_log);
		if (RDEBUG_ENABLED2) {
			RDEBUG2("Revocation time:");
			ASN1_GENERALIZEDTIME_print(ssl_log, rev);
			RINDENT();
			FR_OPENSSL_DRAIN_LOG_QUEUE(RDEBUG2, "", ssl_log);
			REXDENT();
		}
		break;
	}

finish:
	switch (ocsp_status) {
	case OCSP_STATUS_OK:
		RDEBUG2("Certificate is valid");

		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = FR_TLS_OCSP_CERT_VALID_VALUE_YES;
		rcode = RLM_MODULE_OK;

		break;

	case OCSP_STATUS_SKIPPED:
		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = FR_TLS_OCSP_CERT_VALID_VALUE_SKIPPED;
		if (inst->softfail) {
			RWDEBUG("Unable to check certificate: "
				"TLS clients presenting revoked certificates may be granted access");
			rcode = RLM_MODULE_NOOP;

			/* Remove OpenSSL errors from queue or handshake will fail */
			while (ERR_get_error());	/* Not always debugging */
		} else {
			REDEBUG("Unable to check certificate, failing");
		}
		break;

	default:
		MEM(pair_update_request(&vp, attr_tls_ocsp_cert_valid) >= 0);
		vp->vp_uint32 = FR_TLS_OCSP_CERT_VALID_VALUE_NO;
		REDEBUG("Failed to validate certificate");
		break;
	}

	OCSP_BASICRESP_free(bresp);
	OCSP_RESPONSE_free(resp);
	BIO_free(ssl_log);

	RETURN_UNLANG_RCODE(rcode);
}

static unlang_action_t CC_HINT(nonnull) mod_ocsp(unlang_result_t *p_result, module_ctx_t const *mctx,
						 request_t *request)
{
	rlm_ocsp_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ocsp_t);
	rlm_ocsp_env_t		*env = talloc_get_type_abort(mctx->env_data, rlm_ocsp_env_t);
	rlm_ocsp_thread_t	*thread = talloc_get_type_abort(mctx->thread, rlm_ocsp_thread_t);
	char const		*uri;
	fr_pair_t		*vp;
	rlm_rcode_t		rcode = RLM_MODULE_FAIL;
	rlm_ocsp_rctx_t		*rctx;
	uint8_t const		*certid;

	/*
	 *	Check for control.TLS-OCSP-Cert-Valid retrieved from cache.
	 */
	vp = fr_pair_find_by_da(&request->control_pairs, NULL, attr_tls_ocsp_cert_valid);
	if (vp) switch (vp->vp_uint32) {
	case FR_TLS_OCSP_CERT_VALID_VALUE_NO:
		RDEBUG2("Found control.%s = no, forcing OCSP failure", attr_tls_ocsp_cert_valid->name);
		RETURN_UNLANG_FAIL;

	case FR_TLS_OCSP_CERT_VALID_VALUE_YES:
		RDEBUG2("Found control.%s = yes, forcing OCSP success", attr_tls_ocsp_cert_valid->name);
		RETURN_UNLANG_OK;

	case FR_TLS_OCSP_CERT_VALID_VALUE_SKIPPED:
		RDEBUG2("Found control.%s = skipped, skipping OCSP check", attr_tls_ocsp_cert_valid->name);
		if (inst->softfail) RETURN_UNLANG_NOOP;
		RETURN_UNLANG_FAIL;

	case FR_TLS_OCSP_CERT_VALID_VALUE_UNKNOWN:
	default:
		break;
	}

	MEM(rctx = talloc_zero(unlang_interpret_frame_talloc_ctx(request), rlm_ocsp_rctx_t));
	talloc_set_destructor(rctx, rlm_ocsp_rctx_free);

	certid = env->certid.vb_octets;
	rctx->cert_id = d2i_OCSP_CERTID(NULL, &certid, env->certid.vb_length);

	rctx->req = OCSP_REQUEST_new();
	OCSP_request_add0_id(rctx->req, rctx->cert_id);
	if (inst->use_nonce) OCSP_request_add1_nonce(rctx->req, NULL, 8);

	/* Get OCSP responder URL */
	if (inst->override_url) {
	use_url:
		uri = inst->url;
	} else {
		if (env->certuri.type == FR_TYPE_NULL) {
			if (inst->url) {
				RWDEBUG("No OCSP URL in certificate, falling back to configured URL");
				goto use_url;
			}
			RWDEBUG("No OCSP URL in certificate.  Not doing OCSP");
			goto finish;
		}
		uri = env->certuri.vb_strvalue;
	}

	RDEBUG2("Using responder URL \"%s\"", uri);

	rctx->req_size = ASN1_item_i2d((ASN1_VALUE *)rctx->req, &rctx->reqasn1, ASN1_ITEM_rptr(OCSP_REQUEST));

	rctx->handle = ocsp_slab_reserve(thread->slab);

	if (ocsp_request_config(mctx, request, rctx->handle, rctx->reqasn1, rctx->req_size, uri) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	if (fr_curl_io_request_enqueue(thread->mhandle, request, rctx->handle) < 0) {
		rcode = RLM_MODULE_FAIL;
		goto finish;
	}

	rcode = RLM_MODULE_NOT_SET;

finish:

	if (rcode == RLM_MODULE_NOT_SET) return unlang_module_yield(request, mod_ocsp_resume, NULL, 0, rctx);

	RETURN_UNLANG_RCODE(rcode);
}

static int _ocsp_request_cleanup(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	rlm_ocsp_curl_context_t *ctx = talloc_get_type_abort(randle->uctx, rlm_ocsp_curl_context_t);

	if (randle->candle) curl_easy_reset(randle->candle);

	if (ctx->headers != NULL) {
		curl_slist_free_all(ctx->headers);
		ctx->headers = NULL;
	}

	TALLOC_FREE(ctx->response.buffer);

	randle->request = NULL;
	return 0;
}

static int _mod_conn_free(fr_curl_io_request_t *randle)
{
	curl_easy_cleanup(randle->candle);
	return 0;
}

static int ocsp_conn_alloc(fr_curl_io_request_t *randle, UNUSED void *uctx)
{
	rlm_ocsp_curl_context_t	*curl_ctx;

	randle->candle = curl_easy_init();
	if (unlikely(!randle->candle)) {
		fr_strerror_printf("Unable to initialise CURL handle");
		return -1;
	}

	MEM(curl_ctx = talloc_zero(randle, rlm_ocsp_curl_context_t));

	randle->uctx = curl_ctx;
	talloc_set_destructor(randle, _mod_conn_free);

	ocsp_slab_element_set_destructor(randle, _ocsp_request_cleanup, NULL);

	return 0;
}

/** Create a thread specific multihandle
 *
 * Easy handles representing requests are added to the curl multihandle
 * with the multihandle used for mux/demux.
 *
 * @param[in] mctx	Thread instantiation data.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int mod_thread_instantiate(module_thread_inst_ctx_t const *mctx)
{
	rlm_ocsp_t const	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ocsp_t);
	rlm_ocsp_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_ocsp_thread_t);
	fr_curl_handle_t	*mhandle;

	if (!(t->slab = ocsp_slab_list_alloc(t, mctx->el, &inst->conn_config.reuse,
					     ocsp_conn_alloc, NULL, NULL, false, true))) {
		ERROR("Connection handle pool instantiation failed");
		return -1;
	}

	mhandle = fr_curl_io_init(t, mctx->el, false);
	if (!mhandle) return -1;

	t->mhandle = mhandle;

	if (!inst->verifycert) return 0;

	t->store = X509_STORE_new();
	if (!t->store) return -1;
	if (!X509_STORE_load_locations(t->store, inst->ca_file, inst->ca_path)) {
		cf_log_err(mctx->mi->conf, "Failed reading Trusted root CA file \"%s\" and path \"%s\"",
			   inst->ca_file, inst->ca_path);
		return -1;
	}

	return 0;
}

/*
 *	Close the thread and free the memory
 */
static int mod_thread_detach(module_thread_inst_ctx_t const *mctx)
{
	rlm_ocsp_thread_t	*t = talloc_get_type_abort(mctx->thread, rlm_ocsp_thread_t);

	talloc_free(t->mhandle);
	talloc_free(t->slab);
	if (t->store) X509_STORE_free(t->store);
	return 0;
}
#endif

/**	Instantiate the module
 *
 */
static int mod_instantiate(module_inst_ctx_t const *mctx)
{
#ifdef WITH_TLS
	rlm_ocsp_t	*inst = talloc_get_type_abort(mctx->mi->data, rlm_ocsp_t);

	if (!inst->verifycert) return 0;

	if (!inst->ca_file && !inst->ca_path) {
		cf_log_err(mctx->mi->conf, "ca_file or ca_path required when verifycert = yes");
		return -1;
	}

	return 0;
#else
	cf_log_err(mctx->mi->conf, "rlm_ocsp requires OpenSSL");
	return -1;
#endif
}

extern module_rlm_t rlm_ocsp;
module_rlm_t rlm_ocsp = {
	.common = {
		.magic			= MODULE_MAGIC_INIT,
		.inst_size		= sizeof(rlm_ocsp_t),
		.name			= "ocsp",
		.config			= module_config,
		.instantiate		= mod_instantiate,
#ifdef WITH_TLS
		MODULE_THREAD_INST(rlm_ocsp_thread_t),
		.thread_instantiate	= mod_thread_instantiate,
		.thread_detach		= mod_thread_detach,
#endif
	},
#ifdef WITH_TLS
	.method_group = {
		.bindings = (module_method_binding_t[]){
			{ .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_ocsp, .method_env = &ocsp_env },
			MODULE_BINDING_TERMINATOR
		}
	}
#endif
};
