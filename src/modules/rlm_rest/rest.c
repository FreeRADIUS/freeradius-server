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
 * @brief Functions and datatypes for the REST (HTTP) transport.
 * @file rest.c
 *
 * @copyright 2012-2021 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */


RCSID("$Id$")

#define LOG_PREFIX mctx->inst->name

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/log.h>
#include <freeradius-devel/server/pool.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/util/value.h>

#include "rest.h"

/** Table of encoder/decoder support.
 *
 * Indexes in this table match the http_body_type_t enum, and should be
 * updated if additional enum values are added.
 *
 * @see http_body_type_t
 */
const http_body_type_t http_body_type_supported[REST_HTTP_BODY_NUM_ENTRIES] = {
	REST_HTTP_BODY_UNKNOWN,			// REST_HTTP_BODY_UNKNOWN
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_UNSUPPORTED
	REST_HTTP_BODY_UNSUPPORTED,  		// REST_HTTP_BODY_UNAVAILABLE
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_INVALID
	REST_HTTP_BODY_NONE,			// REST_HTTP_BODY_NONE
	REST_HTTP_BODY_CUSTOM_XLAT,		// REST_HTTP_BODY_CUSTOM_XLAT
	REST_HTTP_BODY_CUSTOM_LITERAL,		// REST_HTTP_BODY_CUSTOM_LITERAL
	REST_HTTP_BODY_POST,			// REST_HTTP_BODY_POST
#ifdef HAVE_JSON
	REST_HTTP_BODY_JSON,			// REST_HTTP_BODY_JSON
#else
	REST_HTTP_BODY_UNAVAILABLE,
#endif
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_XML
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_YAML
	REST_HTTP_BODY_INVALID,			// REST_HTTP_BODY_HTML
	REST_HTTP_BODY_PLAIN			// REST_HTTP_BODY_PLAIN
};

/*
 *	Lib CURL doesn't define symbols for unsupported auth methods
 */
#ifndef CURLOPT_TLSAUTH_SRP
#  define CURLOPT_TLSAUTH_SRP	0
#endif
#ifndef CURLAUTH_BASIC
#  define CURLAUTH_BASIC	0
#endif
#ifndef CURLAUTH_DIGEST
#  define CURLAUTH_DIGEST	0
#endif
#ifndef CURLAUTH_DIGEST_IE
#  define CURLAUTH_DIGEST_IE	0
#endif
#ifndef CURLAUTH_GSSNEGOTIATE
#  define CURLAUTH_GSSNEGOTIATE	0
#endif
#ifndef CURLAUTH_NTLM
#  define CURLAUTH_NTLM		0
#endif
#ifndef CURLAUTH_NTLM_WB
#  define CURLAUTH_NTLM_WB	0
#endif

/*
 *  CURL headers do:
 *
 *  #define curl_easy_setopt(handle,opt,param) curl_easy_setopt(handle,opt,param)
 */
const unsigned long http_curl_auth[REST_HTTP_AUTH_NUM_ENTRIES] = {
	[REST_HTTP_AUTH_UNKNOWN]			= 0,
	[REST_HTTP_AUTH_NONE]				= 0,
	[REST_HTTP_AUTH_TLS_SRP]			= CURLOPT_TLSAUTH_SRP,
	[REST_HTTP_AUTH_BASIC]				= CURLAUTH_BASIC,
	[REST_HTTP_AUTH_DIGEST]				= CURLAUTH_DIGEST,
	[REST_HTTP_AUTH_DIGEST_IE]			= CURLAUTH_DIGEST_IE,
	[REST_HTTP_AUTH_GSSNEGOTIATE]			= CURLAUTH_GSSNEGOTIATE,
	[REST_HTTP_AUTH_NTLM]				= CURLAUTH_NTLM,
	[REST_HTTP_AUTH_NTLM_WB]			= CURLAUTH_NTLM_WB,
	[REST_HTTP_AUTH_ANY]				= CURLAUTH_ANY,
	[REST_HTTP_AUTH_ANY_SAFE]			= CURLAUTH_ANYSAFE
};

/** Conversion table for method config values.
 *
 * HTTP verb strings for http_method_t enum values. Used by libcurl in the
 * status line of the outgoing HTTP header, by rest_response_header for decoding
 * incoming HTTP responses, and by the configuration parser.
 *
 * @note must be kept in sync with http_method_t enum.
 *
 * @see http_method_t
 * @see fr_table_value_by_str
 * @see fr_table_str_by_value
 */
fr_table_num_sorted_t const http_method_table[] = {
	{ L("DELETE"),					REST_HTTP_METHOD_DELETE		},
	{ L("GET"),					REST_HTTP_METHOD_GET		},
	{ L("PATCH"),					REST_HTTP_METHOD_PATCH		},
	{ L("POST"),					REST_HTTP_METHOD_POST		},
	{ L("PUT"),					REST_HTTP_METHOD_PUT		},
	{ L("UNKNOWN"),					REST_HTTP_METHOD_UNKNOWN	}
};
size_t http_method_table_len = NUM_ELEMENTS(http_method_table);

/** Conversion table for type config values.
 *
 * Textual names for http_body_type_t enum values, used by the
 * configuration parser.
 *
 * @see http_body_Type_t
 * @see fr_table_value_by_str
 * @see fr_table_str_by_value
 */
fr_table_num_sorted_t const http_body_type_table[] = {
	{ L("html"),					REST_HTTP_BODY_HTML		},
	{ L("invalid"),					REST_HTTP_BODY_INVALID		},
	{ L("json"),					REST_HTTP_BODY_JSON		},
	{ L("none"),					REST_HTTP_BODY_NONE		},
	{ L("plain"),					REST_HTTP_BODY_PLAIN		},
	{ L("post"),					REST_HTTP_BODY_POST		},
	{ L("unavailable"),				REST_HTTP_BODY_UNAVAILABLE	},
	{ L("unknown"),					REST_HTTP_BODY_UNKNOWN		},
	{ L("unsupported"),				REST_HTTP_BODY_UNSUPPORTED	},
	{ L("xml"),					REST_HTTP_BODY_XML		},
	{ L("yaml"),					REST_HTTP_BODY_YAML		}
};
size_t http_body_type_table_len = NUM_ELEMENTS(http_body_type_table);

fr_table_num_sorted_t const http_auth_table[] = {
	{ L("any"),					REST_HTTP_AUTH_ANY		},
	{ L("basic"),					REST_HTTP_AUTH_BASIC		},
	{ L("digest"),					REST_HTTP_AUTH_DIGEST		},
	{ L("digest-ie"),				REST_HTTP_AUTH_DIGEST_IE	},
	{ L("gss-negotiate"),				REST_HTTP_AUTH_GSSNEGOTIATE	},
	{ L("none"),					REST_HTTP_AUTH_NONE		},
	{ L("ntlm"),					REST_HTTP_AUTH_NTLM		},
	{ L("ntlm-winbind"),				REST_HTTP_AUTH_NTLM_WB		},
	{ L("safe"),					REST_HTTP_AUTH_ANY_SAFE		},
	{ L("srp"),					REST_HTTP_AUTH_TLS_SRP		}
};
size_t http_auth_table_len = NUM_ELEMENTS(http_auth_table);

/** Conversion table for "Content-Type" header values.
 *
 * Used by rest_response_header for parsing incoming headers.
 *
 * Values we expect to see in the 'Content-Type:' header of the incoming
 * response.
 *
 * Some data types (like YAML) do no have standard MIME types defined,
 * so multiple types, are listed here.
 *
 * @see http_body_Type_t
 * @see fr_table_value_by_str
 * @see fr_table_str_by_value
 */
fr_table_num_sorted_t const http_content_type_table[] = {
	{ L("application/json"),			REST_HTTP_BODY_JSON		},
	{ L("application/x-www-form-urlencoded"),	REST_HTTP_BODY_POST		},
	{ L("application/x-yaml"),			REST_HTTP_BODY_YAML		},
	{ L("application/yaml"),			REST_HTTP_BODY_YAML		},
	{ L("text/html"),				REST_HTTP_BODY_HTML		},
	{ L("text/plain"),				REST_HTTP_BODY_PLAIN		},
	{ L("text/x-yaml"),				REST_HTTP_BODY_YAML		},
	{ L("text/xml"),				REST_HTTP_BODY_XML		},
	{ L("text/yaml"),				REST_HTTP_BODY_YAML		}
};
size_t http_content_type_table_len = NUM_ELEMENTS(http_content_type_table);

/*
 *	Encoder specific structures.
 *	@todo split encoders/decoders into submodules.
 */
typedef struct {
	char const	*start;	//!< Start of the buffer.
	char const	*p;	//!< how much text we've sent so far.
	size_t		len;	//!< Length of data
} rest_custom_data_t;

#ifdef HAVE_JSON
/** Flags to control the conversion of JSON values to fr_pair_ts.
 *
 * These fields are set when parsing the expanded format for value pairs in
 * JSON, and control how json_pair_alloc_leaf and json_pair_alloc convert the JSON
 * value, and move the new fr_pair_t into an attribute list.
 *
 * @see json_pair_alloc
 * @see json_pair_alloc_leaf
 */
typedef struct {
	int do_xlat;		//!< If true value will be expanded with xlat.
	int is_json;		//!< If true value will be inserted as raw JSON
				// (multiple values not supported).
	fr_token_t op;		//!< The operator that determines how the new VP
				// is processed. @see fr_tokens_table
} json_flags_t;
#endif

/** Frees a libcurl handle, and any additional memory used by context data.
 *
 * @param[in] randle fr_curl_io_request_t to close and free.
 * @return returns true.
 */
static int _mod_conn_free(fr_curl_io_request_t *randle)
{
	curl_easy_cleanup(randle->candle);

	return 0;
}

/** Creates a new connection handle for use by the FR connection API.
 *
 * Matches the fr_pool_connection_create_t function prototype, is passed to
 * fr_pool_init, and called when a new connection is required by the
 * connection pool API.
 *
 * Creates an instances of fr_curl_io_request_t, and rlm_rest_curl_context_t
 * which hold the context data required for generating requests and parsing
 * responses.
 *
 * If instance->connect_uri is not NULL libcurl will attempt to open a
 * TCP socket to the server specified in the URI. This is done so that when the
 * socket is first used, there will already be a cached TCP connection to the
 * REST server associated with the curl handle.
 *
 * @see fr_pool_init
 * @see fr_pool_connection_create_t
 * @see connection.c
 */
void *rest_mod_conn_create(TALLOC_CTX *ctx, void *instance, UNUSED fr_time_delta_t timeout)
{
	rlm_rest_t const	*inst = talloc_get_type_abort_const(instance, rlm_rest_t);

	fr_curl_io_request_t	*randle = NULL;
	rlm_rest_curl_context_t	*curl_ctx = NULL;

	/*
	 *  Allocate memory for the connection handle abstraction.
	 */
	randle = fr_curl_io_request_alloc(ctx);
	if (!randle) return NULL;

	curl_ctx = talloc_zero(randle, rlm_rest_curl_context_t);

	curl_ctx->headers = NULL; /* CURL needs this to be NULL */
	curl_ctx->request.instance = inst;
	curl_ctx->response.instance = inst;

	randle->uctx = curl_ctx;
	talloc_set_destructor(randle, _mod_conn_free);

	return randle;
}

/** Copies a pre-expanded xlat string to the output buffer
 *
 * @param[out] out	Char buffer to write encoded data to.
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_rest_request_t to keep encoding state between calls.
 * @return
 *	- Length of data (including NULL) written to ptr.
 *	- 0 if no more data to write.
 */
static size_t rest_encode_custom(void *out, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_request_t	*ctx = userdata;
	rest_custom_data_t	*data = ctx->encoder;

	size_t			freespace = (size * nmemb) - 1;
	size_t			len;
	size_t			to_copy;

	/*
	 *	Special case for empty body
	 */
	if (data->len == 0) return 0;

	/*
	 *	If len > 0 then we must have these set.
	 */
	fr_assert(data->start);
	fr_assert(data->p);

	to_copy = data->len - (data->p - data->start);
	len = to_copy > freespace ? freespace : to_copy;
	if (len == 0) return 0;

	memcpy(out, data->p, len);
	data->p += len;

	return len;
}

/** Encodes fr_pair_t linked list in POST format
 *
 * This is a stream function matching the rest_read_t prototype. Multiple
 * successive calls will return additional encoded fr_pair_ts.
 * Only complete attribute headers @verbatim '<name>=' @endverbatim and values
 * will be written to the ptr buffer.
 *
 * POST request format is:
 * @verbatim <attribute0>=<value0>&<attribute1>=<value1>&<attributeN>=<valueN>@endverbatim
 *
 * All attributes and values are url encoded. There is currently no support for
 * nested attributes, or attribute qualifiers.
 *
 * Nested attributes may be added in the future using
 * @verbatim <attribute-outer>:<attribute-inner>@endverbatim
 * to denotate nesting.
 *
 * Requires libcurl for url encoding.
 *
 * @see rest_decode_post
 *
 * @param[out] out	Char buffer to write encoded data to.
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_rest_request_t to keep encoding state between calls.
 * @return
 *	- Length of data (including NULL) written to ptr.
 *	- 0 if no more data to write.
 */
static size_t rest_encode_post(void *out, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_request_t	*ctx = userdata;
	request_t			*request = ctx->request; /* Used by RDEBUG */
	fr_pair_t		*vp;

	size_t			len = 0;
	ssize_t			slen;
	size_t			freespace = (size * nmemb) - 1;

	char			*p = out;	/* Position in buffer */
	char			*encoded = p;	/* Position in buffer of last fully encoded attribute or value */
	char			*escaped;	/* Pointer to current URL escaped data */

	/* Allow manual chunking */
	if ((ctx->chunk) && (ctx->chunk <= freespace)) freespace = (ctx->chunk - 1);

	if (ctx->state == READ_STATE_END) return 0;

	/* Post data requires no headers */
	if (ctx->state == READ_STATE_INIT) ctx->state = READ_STATE_ATTR_BEGIN;

	while (freespace > 0) {
		vp = fr_dcursor_current(&ctx->cursor);
		if (!vp) {
			ctx->state = READ_STATE_END;

			break;
		}

		RDEBUG2("Encoding attribute \"%s\"", vp->da->name);

		if (ctx->state == READ_STATE_ATTR_BEGIN) {
			escaped = curl_escape(vp->da->name, 0);
			if (!escaped) {
				REDEBUG("Failed escaping string \"%s\"", vp->da->name);
				return 0;
			}

			len = strlen(escaped);
			if (freespace < (1 + len)) {
				curl_free(escaped);
				/*
				 *  Cleanup for error conditions
				 */
			no_space:
				*encoded = '\0';

				len = encoded - (char *)out;

				RDEBUG3("POST Data: %pV", fr_box_strvalue_len(out, len));

				/*
				 *  The buffer wasn't big enough to encode a single attribute chunk.
				 */
				if (len == 0) {
					REDEBUG("Failed encoding attribute");
				} else {
					RDEBUG3("Returning %zd bytes of POST data "
						"(buffer full or chunk exceeded)", len);
				}

				return len;
			}

			len = snprintf(p, freespace, "%s=", escaped);
			curl_free(escaped);
			p += len;
			freespace -= len;

			/*
			 *  We wrote the attribute header, record progress.
			 */
			encoded = p;
			ctx->state = READ_STATE_ATTR_CONT;
		}

		/*
		 *  Write out single attribute string.
		 */
		slen = fr_pair_print_value_quoted(&FR_SBUFF_OUT(p, freespace), vp, T_BARE_WORD);
		if (slen < 0) return 0;

		RINDENT();
		RDEBUG3("Length : %zd", (size_t)slen);
		REXDENT();
		if (slen > 0) {
			escaped = curl_escape(p, (size_t)slen);
			if (!escaped) {
				REDEBUG("Failed escaping string \"%s\"", vp->da->name);
				return 0;
			}
			len = strlen(escaped);

			if (freespace < len) {
				curl_free(escaped);
				goto no_space;
			}

			len = strlcpy(p, escaped, len + 1);

			curl_free(escaped);

			RINDENT();
			RDEBUG3("Value  : %s", p);
			REXDENT();

			p += len;
			freespace -= len;
		}

		/*
		 *  there are more attributes, insert a separator
		 */
		if (fr_dcursor_next(&ctx->cursor)) {
			if (freespace < 1) goto no_space;
			*p++ = '&';
			freespace--;
		}

		/*
		 *  We wrote one full attribute value pair, record progress.
		 */
		encoded = p;

		ctx->state = READ_STATE_ATTR_BEGIN;
	}

	*p = '\0';

	len = p - (char *)out;

	RDEBUG3("POST Data: %s", (char *)out);
	RDEBUG3("Returning %zd bytes of POST data", len);

	return len;
}

#ifdef HAVE_JSON
/** Encodes fr_pair_t linked list in JSON format
 *
 * This is a stream function matching the rest_read_t prototype. Multiple
 * successive calls will return additional encoded fr_pair_ts.
 *
 * Only complete attribute headers
 * @verbatim "<name>":{"type":"<type>","value":[' @endverbatim
 * and complete attribute values will be written to ptr.
 *
 * If an attribute occurs multiple times in the request the attribute values
 * will be concatenated into a single value array.
 *
 * JSON request format is:
@verbatim
{
	"<attribute0>":{
		"type":"<type0>",
		"value":[<value0>,<value1>,<valueN>]
	},
	"<attribute1>":{
		"type":"<type1>",
		"value":[...]
	},
	"<attributeN>":{
		"type":"<typeN>",
		"value":[...]
	},
}
@endverbatim
 *
 * @param[out] out	Char buffer to write encoded data to.
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_rest_request_t to keep encoding state between calls.
 * @return
 *	- Length of data (including NULL) written to ptr.
 *	- 0 if no more data to write.
 */
static size_t rest_encode_json(void *out, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_request_t	*ctx = userdata;
	request_t			*request = ctx->request;
	rest_custom_data_t	*data = ctx->encoder;

	size_t			freespace = (size * nmemb) - 1;		/* account for the \0 byte here */
	size_t			len;
	size_t			to_copy;
	const char		*encoded;

	fr_assert(freespace > 0);

	if (ctx->state == READ_STATE_INIT) {
		encoded = fr_json_afrom_pair_list(data, &request->request_pairs, NULL);
		if (!encoded) return -1;

		data->start = data->p = encoded;
		data->len = strlen(encoded);

		RDEBUG3("JSON Data: %s", encoded);
		RDEBUG3("Returning %zd bytes of JSON data", data->len);

		ctx->state = READ_STATE_ATTR_BEGIN;
	}

	to_copy = data->len - (data->p - data->start);
	len = to_copy > freespace ? freespace : to_copy;

	if (len == 0) return 0;

	memcpy(out, data->p, len);
	data->p += len;
	return len;
}
#endif

/** Emulates successive libcurl calls to an encoding function
 *
 * This function is used when the request will be sent to the HTTP server as one
 * contiguous entity. A buffer of REST_BODY_ALLOC_CHUNK bytes is allocated and passed
 * to the stream encoding function.
 *
 * If the stream function does not return 0, a new buffer is allocated which is
 * the size of the previous buffer + REST_BODY_ALLOC_CHUNK bytes, the data from the
 * previous buffer is copied, and freed, and another call is made to the stream
 * function, passing a pointer into the new buffer at the end of the previously
 * written data.
 *
 * This process continues until the stream function signals (by returning 0)
 * that it has no more data to write.
 *
 * @param[out] out	where the pointer to the alloced buffer should
 *			be written.
 * @param[in] inst	of rlm_rest.
 * @param[in] func	Stream function.
 * @param[in] limit	Maximum buffer size to alloc.
 * @param[in] userdata	rlm_rest_request_t to keep encoding state between calls to
 *			stream function.
 * @return
 *	- Length of the data written to the buffer (excluding NULL).
 *	- -1 if alloc >= limit.
 */
static ssize_t rest_request_encode_wrapper(char **out, UNUSED rlm_rest_t const *inst,
					   rest_read_t func, size_t limit, void *userdata)
{
	char	*buff = NULL;
	size_t	alloc = REST_BODY_ALLOC_CHUNK;	/* Size of buffer to alloc */
	size_t	used = 0;			/* Size of data written */
	size_t	len = 0;

	buff = talloc_array(NULL, char, alloc);
	for (;;) {
		len = func(buff + used, alloc - used, 1, userdata);
		used += len;
		if (!len) {
			*out = buff;
			return used;
		}

		alloc = alloc * 2;
		if (alloc > limit) break;

		MEM(buff = talloc_realloc(NULL, buff, char, alloc));
	};

	talloc_free(buff);

	return -1;
}

/** (Re-)Initialises the data in a rlm_rest_request_t.
 *
 * Resets the values of a rlm_rest_request_t to their defaults.
 *
 * @param[in] section	configuration data.
 * @param[in] request	Current request.
 * @param[in] ctx	to initialise.
 */
static void rest_request_init(rlm_rest_section_t const *section,
			      request_t *request, rlm_rest_request_t *ctx)
{
	/*
	 * 	Setup stream read data
	 */
	ctx->section = section;
	ctx->request = request;
	ctx->state = READ_STATE_INIT;
}

/** Converts plain response into a single fr_pair_t
 *
 * @param[in] inst	configuration data.
 * @param[in] section	configuration data.
 * @param[in] randle	fr_curl_io_request_t to use.
 * @param[in] request	Current request.
 * @param[in] raw	buffer containing POST data.
 * @param[in] rawlen	Length of data in raw buffer.
 * @return
 *	- Number of fr_pair_t processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_plain(UNUSED rlm_rest_t const *inst, UNUSED rlm_rest_section_t const *section,
			     request_t *request, UNUSED fr_curl_io_request_t *randle, char *raw, size_t rawlen)
{
	fr_pair_t		*vp;

	/*
	 *  Empty response?
	 */
	if (*raw == '\0') return 0;

	/*
	 *  Use rawlen to protect against overrun, and to cope with any binary data
	 */
	MEM(pair_update_request(&vp, attr_rest_http_body) >= 0);
	fr_pair_value_bstrndup(vp, raw, rawlen, true);

	RDEBUG2("&%pP", vp);

	return 1;
}

/** Converts POST response into fr_pair_ts and adds them to the request
 *
 * Accepts fr_pair_tS in the same format as rest_encode_post, but with the
 * addition of optional attribute list qualifiers as part of the attribute name
 * string.
 *
 * If no qualifiers are specified, will default to the request list.
 *
 * POST response format is:
 * @verbatim [outer.][<list>.]<attribute0>=<value0>&[outer.][<list>.]<attribute1>=<value1>&[outer.][<list>.]<attributeN>=<valueN> @endverbatim
 *
 * @see rest_encode_post
 *
 * @param[in] instance	configuration data.
 * @param[in] section	configuration data.
 * @param[in] randle	fr_curl_io_request_t to use.
 * @param[in] request	Current request.
 * @param[in] raw	buffer containing POST data.
 * @param[in] rawlen	Length of data in raw buffer.
 * @return
 *	- Number of fr_pair_ts processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_post(UNUSED rlm_rest_t const *instance, UNUSED rlm_rest_section_t const *section,
			    request_t *request, fr_curl_io_request_t *randle, char *raw, size_t rawlen)
{
	CURL			*candle = randle->candle;

	char const		*p = raw, *q;

	int			count = 0;
	int			ret;

	/*
	 *	Empty response?
	 */
	fr_skip_whitespace(p);
	if (*p == '\0') return 0;

	while (((q = strchr(p, '=')) != NULL) && (count < REST_BODY_MAX_ATTRS)) {
		tmpl_t		*dst;
		request_t			*current;
		fr_pair_list_t		*vps;
		TALLOC_CTX		*ctx;
		fr_dict_attr_t const	*da;
		fr_pair_t		*vp;

		char			*name  = NULL;
		char			*value = NULL;

		char			*expanded = NULL;

		size_t			len;
		int			curl_len; /* Length from last curl_easy_unescape call */

		current = request;

		name = curl_easy_unescape(candle, p, (q - p), &curl_len);
		p = (q + 1);

		/*
		 *  Resolve attribute name to a dictionary entry and pairlist.
		 */
		RDEBUG2("Parsing attribute \"%pV\"", fr_box_strvalue_len(name, curl_len));

		if (tmpl_afrom_attr_str(request, NULL, &dst, name,
					&(tmpl_rules_t){
						.attr = {
							.prefix = TMPL_ATTR_REF_PREFIX_NO,
							.dict_def = request->dict,
							.list_def = request_attr_reply
						}
					}) <= 0) {
			RPWDEBUG("Failed parsing attribute (skipping)");
			talloc_free(dst);
			goto skip;
		}

		if (tmpl_request_ptr(&current, tmpl_request(dst)) < 0) {
			RWDEBUG("Attribute name refers to outer request but not in a tunnel (skipping)");
			talloc_free(dst);
			goto skip;
		}

		vps = tmpl_list_head(current, tmpl_list(dst));
		if (!vps) {
			RWDEBUG("List not valid in this context (skipping)");
			talloc_free(dst);
			goto skip;
		}
		ctx = tmpl_list_ctx(current, tmpl_list(dst));
		da = tmpl_attr_tail_da(dst);

		fr_assert(vps);

		RINDENT();
		RDEBUG3("Type  : %s", fr_type_to_str(da->type));

		q = strchr(p, '&');
		len = (!q) ? (rawlen - (p - raw)) : (unsigned)(q - p);

		value = curl_easy_unescape(candle, p, len, &curl_len);

		/*
		 *  If we found a delimiter we want to skip over it,
		 *  if we didn't we do *NOT* want to skip over the end
		 *  of the buffer...
		 */
		p += (!q) ? len : (len + 1);

		RDEBUG3("Length : %i", curl_len);
		RDEBUG3("Value  : \"%s\"", value);
		REXDENT();

		talloc_free(dst);	/* Free our temporary tmpl */

		RDEBUG2("Performing xlat expansion of response value");

		if (xlat_aeval(request, &expanded, request, value, NULL, NULL) < 0) goto skip;

		fr_assert(expanded);

		MEM(vp = fr_pair_afrom_da(ctx, da));
		if (!vp) {
			REDEBUG("Failed creating valuepair");
			talloc_free(expanded);

			curl_free(name);
			curl_free(value);

			return count;
		}

		ret = fr_pair_value_from_str(vp, expanded, strlen(value), NULL, true);
		TALLOC_FREE(expanded);
		if (ret < 0) {
			RWDEBUG("Incompatible value assignment, skipping");
			talloc_free(vp);
			goto skip;
		}

		fr_pair_append(vps, vp);

		count++;

	skip:
		curl_free(name);
		curl_free(value);

		continue;
	}

	if (!count) REDEBUG("Malformed POST data \"%s\"", raw);

	return count;

}

#ifdef HAVE_JSON
/** Converts JSON "value" key into fr_pair_t.
 *
 * If leaf is not in fact a leaf node, but contains JSON data, the data will
 * written to the attribute in JSON string format.
 *
 * @param[in] instance	configuration data.
 * @param[in] section	configuration data.
 * @param[in] ctx	to allocate new fr_pair_ts in.
 * @param[in] request	Current request.
 * @param[in] da	Attribute to create.
 * @param[in] flags	containing the operator other flags controlling value
 *			expansion.
 * @param[in] leaf	object containing the fr_pair_t value.
 * @return
 *	- #fr_pair_t just created.
 *	- NULL on error.
 */
static fr_pair_t *json_pair_alloc_leaf(UNUSED rlm_rest_t const *instance, UNUSED rlm_rest_section_t const *section,
				        TALLOC_CTX *ctx, request_t *request,
				        fr_dict_attr_t const *da, json_flags_t *flags, json_object *leaf)
{
	char const		*value;
	char			*expanded = NULL;
	int 			ret;

	fr_pair_t		*vp;

	fr_value_box_t		src;

	if (json_object_is_type(leaf, json_type_null)) {
		RDEBUG3("Got null value for attribute \"%s\" (skipping)", da->name);
		return NULL;
	}

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (!vp) {
		RWDEBUG("Failed creating valuepair for attribute \"%s\" (skipping)", da->name);
		return NULL;
	}

	fr_value_box_init_null(&src);

	switch (json_object_get_type(leaf)) {
	case json_type_int:
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'int', attribute \"%s\"", da->name);
		fr_value_box(&src, (int32_t)json_object_get_int(leaf), true);
		break;

	case json_type_double:
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'double', attribute \"%s\"", da->name);
		fr_value_box(&src, (double)json_object_get_double(leaf), true);
		break;

	case json_type_string:
		value = json_object_get_string(leaf);
		if (flags->do_xlat && memchr(value, '%', json_object_get_string_len(leaf))) {
			if (xlat_aeval(request, &expanded, request, value, NULL, NULL) < 0) {
				talloc_free(vp);
				return NULL;
			}
			fr_value_box_bstrndup_shallow(&src, NULL, expanded,
						      talloc_array_length(expanded) - 1, true);
		} else {
			fr_value_box_bstrndup_shallow(&src, NULL, value,
						      json_object_get_string_len(leaf), true);
		}
		break;

	default:
	{
		char const *str;
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'object', attribute \"%s\"", da->name);

		/*
		 *	Should encode any nested JSON structures into JSON strings.
		 *
		 *	"I knew you liked JSON so I put JSON in your JSON!"
		 */
		str = json_object_get_string(leaf);
		if (!str) {
			RWDEBUG("Failed getting string value for attribute \"%s\" (skipping)", da->name);
			talloc_free(vp);
			return NULL;
		}
		fr_value_box_strdup_shallow(&src, NULL, str, true);
	}
	}

	ret = fr_value_box_cast(vp, &vp->data, da->type, da, &src);
	talloc_free(expanded);
	if (ret < 0) {
		RWDEBUG("Failed parsing value for attribute \"%s\" (skipping)", da->name);
		talloc_free(vp);
		return NULL;
	}

	vp->op = flags->op;

	return vp;
}

/** Processes JSON response and converts it into multiple fr_pair_ts
 *
 * Processes JSON attribute declarations in the format below. Will recurse when
 * processing nested attributes. When processing nested attributes flags and
 * operators from previous attributes are not inherited.
 *
 * JSON response format is:
@verbatim
{
	"<attribute0>":{
		"do_xlat":<bool>,
		"is_json":<bool>,
		"op":"<operator>",
		"value":[<value0>,<value1>,<valueN>]
	},
	"<attribute1>":{
		"value":{
			"<nested-attribute0>":{
				"op":"<operator>",
				"value":<value0>
			}
		}
	},
	"<attribute2>":"<value0>",
	"<attributeN>":[<value0>,<value1>,<valueN>]
}
@endverbatim
 *
 * JSON valuepair flags:
 *  - do_xlat	(optional) Controls xlat expansion of values. Defaults to true.
 *  - is_json	(optional) If true, any nested JSON data will be copied to the
 *			   fr_pair_t in string form. Defaults to true.
 *  - op	(optional) Controls how the attribute is inserted into
 *			   the target list. Defaults to ':=' (T_OP_SET).
 *
 * If "op" is ':=' or '=', it will be automagically changed to '+=' for the
 * second and subsequent values in multivalued attributes. This does not work
 * between multiple attribute declarations.
 *
 * @see fr_tokens_table
 *
 * @param[in] instance	configuration data.
 * @param[in] section	configuration data.
 * @param[in] request	Current request.
 * @param[in] object	containing root node, or parent node.
 * @param[in] level	Current nesting level.
 * @param[in] max	counter, decremented after each fr_pair_t is created,
 *			when 0 no more attributes will be processed.
 * @return
 *	- Number of attributes created.
 *	- < 0 on error.
 */
static int json_pair_alloc(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			   request_t *request, json_object *object, UNUSED int level, int max)
{
	int max_attrs = max;
	tmpl_t *dst = NULL;

	if (!json_object_is_type(object, json_type_object)) {
#ifdef HAVE_JSON_TYPE_TO_NAME
		REDEBUG("Can't process VP container, expected JSON object"
			"got \"%s\" (skipping)",
			json_type_to_name(json_object_get_type(object)));
#else
		REDEBUG("Can't process VP container, expected JSON object"
			" (skipping)");
#endif
		return -1;
	}

	/*
	 *	Process VP container
	 */
	{
		json_object_object_foreach(object, name, value) {
			int		i = 0, elements;
			struct		json_object *element, *tmp;
			TALLOC_CTX	*ctx;

			json_flags_t flags = {
				.op = T_OP_SET,
				.do_xlat = 1,
				.is_json = 0
			};

			request_t		*current = request;
			fr_pair_list_t		*vps;
			fr_pair_t		*vp = NULL;

			TALLOC_FREE(dst);

			/*
			 *  Resolve attribute name to a dictionary entry and pairlist.
			 */
			RDEBUG2("Parsing attribute \"%s\"", name);

			if (tmpl_afrom_attr_str(request, NULL, &dst, name,
						&(tmpl_rules_t){
							.attr = {
								.prefix = TMPL_ATTR_REF_PREFIX_NO,
								.dict_def = request->dict,
								.list_def = request_attr_reply
							}
						}) <= 0) {
				RPWDEBUG("Failed parsing attribute (skipping)");
				continue;
			}

			if (tmpl_request_ptr(&current, tmpl_request(dst)) < 0) {
				RWDEBUG("Attribute name refers to outer request but not in a tunnel (skipping)");
				continue;
			}

			vps = tmpl_list_head(current, tmpl_list(dst));
			if (!vps) {
				RWDEBUG("List not valid in this context (skipping)");
				continue;
			}
			ctx = tmpl_list_ctx(current, tmpl_list(dst));

			/*
			 *  Alternative JSON structure which allows operator,
			 *  and other flags to be specified.
			 *
			 *	"<name>":{
			 *		"do_xlat":<bool>,
			 *		"is_json":<bool>,
			 *		"op":"<op>",
			 *		"value":<value>
			 *	}
			 *
			 *	Where value is a:
			 *	  - []	Multivalued array
			 *	  - {}	Nested Valuepair
			 *	  - *	Integer or string value
			 */
			if (json_object_is_type(value, json_type_object)) {
				/*
				 *  Process operator if present.
				 */
				if (json_object_object_get_ex(value, "op", &tmp)) {
					flags.op = fr_table_value_by_str(fr_tokens_table, json_object_get_string(tmp), 0);
					if (!flags.op) {
						RWDEBUG("Invalid operator value \"%s\" (skipping)",
							json_object_get_string(tmp));
						continue;
					}
				}

				/*
				 *  Process optional do_xlat bool.
				 */
				if (json_object_object_get_ex(value, "do_xlat", &tmp)) {
					flags.do_xlat = json_object_get_boolean(tmp);
				}

				/*
				 *  Process optional is_json bool.
				 */
				if (json_object_object_get_ex(value, "is_json", &tmp)) {
					flags.is_json = json_object_get_boolean(tmp);
				}

				/*
				 *  Value key must be present if were using the expanded syntax.
				 */
				if (!json_object_object_get_ex(value, "value", &tmp)) {
					RWDEBUG("Value key missing (skipping)");
					continue;
				}

				/*
				 *  The value field now becomes the key we're operating on
				 */
				value = tmp;
			}

			/*
			 *  Setup fr_pair_afrom_da / recursion loop.
			 */
			if (!flags.is_json && json_object_is_type(value, json_type_array)) {
				elements = json_object_array_length(value);
				if (!elements) {
					RWDEBUG("Zero length value array (skipping)");
					continue;
				}
				element = json_object_array_get_idx(value, 0);
			} else {
				elements = 1;
				element = value;
			}

			/*
			 *  A JSON 'value' key, may have multiple elements, iterate
			 *  over each of them, creating a new fr_pair_t.
			 */
			do {
				fr_pair_list_t tmp_list;

				if (max_attrs-- <= 0) {
					RWDEBUG("At maximum attribute limit");
					talloc_free(dst);
					return max;
				}

				/*
				 *  Automagically switch the op for multivalued attributes.
				 */
				if (((flags.op == T_OP_SET) || (flags.op == T_OP_EQ)) && (i >= 1)) {
					flags.op = T_OP_ADD_EQ;
				}

				if (json_object_is_type(element, json_type_object) && !flags.is_json) {
					/* TODO: Insert nested VP into VP structure...*/
					RWDEBUG("Found nested VP, these are not yet supported (skipping)");

					continue;

					/*
					vp = json_pair_alloc(instance, section,
							request, value,
							level + 1, max_attrs);*/
				} else {
					vp = json_pair_alloc_leaf(instance, section, ctx, request,
								  tmpl_attr_tail_da(dst), &flags, element);
					if (!vp) continue;
				}
				RINDENT();
				RDEBUG2("&%s:%pP", tmpl_list_name(tmpl_list(dst), ""), vp);
				REXDENT();

				fr_pair_list_init(&tmp_list);
				fr_pair_append(&tmp_list, vp);
				radius_pairmove(current, vps, &tmp_list);
			/*
			 *  If we call json_object_array_get_idx on something that's not an array
			 *  the behaviour appears to be to occasionally segfault.
			 */
			} while ((++i < elements) && (element = json_object_array_get_idx(value, i)));
		}
	}

	talloc_free(dst);

	return max - max_attrs;
}

/** Converts JSON response into fr_pair_ts and adds them to the request.
 *
 * Converts the raw JSON string into a json-c object tree and passes it to
 * json_pair_alloc. After the tree has been parsed json_object_put is called
 * which decrements the reference count of the root node by one, and frees
 * the entire tree.
 *
 * @see rest_encode_json
 * @see json_pair_alloc
 *
 * @param[in] instance	configuration data.
 * @param[in] section	configuration data.
 * @param[in,out] request Current request.
 * @param[in] randle	REST handle.
 * @param[in] raw	buffer containing JSON data.
 * @param[in] rawlen	Length of data in raw buffer.
 * @return
 *	- The number of #fr_pair_t processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_json(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			    request_t *request, UNUSED fr_curl_io_request_t *randle, char *raw, UNUSED size_t rawlen)
{
	char const *p = raw;

	struct json_object *json;

	int ret;

	/*
	 *  Empty response?
	 */
	fr_skip_whitespace(p);
	if (*p == '\0') return 0;

	json = json_tokener_parse(p);
	if (!json) {
		REDEBUG("Malformed JSON data \"%s\"", raw);
		return -1;
	}

	ret = json_pair_alloc(instance, section, request, json, 0, REST_BODY_MAX_ATTRS);

	/*
	 *  Decrement reference count for root object, should free entire JSON tree.
	 */
	json_object_put(json);

	return ret;
}
#endif

/** Processes incoming HTTP header data from libcurl.
 *
 * Processes the status line, and Content-Type headers from the incoming HTTP
 * response.
 *
 * Matches prototype for CURLOPT_HEADERFUNCTION, and will be called directly
 * by libcurl.
 *
 * @param[in] in	Char buffer where inbound header data is written.
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_rest_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t rest_response_header(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_response_t	*ctx = userdata;
	request_t			*request = ctx->request; /* Used by RDEBUG */

	char const		*start = (char *)in, *p = start, *end = p + (size * nmemb);
	char			*q;
	size_t			len;

	http_body_type_t	type;

#ifndef NDEBUG
	if (ctx->instance->fail_header_decode) {
		REDEBUG("Forcing header decode failure");
		return 0;
	}
#endif

	/*
	 *  This seems to be curl's indication there are no more header lines.
	 */
	if (((end - p) == 2) && ((p[0] == '\r') && (p[1] == '\n'))) {
		/*
		 *  If we got a 100 Continue, we need to send additional payload data.
		 *  reset the state to WRITE_STATE_INIT, so that when were called again
		 *  we overwrite previous header data with that from the proper header.
		 */
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

			/*
			 *	Indicate we parsed the entire line, otherwise
			 *	bad things seem to happen internally with
			 *	libcurl when we try and use it with asynchronous
			 *      I/O handlers.
			 */
			return (end - start);
		}
		/*
		 *  Check start of header matches...
		 */
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
		 *  Convert status code into an integer value
		 */
		q = NULL;
		ctx->code = (int)strtoul(p, &q, 10);
		fr_assert(q == (p + 3));	/* We check this above */
		p = q;

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
			type = fr_table_value_by_substr(http_content_type_table, p, len, REST_HTTP_BODY_UNKNOWN);

			RINDENT();
			RDEBUG2("Type   : %s (%pV)", fr_table_str_by_value(http_body_type_table, type, "<INVALID>"),
				fr_box_strvalue_len(p, len));
			REXDENT();

			/*
			 *  Assume the force_to value has already been validated.
			 */
			if (ctx->force_to != REST_HTTP_BODY_UNKNOWN) {
				if (ctx->force_to != ctx->type) {
					RDEBUG3("Forcing body type to \"%s\"",
						fr_table_str_by_value(http_body_type_table, ctx->force_to, "<INVALID>"));
					ctx->type = ctx->force_to;
				}
			/*
			 *  Figure out if the type is supported by one of the decoders.
			 */
			} else {
				ctx->type = http_body_type_supported[type];
				switch (ctx->type) {
				case REST_HTTP_BODY_UNKNOWN:
					RWDEBUG("Couldn't determine type, using the request's type \"%s\".",
						fr_table_str_by_value(http_body_type_table, type, "<INVALID>"));
					break;

				case REST_HTTP_BODY_UNSUPPORTED:
					REDEBUG("Type \"%s\" is currently unsupported",
						fr_table_str_by_value(http_body_type_table, type, "<INVALID>"));
					break;

				case REST_HTTP_BODY_UNAVAILABLE:
					REDEBUG("Type \"%s\" is unavailable, please rebuild this module with the required "
						"library", fr_table_str_by_value(http_body_type_table, type, "<INVALID>"));
					break;

				case REST_HTTP_BODY_INVALID:
					REDEBUG("Type \"%s\" is not a valid web API data markup format",
						fr_table_str_by_value(http_body_type_table, type, "<INVALID>"));
					break;

				/* supported type */
				default:
					break;
				}
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
 * Writes incoming body data to an intermediary buffer for later parsing by
 * one of the decode functions.
 *
 * @param[in] in	Char buffer where inbound header data is written
 * @param[in] size	Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb	Multiply by size to get the length of ptr.
 * @param[in] userdata	rlm_rest_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t rest_response_body(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_response_t	*ctx = userdata;
	request_t			*request = ctx->request; /* Used by RDEBUG */

	char const		*start = in, *p = start, *end = p + (size * nmemb);
	char			*q;

	size_t			needed;

	if (start == end) return 0; 	/* Nothing to process */

#ifndef NDEBUG
	if (ctx->instance->fail_body_decode) {
		REDEBUG("Forcing body read failure");
		return 0;
	}
#endif

	/*
	 *  Any post processing of headers should go here...
	 */
	if (ctx->state == WRITE_STATE_PARSE_HEADERS) ctx->state = WRITE_STATE_PARSE_CONTENT;

	switch (ctx->type) {
	case REST_HTTP_BODY_UNSUPPORTED:
	case REST_HTTP_BODY_UNAVAILABLE:
	case REST_HTTP_BODY_INVALID:
		while ((q = memchr(p, '\n', (end - p)))) {
			REDEBUG("%pV", fr_box_strvalue_len(p, q - p));
			p = q + 1;
		}

		if (p != end) REDEBUG("%pV", fr_box_strvalue_len(p, end - p));
		break;

	case REST_HTTP_BODY_NONE:
		while ((q = memchr(p, '\n', (end - p)))) {
			RDEBUG3("%pV", fr_box_strvalue_len(p, q - p));
			p = q + 1;
		}

		if (p != end) RDEBUG3("%pV", fr_box_strvalue_len(p, end - p));
		break;

	default:
	{
		char *out_p;

		if ((ctx->section->max_body_in > 0) && ((ctx->used + (end - p)) > ctx->section->max_body_in)) {
			REDEBUG("Incoming data (%zu bytes) exceeds max_body_in (%zu bytes).  "
				"Forcing body to type 'invalid'", ctx->used + (end - p), ctx->section->max_body_in);
			ctx->type = REST_HTTP_BODY_INVALID;
			TALLOC_FREE(ctx->buffer);
			break;
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
	}
		break;
	}

	return (end - start);
}

/** Print out the response text as error lines
 *
 * @param request	The Current request.
 * @param handle	fr_curl_io_request_t used to execute the previous request.
 */
void rest_response_error(request_t *request, fr_curl_io_request_t *handle)
{
	char const	*p, *end;
	char		*q;
	size_t len;

	len = rest_get_handle_data(&p, handle);
	if (len == 0) return;

	end = p + len;

	RERROR("Server returned:");
	while ((q = memchr(p, '\n', (end - p)))) {
		RERROR("%pV", fr_box_strvalue_len(p, q - p));
		p = q + 1;
	}

	if (p != end) RERROR("%pV", fr_box_strvalue_len(p, end - p));
}

/** Print out the response text
 *
 * @param request	The Current request.
 * @param handle	fr_curl_io_request_t used to execute the previous request.
 */
void rest_response_debug(request_t *request, fr_curl_io_request_t *handle)
{
	char const	*p, *end;
	char		*q;
	size_t len;

	len = rest_get_handle_data(&p, handle);
	if (len == 0) return;

	end = p + len;

	RDEBUG3("Server returned:");
	while ((q = memchr(p, '\n', (end - p)))) {
		RDEBUG3("%pV", fr_box_strvalue_len(p, q - p));
		p = q + 1;
	}

	if (p != end) RDEBUG3("%pV", fr_box_strvalue_len(p, end - p));
}

/** (Re-)Initialises the data in a rlm_rest_response_t.
 *
 * This resets the values of the a rlm_rest_response_t to their defaults.
 * Must be called between encoding sessions.
 *
 * @see rest_response_body
 * @see rest_response_header
 *
 * @param[in] section	that created the request.
 * @param[in] request	Current request.
 * @param[in] ctx	data to initialise.
 * @param[in] type	Default http_body_type to use when decoding raw data, may be
 * 			overwritten by rest_response_header.
 */
static void rest_response_init(rlm_rest_section_t const *section,
			       request_t *request, rlm_rest_response_t *ctx, http_body_type_t type)
{
	ctx->section = section;
	ctx->request = request;
	ctx->type = type;
	ctx->state = WRITE_STATE_INIT;
	ctx->alloc = 0;
	ctx->used = 0;
	ctx->code = 0;
	TALLOC_FREE(ctx->buffer);
}

/** Extracts pointer to buffer containing response data
 *
 * @param[out] out	Where to write the pointer to the buffer.
 * @param[in] randle	used for the last request.
 * @return
 *	- 0 if no data i available.
 *	- > 0 if data is available.
 */
size_t rest_get_handle_data(char const **out, fr_curl_io_request_t *randle)
{
	rlm_rest_curl_context_t *ctx = talloc_get_type_abort(randle->uctx, rlm_rest_curl_context_t);

	if (!ctx->response.buffer) return 0;

	*out = ctx->response.buffer;
	return ctx->response.used;
}

/** Configures body specific curlopts.
 *
 * Configures libcurl handle to use either chunked mode, where the request
 * data will be sent using multiple HTTP requests, or contiguous mode where
 * the request data will be sent in a single HTTP request.
 *
 * @param[in] mctx	Call data.
 * @param[in] section	configuration data.
 * @param[in] request	Current request.
 * @param[in] randle	fr_curl_io_request_t to configure.
 * @param[in] func	to pass to libcurl for chunked.
 *	      		transfers (NULL if not using chunked mode).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int rest_request_config_body(module_ctx_t const *mctx, rlm_rest_section_t const *section,
				    request_t *request, fr_curl_io_request_t *randle, rest_read_t func)
{
	rlm_rest_t const *inst = talloc_get_type_abort(mctx->inst->data, rlm_rest_t);
	rlm_rest_curl_context_t	*uctx = talloc_get_type_abort(randle->uctx, rlm_rest_curl_context_t);
	ssize_t len;

	/*
	 *  We were provided with no read function, assume this means
	 *  no body should be sent.
	 */
	if (!func) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_POSTFIELDSIZE, 0);
		return 0;
	}

	/*
	 *  Chunked transfer encoding means the body will be sent in
	 *  multiple parts.
	 */
	if (section->chunk > 0) {
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_READDATA, &uctx->request);
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_READFUNCTION, func);

		return 0;
	}

	/*
	 *  If were not doing chunked encoding then we read the entire
	 *  body into a buffer, and send it in one go.
	 */
	len = rest_request_encode_wrapper(&uctx->body, inst, func, REST_BODY_MAX_LEN, &uctx->request);
	if (len <= 0) {
		REDEBUG("Failed creating HTTP body content");
		return -1;
	}
	RDEBUG2("Content-Length will be %zu bytes", len);

	fr_assert((len == 0) || (talloc_array_length(uctx->body) >= (size_t)len));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_POSTFIELDS, uctx->body);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_POSTFIELDSIZE, len);

	return 0;

error:
	return -1;
}

/** Configures request curlopts.
 *
 * Configures libcurl handle setting various curlopts for things like local
 * client time, Content-Type, and other FreeRADIUS custom headers.
 *
 * Current FreeRADIUS custom headers are:
 *  - X-FreeRADIUS-Section	The module section being processed.
 *  - X-FreeRADIUS-Server	The current virtual server the request_t is
 *				passing through.
 *
 * Sets up callbacks for all response processing (buffers and body data).
 *
 * @param[in] mctx	call data.
 * @param[in] section	configuration data.
 * @param[in] randle	to configure.
 * @param[in] request	Current request.
 * @param[in] method	to use (HTTP verbs PUT, POST, DELETE etc...).
 * @param[in] type	Content-Type for request encoding, also sets
 *			the default for decoding.
 * @param[in] username	to use for HTTP authentication, may be NULL in
 *			which case configured defaults will be used.
 * @param[in] password	to use for HTTP authentication, may be NULL in
 *			which case configured defaults will be used.
 * @param[in] uri	buffer containing the expanded URI to send the request to.
 * @return
 *	- 0 on success (all opts configured).
 *	- -1 on failure.
 */
int rest_request_config(module_ctx_t const *mctx, rlm_rest_section_t const *section,
			request_t *request, fr_curl_io_request_t *randle, http_method_t method,
			http_body_type_t type,
			char const *uri, char const *username, char const *password)
{
	rlm_rest_t const	*inst = talloc_get_type_abort(mctx->inst->data, rlm_rest_t);
	rlm_rest_curl_context_t *ctx = talloc_get_type_abort(randle->uctx, rlm_rest_curl_context_t);
	CURL			*candle = randle->candle;
	fr_time_delta_t		timeout;

	http_auth_type_t	auth = section->auth;

	CURLcode		ret = CURLE_OK;
	char const		*option = "unknown";

	char			buffer[512];
	bool			content_type_set = false;

	fr_assert(candle);
	fr_assert((!username && !password) || (username && password));

	buffer[(sizeof(buffer) - 1)] = '\0';

	/*
	 *	Control which HTTP version we're going to use
	 */
	if (inst->http_negotiation != CURL_HTTP_VERSION_NONE) FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTP_VERSION, inst->http_negotiation);

	/*
	 *	Setup any header options and generic headers.
	 */
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_URL, uri);
#if CURL_AT_LEAST_VERSION(7,85,0)
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS_STR, "http,https");
#else
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
	if (section->proxy) {
		if (section->proxy == rest_no_proxy) {
			FR_CURL_REQUEST_SET_OPTION(CURLOPT_NOPROXY, "*");
		} else {
			FR_CURL_REQUEST_SET_OPTION(CURLOPT_PROXY, section->proxy);
		}
	}
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_NOSIGNAL, 1L);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_USERAGENT, "FreeRADIUS " RADIUSD_VERSION_STRING);

	timeout = inst->conn_config.connect_timeout;
	RDEBUG3("Connect timeout is %pVs, request timeout is %pVs",
	        fr_box_time_delta(timeout), fr_box_time_delta(section->timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(timeout));
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(section->timeout));

	/*
	 *	FreeRADIUS custom headers
	 */
	RDEBUG3("Adding custom headers:");
	snprintf(buffer, sizeof(buffer), "X-FreeRADIUS-Section: %s", section->name);

	RINDENT();
	RDEBUG3("%s", buffer);
	REXDENT();
	ctx->headers = curl_slist_append(ctx->headers, buffer);
	if (!ctx->headers) goto error_header;

	snprintf(buffer, sizeof(buffer), "X-FreeRADIUS-Server: %s", cf_section_name2(unlang_call_current(request)));
	RINDENT();
	RDEBUG3("%s", buffer);
	REXDENT();
	ctx->headers = curl_slist_append(ctx->headers, buffer);
	if (!ctx->headers) goto error_header;

	/*
	 *	Add in the section headers
	 */
	if (section->headers) {
		talloc_foreach(section->headers, header) {
			RINDENT();
			RDEBUG3("%pV", fr_box_strvalue_buffer(header));
			REXDENT();

			ctx->headers = curl_slist_append(ctx->headers, header);
		}
	}

	/*
	 *	Add in dynamic headers from the request
	 */
	{
		fr_pair_t 	*header;
		fr_dcursor_t	headers;

		for (header =  fr_pair_dcursor_by_da_init(&headers, &request->control_pairs, attr_rest_http_header);
		     header;
		     header = fr_dcursor_current(&headers)) {
			header = fr_dcursor_remove(&headers);
			if (!strchr(header->vp_strvalue, ':')) {
				RWDEBUG("Invalid HTTP header \"%s\" must be in format '<attribute>: <value>'.  Skipping...",
					header->vp_strvalue);
				talloc_free(header);
				continue;
			}
			RINDENT();
			RDEBUG3("%pV", &header->data);
			REXDENT();

			ctx->headers = curl_slist_append(ctx->headers, header->vp_strvalue);

			/*
			 *  Set content-type based on a corresponding REST-HTTP-Header attribute, if provided.
			 */
			if (!content_type_set && (strncasecmp(header->vp_strvalue, "content-type:", sizeof("content-type:") - 1) == 0)) {
				char const *content_type = header->vp_strvalue + (sizeof("content-type:") - 1);

				while (isspace((uint8_t)*content_type)) content_type++;

				RDEBUG3("Request body content-type provided as \"%s\"", content_type);

				content_type_set = true;
			}

			talloc_free(header);
		}
	}

	if (!content_type_set) {
		/*
		 *  HTTP/1.1 doesn't require a content type so only set it
		 *  if where body type requires it, and we haven't set one
		 *  already from attributes.
		 */
		if (type != REST_HTTP_BODY_NONE) {
			char const *content_type = fr_table_str_by_value(http_content_type_table, type, section->body_str);
			snprintf(buffer, sizeof(buffer), "Content-Type: %s", content_type);
			ctx->headers = curl_slist_append(ctx->headers, buffer);
			if (!ctx->headers) {
			error_header:
				REDEBUG("Failed creating header");
				return -1;
			}

			RDEBUG3("Request body content-type will be \"%s\"", content_type);
		}
	}

	/*
	 *	Configure HTTP verb (GET, POST, PUT, PATCH, DELETE, other...)
	 */
	switch (method) {
	case REST_HTTP_METHOD_GET:
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPGET, 1L);
		break;

	case REST_HTTP_METHOD_POST:
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_POST, 1L);
		break;

	case REST_HTTP_METHOD_PUT:
		/*
		 *	Do not set CURLOPT_PUT, this will cause libcurl
		 *	to ignore CURLOPT_POSTFIELDs and attempt to read
		 *	whatever was set with CURLOPT_READDATA, which by
		 *	default is stdin.
		 *
		 *	This is many cases will cause the server to block,
		 *	indefinitely.
		 */
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_CUSTOMREQUEST, "PUT");
		break;

	case REST_HTTP_METHOD_PATCH:
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_CUSTOMREQUEST, "PATCH");
		break;

	case REST_HTTP_METHOD_DELETE:
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_CUSTOMREQUEST, "DELETE");
		break;

	case REST_HTTP_METHOD_CUSTOM:
		FR_CURL_REQUEST_SET_OPTION(CURLOPT_CUSTOMREQUEST, section->method_str);
		break;

	default:
		fr_assert(0);
		break;
	};

	/*
	 *	Set user based authentication parameters
	 */
	if (auth > REST_HTTP_AUTH_NONE) {
		TALLOC_CTX *cred_ctx = NULL;

#define SET_AUTH_OPTION(_x, _y)\
do {\
	if ((ret = curl_easy_setopt(candle, _x, _y)) != CURLE_OK) {\
		option = STRINGIFY(_x);\
		REDEBUG("Failed setting curl option %s: %s (%i)", option, curl_easy_strerror(ret), ret); \
		talloc_free(cred_ctx);\
		goto error;\
	}\
} while (0)

		if (!username || !password) cred_ctx = talloc_init_const("cred_ctx");

		if (!username) {
			char *tmp = NULL;
			if (xlat_aeval(cred_ctx, &tmp, request, section->username, NULL, NULL) < 0) {
				REDEBUG("Failed expanding username");
				talloc_free(cred_ctx);
				goto error;
			}
			username = tmp;
		}

		if (!password) {
			char *tmp = NULL;
			if (xlat_aeval(cred_ctx, &tmp, request, section->password, NULL, NULL) < 0) {
				REDEBUG("Failed expanding password");
				talloc_free(cred_ctx);
				goto error;
			}
			password = tmp;
		}

		RDEBUG3("Configuring HTTP auth type %s, user \"%pV\", password \"%pV\"",
			fr_table_str_by_value(http_auth_table, auth, "<INVALID>"),
			fr_box_strvalue_buffer(username), fr_box_strvalue_buffer(password));

		if ((auth >= REST_HTTP_AUTH_BASIC) &&
		    (auth <= REST_HTTP_AUTH_ANY_SAFE)) {
			SET_AUTH_OPTION(CURLOPT_HTTPAUTH, http_curl_auth[auth]);
			SET_AUTH_OPTION(CURLOPT_USERNAME, username);
			SET_AUTH_OPTION(CURLOPT_PASSWORD, password);
		} else if (auth == REST_HTTP_AUTH_TLS_SRP) {
			SET_AUTH_OPTION(CURLOPT_TLSAUTH_TYPE, http_curl_auth[auth]);
			SET_AUTH_OPTION(CURLOPT_TLSAUTH_USERNAME, username);
			SET_AUTH_OPTION(CURLOPT_TLSAUTH_PASSWORD, password);
		}
	}

	/*
	 *	Set SSL/TLS authentication parameters
	 */
	fr_curl_easy_tls_init(randle, &section->tls);

	/*
	 *	Tell CURL how to get HTTP body content, and how to process incoming data.
	 */
	rest_response_init(section, request, &ctx->response, type);

	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HEADERFUNCTION, rest_response_header);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HEADERDATA, &ctx->response);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEFUNCTION, rest_response_body);
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_WRITEDATA, &ctx->response);

	/*
	 *  Force parsing the body text as a particular encoding.
	 */
	ctx->response.force_to = section->force_to;

	switch (method) {
	case REST_HTTP_METHOD_GET:
	case REST_HTTP_METHOD_DELETE:
		RDEBUG3("Using a HTTP method which does not require a body.  Forcing request body type to \"none\"");
		goto finish;

	case REST_HTTP_METHOD_POST:
	case REST_HTTP_METHOD_PUT:
	case REST_HTTP_METHOD_PATCH:
	case REST_HTTP_METHOD_CUSTOM:
		if (section->chunk > 0) {
			ctx->request.chunk = section->chunk;

			ctx->headers = curl_slist_append(ctx->headers, "Expect:");
			if (!ctx->headers) goto error_header;

			ctx->headers = curl_slist_append(ctx->headers, "Transfer-Encoding: chunked");
			if (!ctx->headers) goto error_header;
		}

		break;

	default:
		fr_assert(0);
	};

	/*
	 *  Setup encoder specific options
	 */
	switch (type) {
	case REST_HTTP_BODY_NONE:
		if (rest_request_config_body(mctx, section, request, randle, NULL) < 0) return -1;

		break;

	case REST_HTTP_BODY_CUSTOM_XLAT:
	{
		rest_custom_data_t *data;
		char *expanded = NULL;

		if (xlat_aeval(request, &expanded, request, section->data, NULL, NULL) < 0) return -1;

		data = talloc_zero(request, rest_custom_data_t);
		data->p = expanded;
		data->start = expanded;
		data->len = strlen(expanded);	// Fix me when we do binary xlat

		/* Use the encoder specific pointer to store the data we need to encode */
		ctx->request.encoder = data;
		if (rest_request_config_body(mctx, section, request, randle, rest_encode_custom) < 0) {
			TALLOC_FREE(ctx->request.encoder);
			return -1;
		}

		break;
	}

	case REST_HTTP_BODY_CUSTOM_LITERAL:
	{
		rest_custom_data_t *data;

		data = talloc_zero(request, rest_custom_data_t);
		data->p = section->data;
		data->start = section->data;
		data->len = strlen(section->data);

		/* Use the encoder specific pointer to store the data we need to encode */
		ctx->request.encoder = data;
		if (rest_request_config_body(mctx, section, request, randle, rest_encode_custom) < 0) {
			TALLOC_FREE(ctx->request.encoder);
			return -1;
		}
	}
		break;

#ifdef HAVE_JSON
	case REST_HTTP_BODY_JSON:
	{
		rest_custom_data_t *data;

		data = talloc_zero(request, rest_custom_data_t);
		ctx->request.encoder = data;

		rest_request_init(section, request, &ctx->request);

		if (rest_request_config_body(mctx, section, request, randle, rest_encode_json) < 0) return -1;
	}

		break;
#endif

	case REST_HTTP_BODY_POST:
		rest_request_init(section, request, &ctx->request);
		fr_pair_dcursor_init(&(ctx->request.cursor), &request->request_pairs);

		if (rest_request_config_body(mctx, section, request, randle, rest_encode_post) < 0) return -1;

		break;

	default:
		fr_assert(0);
	}


finish:
	FR_CURL_REQUEST_SET_OPTION(CURLOPT_HTTPHEADER, ctx->headers);

	return 0;

error:
	return -1;
}

/** Sends the response to the correct decode function.
 *
 * Uses the Content-Type information written in rest_response_header to
 * determine the correct decode function to use. The decode function will
 * then convert the raw received data into fr_pair_ts.
 *
 * @param[in] instance	configuration data.
 * @param[in] section	configuration data.
 * @param[in] request	Current request.
 * @param[in] randle	to use.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rest_response_decode(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			 request_t *request, fr_curl_io_request_t *randle)
{
	rlm_rest_curl_context_t *ctx = talloc_get_type_abort(randle->uctx, rlm_rest_curl_context_t);

	int ret = -1;	/* -Wsometimes-uninitialized */

	if (!ctx->response.buffer) {
		RDEBUG2("Skipping attribute processing, no valid body data received");
		return 0;
	}

	switch (ctx->response.type) {
	case REST_HTTP_BODY_NONE:
		return 0;

	case REST_HTTP_BODY_PLAIN:
		ret = rest_decode_plain(instance, section, request, randle, ctx->response.buffer, ctx->response.used);
		break;

	case REST_HTTP_BODY_POST:
		ret = rest_decode_post(instance, section, request, randle, ctx->response.buffer, ctx->response.used);
		break;

#ifdef HAVE_JSON
	case REST_HTTP_BODY_JSON:
		ret = rest_decode_json(instance, section, request, randle, ctx->response.buffer, ctx->response.used);
		break;
#endif

	case REST_HTTP_BODY_UNSUPPORTED:
	case REST_HTTP_BODY_UNAVAILABLE:
	case REST_HTTP_BODY_INVALID:
		return -1;

	default:
		fr_assert(0);
	}

	return ret;
}

/** URL encodes a string.
 *
 * Encode special chars as per RFC 3986 section 4.
 *
 * @param[in] request	Current request.
 * @param[out] out	Where to write escaped string.
 * @param[in] outlen	Size of out buffer.
 * @param[in] raw	string to be urlencoded.
 * @param[in] arg	pointer, gives context for escaping.
 * @return length of data written to out (excluding NULL).
 */
size_t rest_uri_escape(UNUSED request_t *request, char *out, size_t outlen, char const *raw, UNUSED void *arg)
{
	char *escaped;

	escaped = curl_escape(raw, 0);
	strlcpy(out, escaped, outlen);
	curl_free(escaped);

	return strlen(out);
}

/** Builds URI; performs XLAT expansions and encoding.
 *
 * Splits the URI into "http://example.org" and "/%{xlat}/query/?bar=foo"
 * Both components are expanded, but values expanded for the second component
 * are also url encoded.
 *
 * @param[out] out	Where to write the pointer to the new buffer containing the escaped URI.
 * @param[in] inst	of rlm_rest.
 * @param[in] uri	configuration data.
 * @param[in] request	Current request
 * @return
 *	- Length of data written to buffer (excluding NULL).
 *	- < 0 if an error occurred.
 */
ssize_t rest_uri_build(char **out, UNUSED rlm_rest_t const *inst, request_t *request, char const *uri)
{
	char const	*p;
	char		*path_exp = NULL;

	char		*scheme;
	char const	*path;

	ssize_t		len;

	p = uri;

	/*
	 *  All URLs must contain at least <scheme>://<server>/
	 */
	p = strchr(p, ':');
	if (!p || (*++p != '/') || (*++p != '/')) {
		malformed:
		REDEBUG("Error URI \"%s\" is malformed, can't find start of path", uri);
		return -1;
	}
	p = strchr(p + 1, '/');
	if (!p) {
		goto malformed;
	}

	len = (p - uri);

	/*
	 *  Allocate a temporary buffer to hold the first part of the URI
	 */
	scheme = talloc_array(request, char, len + 1);
	strlcpy(scheme, uri, len + 1);

	path = (uri + len);

	len = xlat_aeval(request, out, request, scheme, NULL, NULL);
	talloc_free(scheme);
	if (len < 0) {
		TALLOC_FREE(*out);

		return 0;
	}

	len = xlat_aeval(request, &path_exp, request, path, rest_uri_escape, NULL);
	if (len < 0) {
		TALLOC_FREE(*out);

		return 0;
	}

	MEM(*out = talloc_strdup_append(*out, path_exp));
	talloc_free(path_exp);

	return talloc_array_length(*out) - 1;	/* array_length includes \0 */
}

/** Unescapes the host portion of a URI string
 *
 * This is required because the xlat functions which operate on the input string
 * cannot distinguish between host and path components.
 *
 * @param[out] out	Where to write the pointer to the new
 *			buffer containing the escaped URI.
 * @param[in] inst	of rlm_rest.
 * @param[in] request	Current request
 * @param[in] randle	to use.
 * @param[in] uri	configuration data.
 * @return
 *	- Length of data written to buffer (excluding NULL).
 *	- < 0 if an error occurred.
 */
ssize_t rest_uri_host_unescape(char **out, UNUSED rlm_rest_t const *inst, request_t *request,
			       fr_curl_io_request_t *randle, char const *uri)
{
	CURL			*candle = randle->candle;

	char const		*p, *q;

	char			*scheme;

	ssize_t			len;

	p = uri;

	/*
	 *  All URLs must contain at least <scheme>://<server>/
	 */
	p = strchr(p, ':');
	if (!p || (*++p != '/') || (*++p != '/')) {
	malformed:
		REDEBUG("URI \"%s\" is malformed, can't find start of path", uri);
		return -1;
	}
	p = strchr(p + 1, '/');
	if (!p) {
		goto malformed;
	}

	len = (p - uri);

	/*
	 *  Unescape any special sequences in the first part of the URI
	 */
	scheme = curl_easy_unescape(candle, uri, len, NULL);
	if (!scheme) {
		REDEBUG("Error unescaping host");
		return -1;
	}

	/*
	 *  URIs can't contain spaces, so anything after the space must
	 *  be something else.
	 */
	q = strchr(p, ' ');
	*out = q ? talloc_typed_asprintf(request, "%s%.*s", scheme, (int)(q - p), p) :
		   talloc_typed_asprintf(request, "%s%s", scheme, p);

	MEM(*out);
	curl_free(scheme);

	return talloc_array_length(*out) - 1;	/* array_length includes \0 */
}
