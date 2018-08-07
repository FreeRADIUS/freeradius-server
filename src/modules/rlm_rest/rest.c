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
 * @copyright 2012-2016 Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 */

RCSID("$Id$")

#define LOG_PREFIX "rlm_rest (%s) - "
#define LOG_PREFIX_ARGS inst->xlat_name

#include <ctype.h>
#include <string.h>
#include <time.h>

#include <freeradius-devel/server/rad_assert.h>
#include <freeradius-devel/server/base.h>
#include <freeradius-devel/util/base.h>
#include <freeradius-devel/server/pool.h>

#include "rest.h"

/** Table of encoder/decoder support.
 *
 * Indexes in this table match the http_body_type_t enum, and should be
 * updated if additional enum values are added.
 *
 * @see http_body_type_t
 */
const http_body_type_t http_body_type_supported[HTTP_BODY_NUM_ENTRIES] = {
	HTTP_BODY_UNKNOWN,		// HTTP_BODY_UNKNOWN
	HTTP_BODY_UNSUPPORTED,		// HTTP_BODY_UNSUPPORTED
	HTTP_BODY_UNSUPPORTED,  	// HTTP_BODY_UNAVAILABLE
	HTTP_BODY_UNSUPPORTED,		// HTTP_BODY_INVALID
	HTTP_BODY_NONE,			// HTTP_BODY_NONE
	HTTP_BODY_CUSTOM_XLAT,		// HTTP_BODY_CUSTOM_XLAT
	HTTP_BODY_CUSTOM_LITERAL,	// HTTP_BODY_CUSTOM_LITERAL
	HTTP_BODY_POST,			// HTTP_BODY_POST
#ifdef HAVE_JSON
	HTTP_BODY_JSON,			// HTTP_BODY_JSON
#else
	HTTP_BODY_UNAVAILABLE,
#endif
	HTTP_BODY_UNSUPPORTED,		// HTTP_BODY_XML
	HTTP_BODY_UNSUPPORTED,		// HTTP_BODY_YAML
	HTTP_BODY_INVALID,		// HTTP_BODY_HTML
	HTTP_BODY_PLAIN			// HTTP_BODY_PLAIN
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
DIAG_OPTIONAL
DIAG_OFF(disabled-macro-expansion)
#define SET_OPTION(_x, _y)\
do {\
	if ((ret = curl_easy_setopt(candle, _x, _y)) != CURLE_OK) {\
		option = STRINGIFY(_x);\
		goto error;\
	}\
} while (0)

const unsigned long http_curl_auth[HTTP_AUTH_NUM_ENTRIES] = {
	0,			// HTTP_AUTH_UNKNOWN
	0,			// HTTP_AUTH_NONE
	CURLOPT_TLSAUTH_SRP,	// HTTP_AUTH_TLS_SRP
	CURLAUTH_BASIC,		// HTTP_AUTH_BASIC
	CURLAUTH_DIGEST,	// HTTP_AUTH_DIGEST
	CURLAUTH_DIGEST_IE,	// HTTP_AUTH_DIGEST_IE
	CURLAUTH_GSSNEGOTIATE,	// HTTP_AUTH_GSSNEGOTIATE
	CURLAUTH_NTLM,		// HTTP_AUTH_NTLM
	CURLAUTH_NTLM_WB,	// HTTP_AUTH_NTLM_WB
	CURLAUTH_ANY,		// HTTP_AUTH_ANY
	CURLAUTH_ANYSAFE	// HTTP_AUTH_ANY_SAFE
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
 * @see fr_str2int
 * @see fr_int2str
 */
const FR_NAME_NUMBER http_method_table[] = {
	{ "UNKNOWN",				HTTP_METHOD_UNKNOWN	},
	{ "GET",				HTTP_METHOD_GET		},
	{ "POST",				HTTP_METHOD_POST	},
	{ "PUT",				HTTP_METHOD_PUT		},
	{ "PATCH",				HTTP_METHOD_PATCH	},
	{ "DELETE",				HTTP_METHOD_DELETE	},

	{  NULL , -1 }
};

/** Conversion table for type config values.
 *
 * Textual names for http_body_type_t enum values, used by the
 * configuration parser.
 *
 * @see http_body_Type_t
 * @see fr_str2int
 * @see fr_int2str
 */
const FR_NAME_NUMBER http_body_type_table[] = {
	{ "unknown",				HTTP_BODY_UNKNOWN	},
	{ "unsupported",			HTTP_BODY_UNSUPPORTED	},
	{ "unavailable",			HTTP_BODY_UNAVAILABLE	},
	{ "invalid",				HTTP_BODY_INVALID	},
	{ "none",				HTTP_BODY_NONE		},
	{ "post",				HTTP_BODY_POST		},
	{ "json",				HTTP_BODY_JSON		},
	{ "xml",				HTTP_BODY_XML		},
	{ "yaml",				HTTP_BODY_YAML		},
	{ "html",				HTTP_BODY_HTML		},
	{ "plain",				HTTP_BODY_PLAIN		},

	{  NULL , -1 }
};

const FR_NAME_NUMBER http_auth_table[] = {
	{ "none",				HTTP_AUTH_NONE		},
	{ "srp",				HTTP_AUTH_TLS_SRP	},
	{ "basic",				HTTP_AUTH_BASIC		},
	{ "digest",				HTTP_AUTH_DIGEST	},
	{ "digest-ie",				HTTP_AUTH_DIGEST_IE	},
	{ "gss-negotiate",			HTTP_AUTH_GSSNEGOTIATE	},
	{ "ntlm",				HTTP_AUTH_NTLM		},
	{ "ntlm-winbind",			HTTP_AUTH_NTLM_WB	},
	{ "any",				HTTP_AUTH_ANY		},
	{ "safe",				HTTP_AUTH_ANY_SAFE	},

	{  NULL , -1 }
};

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
 * @see fr_str2int
 * @see fr_int2str
 */
const FR_NAME_NUMBER http_content_type_table[] = {
	{ "application/x-www-form-urlencoded",	HTTP_BODY_POST		},
	{ "application/json",			HTTP_BODY_JSON		},
	{ "text/html",				HTTP_BODY_HTML		},
	{ "text/plain",				HTTP_BODY_PLAIN		},
	{ "text/xml",				HTTP_BODY_XML		},
	{ "text/yaml",				HTTP_BODY_YAML		},
	{ "text/x-yaml",			HTTP_BODY_YAML		},
	{ "application/yaml",			HTTP_BODY_YAML		},
	{ "application/x-yaml",			HTTP_BODY_YAML		},

	{  NULL , -1 }
};

/*
 *	Encoder specific structures.
 *	@todo split encoders/decoders into submodules.
 */
typedef struct rest_custom_data {
	char const	*start;	//!< Start of the buffer.
	char const	*p;	//!< how much text we've sent so far.
	size_t		len;	//!< Length of data
} rest_custom_data_t;

#ifdef HAVE_JSON
/** Flags to control the conversion of JSON values to VALUE_PAIRs.
 *
 * These fields are set when parsing the expanded format for value pairs in
 * JSON, and control how json_pair_alloc_leaf and json_pair_alloc convert the JSON
 * value, and move the new VALUE_PAIR into an attribute list.
 *
 * @see json_pair_alloc
 * @see json_pair_alloc_leaf
 */
typedef struct json_flags {
	int do_xlat;		//!< If true value will be expanded with xlat.
	int is_json;		//!< If true value will be inserted as raw JSON
				// (multiple values not supported).
	FR_TOKEN op;		//!< The operator that determines how the new VP
				// is processed. @see fr_tokens_table
} json_flags_t;
#endif

/** Frees a libcurl handle, and any additional memory used by context data.
 *
 * @param[in] randle rlm_rest_handle_t to close and free.
 * @return returns true.
 */
static int _mod_conn_free(rlm_rest_handle_t *randle)
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
 * Creates an instances of rlm_rest_handle_t, and rlm_rest_curl_context_t
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
void *mod_conn_create(TALLOC_CTX *ctx, void *instance, UNUSED struct timeval const *timeout)
{
	rlm_rest_t const	*inst = instance;

	rlm_rest_handle_t	*randle = NULL;
	rlm_rest_curl_context_t	*curl_ctx = NULL;

	CURL			*candle;

	candle = curl_easy_init();
	if (!candle) {
		ERROR("Failed to create CURL handle");
		return NULL;
	}

	/*
	 *  Allocate memory for the connection handle abstraction.
	 */
	randle = talloc_zero(ctx, rlm_rest_handle_t);
	curl_ctx = talloc_zero(randle, rlm_rest_curl_context_t);

	curl_ctx->headers = NULL; /* CURL needs this to be NULL */
	curl_ctx->request.instance = inst;

	randle->ctx = curl_ctx;
	randle->candle = candle;
	talloc_set_destructor(randle, _mod_conn_free);

	return randle;
}

/** Copies a pre-expanded xlat string to the output buffer
 *
 * @param[out] out Char buffer to write encoded data to.
 * @param[in] size Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb Multiply by size to get the length of ptr.
 * @param[in] userdata rlm_rest_request_t to keep encoding state between calls.
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
	rad_assert(data->start);
	rad_assert(data->p);

	to_copy = data->len - (data->p - data->start);
	len = to_copy > freespace ? freespace : to_copy;
	if (len == 0) return 0;

	memcpy(out, data->p, len);
	data->p += len;

	return len;
}

/** Encodes VALUE_PAIR linked list in POST format
 *
 * This is a stream function matching the rest_read_t prototype. Multiple
 * successive calls will return additional encoded VALUE_PAIRs.
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
 * @param[out] out Char buffer to write encoded data to.
 * @param[in] size Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb Multiply by size to get the length of ptr.
 * @param[in] userdata rlm_rest_request_t to keep encoding state between calls.
 * @return
 *	- Length of data (including NULL) written to ptr.
 *	- 0 if no more data to write.
 */
static size_t rest_encode_post(void *out, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_request_t	*ctx = userdata;
	REQUEST			*request = ctx->request; /* Used by RDEBUG */
	VALUE_PAIR		*vp;

	char *p = out;		/* Position in buffer */
	char *encoded = p;	/* Position in buffer of last fully encoded attribute or value */
	char *escaped;		/* Pointer to current URL escaped data */

	size_t len = 0;
	size_t freespace = (size * nmemb) - 1;

	/* Allow manual chunking */
	if ((ctx->chunk) && (ctx->chunk <= freespace)) {
		freespace = (ctx->chunk - 1);
	}

	if (ctx->state == READ_STATE_END) return 0;

	/* Post data requires no headers */
	if (ctx->state == READ_STATE_INIT) ctx->state = READ_STATE_ATTR_BEGIN;

	while (freespace > 0) {
		vp = fr_cursor_current(&ctx->cursor);
		if (!vp) {
			ctx->state = READ_STATE_END;

			break;
		}

		RDEBUG2("Encoding attribute \"%s\"", vp->da->name);

		if (ctx->state == READ_STATE_ATTR_BEGIN) {
			escaped = curl_escape(vp->da->name, strlen(vp->da->name));
			if (!escaped) {
				REDEBUG("Failed escaping string \"%s\"", vp->da->name);
				return 0;
			}

			len = strlen(escaped);
			if (freespace < (1 + len)) {
				curl_free(escaped);
				goto no_space;
			}

			len = sprintf(p, "%s=", escaped);
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
		len = fr_pair_value_snprint(p, freespace, vp, 0);
		if (is_truncated(len, freespace)) goto no_space;

		RINDENT();
		RDEBUG3("Length : %zd", len);
		REXDENT();
		if (len > 0) {
			escaped = curl_escape(p, len);
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
		if (fr_cursor_next(&ctx->cursor)) {
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

	/*
	 *  Cleanup for error conditions
	 */
no_space:
	*encoded = '\0';

	len = encoded - (char *)out;

	RDEBUG3("POST Data: %s", (char *)out);

	/*
	 *  The buffer wasn't big enough to encode a single attribute chunk.
	 */
	if (len == 0) {
		REDEBUG("Failed encoding attribute");
	} else {
		RDEBUG3("Returning %zd bytes of POST data (buffer full or chunk exceeded)", len);
	}

	return len;
}

#ifdef HAVE_JSON
/** Encodes VALUE_PAIR linked list in JSON format
 *
 * This is a stream function matching the rest_read_t prototype. Multiple
 * successive calls will return additional encoded VALUE_PAIRs.
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
 * @param[out] out Char buffer to write encoded data to.
 * @param[in] size Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb Multiply by size to get the length of ptr.
 * @param[in] userdata rlm_rest_request_t to keep encoding state between calls.
 * @return
 *	- Length of data (including NULL) written to ptr.
 *	- 0 if no more data to write.
 */
static size_t rest_encode_json(void *out, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_request_t	*ctx = userdata;
	REQUEST *request = ctx->request;
	rest_custom_data_t *data = ctx->encoder;

	size_t freespace = (size * nmemb) - 1;		/* account for the \0 byte here */
	size_t len;
	size_t to_copy;
	const char *encoded;

	rad_assert(freespace > 0);

	if (ctx->state == READ_STATE_INIT) {
		encoded = fr_json_afrom_pair_list(data, &request->packet->vps, NULL);
		if (!encoded) return -1;

		data->start = data->p = encoded;
		data->len = strlen(encoded);

		RDEBUG3("JSON Data: %s", encoded);
		RDEBUG3("Returning %zd bytes of JSON data", data->len);

		ctx->state = READ_STATE_ATTR_BEGIN;
	}

	to_copy = data->len - (data->p - data->start);
	len = to_copy > freespace ? freespace : to_copy;

	if (len == 0) {
		return 0;
	} else {
		memcpy(out, data->p, len);
		data->p += len;
		return len;
	}
}
#endif

/** Emulates successive libcurl calls to an encoding function
 *
 * This function is used when the request will be sent to the HTTP server as one
 * contiguous entity. A buffer of REST_BODY_INIT bytes is allocated and passed
 * to the stream encoding function.
 *
 * If the stream function does not return 0, a new buffer is allocated which is
 * the size of the previous buffer + REST_BODY_INIT bytes, the data from the
 * previous buffer is copied, and freed, and another call is made to the stream
 * function, passing a pointer into the new buffer at the end of the previously
 * written data.
 *
 * This process continues until the stream function signals (by returning 0)
 * that it has no more data to write.
 *
 * @param[out] out where the pointer to the alloced buffer should
 *	be written.
 * @param[in] inst of rlm_rest.
 * @param[in] func Stream function.
 * @param[in] limit Maximum buffer size to alloc.
 * @param[in] userdata rlm_rest_request_t to keep encoding state between calls to
 *	stream function.
 * @return
 *	- Length of the data written to the buffer (excluding NULL).
 *	- -1 if alloc >= limit.
 */
static ssize_t rest_request_encode_wrapper(char **out, rlm_rest_t const *inst,
					   rest_read_t func, size_t limit, void *userdata)
{
	char *buff = NULL;

	size_t alloc = REST_BODY_INIT;	/* Size of buffer to alloc */
	size_t used = 0;		/* Size of data written */
	size_t len = 0;

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
 * @param[in] request Current request.
 * @param[in] ctx to initialise.
 *	pointer array.
 */
static void rest_request_init(REQUEST *request, rlm_rest_request_t *ctx)
{
	/*
	 * 	Setup stream read data
	 */
	ctx->request = request;
	ctx->state = READ_STATE_INIT;
}

/** Converts plain response into a single VALUE_PAIR
 *
 * @param[in] inst configuration data.
 * @param[in] section configuration data.
 * @param[in] handle rlm_rest_handle_t to use.
 * @param[in] request Current request.
 * @param[in] raw buffer containing POST data.
 * @param[in] rawlen Length of data in raw buffer.
 * @return
 *	- Number of VALUE_PAIR processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_plain(rlm_rest_t const *inst, UNUSED rlm_rest_section_t const *section,
			     REQUEST *request, UNUSED void *handle, char *raw, size_t rawlen)
{
	VALUE_PAIR		*vp;

	/*
	 *  Empty response?
	 */
	if (*raw == '\0') return 0;

	/*
	 *  Use rawlen to protect against overrun, and to cope with any binary data
	 */
	MEM(pair_update_request(&vp, attr_rest_http_body) >= 0);
	fr_pair_value_bstrncpy(vp, raw, rawlen);

	RDEBUG2("&%pP", vp);

	return 1;
}

/** Converts POST response into VALUE_PAIRs and adds them to the request
 *
 * Accepts VALUE_PAIRS in the same format as rest_encode_post, but with the
 * addition of optional attribute list qualifiers as part of the attribute name
 * string.
 *
 * If no qualifiers are specified, will default to the request list.
 *
 * POST response format is:
 * @verbatim [outer.][<list>:]<attribute0>=<value0>&[outer.][<list>:]<attribute1>=<value1>&[outer.][<list>:]<attributeN>=<valueN> @endverbatim
 *
 * @see rest_encode_post
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in] handle rlm_rest_handle_t to use.
 * @param[in] request Current request.
 * @param[in] raw buffer containing POST data.
 * @param[in] rawlen Length of data in raw buffer.
 * @return
 *	- Number of VALUE_PAIRs processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_post(UNUSED rlm_rest_t const *instance, UNUSED rlm_rest_section_t const *section,
			    REQUEST *request, void *handle, char *raw, size_t rawlen)
{
	rlm_rest_handle_t	*randle = handle;
	CURL			*candle = randle->candle;

	char const *p = raw, *q;

	char const *attribute;
	char *name  = NULL;
	char *value = NULL;

	char *expanded = NULL;

	fr_dict_attr_t const *da;
	VALUE_PAIR *vp;

	pair_lists_t list_name;
	request_refs_t request_name;
	REQUEST *reference = request;
	VALUE_PAIR **vps;
	TALLOC_CTX *ctx;

	size_t len;
	int curl_len; /* Length from last curl_easy_unescape call */

	int count = 0;
	int ret;

	/*
	 *	Empty response?
	 */
	while (isspace(*p)) p++;
	if (*p == '\0') return 0;

	while (((q = strchr(p, '=')) != NULL) && (count < REST_BODY_MAX_ATTRS)) {
		reference = request;

		name = curl_easy_unescape(candle, p, (q - p), &curl_len);
		p = (q + 1);

		RDEBUG2("Parsing attribute \"%s\"", name);

		/*
		 *  The attribute pointer is updated to point to the portion of
		 *  the string after the list qualifier.
		 */
		attribute = name;
		attribute += radius_request_name(&request_name, attribute, REQUEST_CURRENT);
		if (request_name == REQUEST_UNKNOWN) {
			RWDEBUG("Invalid request qualifier, skipping");

			curl_free(name);

			continue;
		}

		if (radius_request(&reference, request_name) < 0) {
			RWDEBUG("Attribute name refers to outer request but not in a tunnel, skipping");

			curl_free(name);

			continue;
		}

		attribute += radius_list_name(&list_name, attribute, PAIR_LIST_REPLY);
		if (list_name == PAIR_LIST_UNKNOWN) {
			RWDEBUG("Invalid list qualifier, skipping");
			curl_free(name);

			continue;
		}

		da = fr_dict_attr_by_name(request->dict, attribute);
		if (!da) {
			RWDEBUG("Attribute \"%s\" unknown, skipping", attribute);

			curl_free(name);

			continue;
		}

		vps = radius_list(reference, list_name);
		rad_assert(vps);

		RINDENT();
		RDEBUG3("Type  : %s", fr_int2str(fr_value_box_type_names, da->type, "<INVALID>"));

		ctx = radius_list_ctx(reference, list_name);

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

		RDEBUG2("Performing xlat expansion of response value");

		if (xlat_aeval(request, &expanded, request, value, NULL, NULL) < 0) {
			goto skip;
		}

		vp = fr_pair_afrom_da(ctx, da);
		if (!vp) {
			REDEBUG("Failed creating valuepair");
			talloc_free(expanded);

			goto error;
		}

		ret = fr_pair_value_from_str(vp, expanded, -1, '\0', true);
		TALLOC_FREE(expanded);
		if (ret < 0) {
			RWDEBUG("Incompatible value assignment, skipping");
			talloc_free(vp);
			goto skip;
		}

		fr_pair_add(vps, vp);

		count++;

	skip:
		curl_free(name);
		curl_free(value);

		continue;

	error:
		curl_free(name);
		curl_free(value);

		return count;
	}

	if (!count) {
		REDEBUG("Malformed POST data \"%s\"", raw);
	}

	return count;

}

#ifdef HAVE_JSON
/** Converts JSON "value" key into VALUE_PAIR.
 *
 * If leaf is not in fact a leaf node, but contains JSON data, the data will
 * written to the attribute in JSON string format.
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in] ctx to allocate new VALUE_PAIRs in.
 * @param[in] request Current request.
 * @param[in] da Attribute to create.
 * @param[in] flags containing the operator other flags controlling value
 *	expansion.
 * @param[in] leaf object containing the VALUE_PAIR value.
 * @return
 *	- #VALUE_PAIR just created.
 *	- NULL on error.
 */
static VALUE_PAIR *json_pair_alloc_leaf(UNUSED rlm_rest_t const *instance, UNUSED rlm_rest_section_t const *section,
				      TALLOC_CTX *ctx, REQUEST *request,
				      fr_dict_attr_t const *da, json_flags_t *flags, json_object *leaf)
{
	char const	*value;
	char		*expanded = NULL;
	int 		ret;

	VALUE_PAIR	*vp;

	fr_value_box_t	src;

	if (fr_json_object_is_type(leaf, json_type_null)) {
		RDEBUG3("Got null value for attribute \"%s\" (skipping)", da->name);
		return NULL;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) {
		RWDEBUG("Failed creating valuepair for attribute \"%s\" (skipping)", da->name);
		talloc_free(expanded);

		return NULL;
	}

	memset(&src, 0, sizeof(src));

	switch (json_object_get_type(leaf)) {
	case json_type_int:
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'int', attribute \"%s\"", da->name);
		src.vb_int32 = json_object_get_int(leaf);
		src.type = FR_TYPE_INT32;
		break;

	case json_type_double:
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'double', attribute \"%s\"", da->name);
		src.vb_float64 = json_object_get_double(leaf);
		src.type = FR_TYPE_FLOAT64;
		break;

	case json_type_string:
		value = json_object_get_string(leaf);
		if (flags->do_xlat) {
			if (xlat_aeval(request, &expanded, request, value, NULL, NULL) < 0) return NULL;
			src.vb_strvalue = expanded;
			src.datum.length = talloc_array_length(src.vb_strvalue) - 1;
		} else {
			src.vb_strvalue = value;
			src.datum.length = json_object_get_string_len(leaf);
		}
		src.type = FR_TYPE_STRING;

		break;

	default:
		if (flags->do_xlat) RWDEBUG("Ignoring do_xlat on 'object', attribute \"%s\"", da->name);

		/*
		 *	Should encode any nested JSON structures into JSON strings.
		 *
		 *	"I knew you liked JSON so I put JSON in your JSON!"
		 */
		src.vb_strvalue = json_object_get_string(leaf);
		if (!src.vb_strvalue) {
			RWDEBUG("Failed getting string value for attribute \"%s\" (skipping)", da->name);

			return NULL;
		}
		src.type = FR_TYPE_STRING;
		src.datum.length = strlen(src.vb_strvalue);
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

/** Processes JSON response and converts it into multiple VALUE_PAIRs
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
 *			   VALUE_PAIR in string form. Defaults to true.
 *  - op	(optional) Controls how the attribute is inserted into
 *			   the target list. Defaults to ':=' (T_OP_SET).
 *
 * If "op" is ':=' or '=', it will be automagically changed to '+=' for the
 * second and subsequent values in multivalued attributes. This does not work
 * between multiple attribute declarations.
 *
 * @see fr_tokens_table
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in] request Current request.
 * @param[in] object containing root node, or parent node.
 * @param[in] level Current nesting level.
 * @param[in] max counter, decremented after each VALUE_PAIR is created,
 * 	      when 0 no more attributes will be processed.
 * @return
 *	- Number of attributes created.
 *	- < 0 on error.
 */
static int json_pair_alloc(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			 REQUEST *request, json_object *object, UNUSED int level, int max)
{
	int max_attrs = max;
	vp_tmpl_t *dst = NULL;

	if (!fr_json_object_is_type(object, json_type_object)) {
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
	json_object_object_foreach(object, name, value) {
		int i = 0, elements;
		struct json_object *element, *tmp;
		TALLOC_CTX *ctx;

		json_flags_t flags = {
			.op = T_OP_SET,
			.do_xlat = 1,
			.is_json = 0
		};

		REQUEST *current = request;
		VALUE_PAIR **vps, *vp = NULL;

		TALLOC_FREE(dst);

		/*
		 *  Resolve attribute name to a dictionary entry and pairlist.
		 */
		RDEBUG2("Parsing attribute \"%s\"", name);

		if (tmpl_afrom_attr_str(request, &dst, name,
					&(vp_tmpl_rules_t){
						.dict_def = request->dict,
						.list_def = PAIR_LIST_REPLY
					}) <= 0) {
			RPWDEBUG("Failed parsing attribute (skipping)");
			continue;
		}

		if (radius_request(&current, dst->tmpl_request) < 0) {
			RWDEBUG("Attribute name refers to outer request but not in a tunnel (skipping)");
			continue;
		}

		vps = radius_list(current, dst->tmpl_list);
		if (!vps) {
			RWDEBUG("List not valid in this context (skipping)");
			continue;
		}
		ctx = radius_list_ctx(current, dst->tmpl_list);

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
		if (fr_json_object_is_type(value, json_type_object)) {
			/*
			 *  Process operator if present.
			 */
			if (json_object_object_get_ex(value, "op", &tmp)) {
				flags.op = fr_str2int(fr_tokens_table, json_object_get_string(tmp), 0);
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
		}

		/*
		 *  Setup fr_pair_alloc / recursion loop.
		 */
		if (!flags.is_json && fr_json_object_is_type(value, json_type_array)) {
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
		 *  over each of them, creating a new VALUE_PAIR.
		 */
		do {
			if (max_attrs-- <= 0) {
				RWDEBUG("At maximum attribute limit");
				return max;
			}

			/*
			 *  Automagically switch the op for multivalued attributes.
			 */
			if (((flags.op == T_OP_SET) || (flags.op == T_OP_EQ)) && (i >= 1)) {
				flags.op = T_OP_ADD;
			}

			if (fr_json_object_is_type(element, json_type_object) && !flags.is_json) {
				/* TODO: Insert nested VP into VP structure...*/
				RWDEBUG("Found nested VP, these are not yet supported (skipping)");

				continue;

				/*
				vp = json_pair_alloc(instance, section,
						   request, value,
						   level + 1, max_attrs);*/
			} else {
				vp = json_pair_alloc_leaf(instance, section, ctx, request,
							  dst->tmpl_da, &flags, element);
				if (!vp) continue;
			}
			RDEBUG2("&%pP", vp);
			radius_pairmove(current, vps, vp, false);
		/*
		 *  If we call json_object_array_get_idx on something that's not an array
		 *  the behaviour appears to be to occasionally segfault.
		 */
		} while ((++i < elements) && (element = json_object_array_get_idx(value, i)));
	}

	talloc_free(dst);

	return max - max_attrs;
}

/** Converts JSON response into VALUE_PAIRs and adds them to the request.
 *
 * Converts the raw JSON string into a json-c object tree and passes it to
 * json_pair_alloc. After the tree has been parsed json_object_put is called
 * which decrements the reference count of the root node by one, and frees
 * the entire tree.
 *
 * @see rest_encode_json
 * @see json_pair_alloc
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in,out] request Current request.
 * @param[in] handle REST handle.
 * @param[in] raw buffer containing JSON data.
 * @param[in] rawlen Length of data in raw buffer.
 * @return
 *	- The number of #VALUE_PAIR processed.
 *	- -1 on unrecoverable error.
 */
static int rest_decode_json(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			    REQUEST *request, UNUSED void *handle, char *raw, UNUSED size_t rawlen)
{
	char const *p = raw;

	struct json_object *json;

	int ret;

	/*
	 *  Empty response?
	 */
	while (isspace(*p)) p++;
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
 * @param[in] in Char buffer where inbound header data is written.
 * @param[in] size Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb Multiply by size to get the length of ptr.
 * @param[in] userdata rlm_rest_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t rest_response_header(void *in, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_response_t *ctx = userdata;
	REQUEST *request = ctx->request; /* Used by RDEBUG */

	char const *p = in, *q;

	size_t const t = (size * nmemb);
	size_t s = t;
	size_t len;

	http_body_type_t type;

	/*
	 *  This seems to be curl's indication there are no more header lines.
	 */
	if (t == 2 && ((p[0] == '\r') && (p[1] == '\n'))) {
		/*
		 *  If we got a 100 Continue, we need to send additional payload data.
		 *  reset the state to WRITE_STATE_INIT, so that when were called again
		 *  we overwrite previous header data with that from the proper header.
		 */
		if (ctx->code == 100) {
			RDEBUG2("Continuing...");
			ctx->state = WRITE_STATE_INIT;
		}

		return t;
	}

	switch (ctx->state) {
	case WRITE_STATE_INIT:
		RDEBUG2("Processing response header");

		/*
		 *  HTTP/<version> <reason_code>[ <reason_phrase>]\r\n
		 *
		 *  "HTTP/1.1 " (8) + "100 " (4) + "\r\n" (2) = 14
		 */
		if (s < 14) {
			REDEBUG("Malformed HTTP header: Status line too short");
			goto malformed;
		}
		/*
		 *  Check start of header matches...
		 */
		if (strncasecmp("HTTP/", p, 5) != 0) {
			REDEBUG("Malformed HTTP header: Missing HTTP version");
			goto malformed;
		}
		p += 5;
		s -= 5;

		/*
		 *  Skip the version field, next space should mark start of reason_code.
		 */
		q = memchr(p, ' ', s);
		if (!q) {
			RDEBUG("Malformed HTTP header: Missing reason code");
			goto malformed;
		}

		s -= (q - p);
		p  = q;

		/*
		 *  Process reason_code.
		 *
		 *  " 100" (4) + "\r\n" (2) = 6
		 */
		if (s < 6) {
			REDEBUG("Malformed HTTP header: Reason code too short");
			goto malformed;
		}
		p++;
		s--;

		/*  Char after reason code must be a space, or \r */
		if (!((p[3] == ' ') || (p[3] == '\r'))) goto malformed;

		ctx->code = atoi(p);

		/*
		 *  Process reason_phrase (if present).
		 */
		RINDENT();
		if (p[3] == ' ') {
			p += 4;
			s -= 4;

			q = memchr(p, '\r', s);
			if (!q) goto malformed;

			len = (q - p);

			RDEBUG2("Status : %i (%.*s)", ctx->code, (int) len, p);
		} else {
			RDEBUG2("Status : %i", ctx->code);
		}
		REXDENT();

		ctx->state = WRITE_STATE_PARSE_HEADERS;

		break;

	case WRITE_STATE_PARSE_HEADERS:
		if ((s >= 14) &&
		    (strncasecmp("Content-Type: ", p, 14) == 0)) {
			p += 14;
			s -= 14;

			/*
			 *  Check to see if there's a parameter separator.
			 */
			q = memchr(p, ';', s);

			/*
			 *  If there's not, find the end of this header.
			 */
			if (!q) q = memchr(p, '\r', s);

			len = !q ? s : (size_t) (q - p);
			type = fr_substr2int(http_content_type_table, p, HTTP_BODY_UNKNOWN, len);

			RINDENT();
			RDEBUG2("Type   : %s (%.*s)", fr_int2str(http_body_type_table, type, "<INVALID>"),
				(int) len, p);
			REXDENT();

			/*
			 *  Assume the force_to value has already been validated.
			 */
			if (ctx->force_to != HTTP_BODY_UNKNOWN) {
				if (ctx->force_to != ctx->type) {
					RDEBUG3("Forcing body type to \"%s\"",
						fr_int2str(http_body_type_table, ctx->force_to, "<INVALID>"));
					ctx->type = ctx->force_to;
				}
			/*
			 *  Figure out if the type is supported by one of the decoders.
			 */
			} else {
				ctx->type = http_body_type_supported[type];
				switch (ctx->type) {
				case HTTP_BODY_UNKNOWN:
					RWDEBUG("Couldn't determine type, using the request's type \"%s\".",
						fr_int2str(http_body_type_table, type, "<INVALID>"));
					break;

				case HTTP_BODY_UNSUPPORTED:
					REDEBUG("Type \"%s\" is currently unsupported",
						fr_int2str(http_body_type_table, type, "<INVALID>"));
					break;

				case HTTP_BODY_UNAVAILABLE:
					REDEBUG("Type \"%s\" is unavailable, please rebuild this module with the required "
						"library", fr_int2str(http_body_type_table, type, "<INVALID>"));
					break;

				case HTTP_BODY_INVALID:
					REDEBUG("Type \"%s\" is not a valid web API data markup format",
						fr_int2str(http_body_type_table, type, "<INVALID>"));
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

	return t;

malformed:
	{
		char escaped[1024];

		fr_snprint(escaped, sizeof(escaped), (char *) in, t, '\0');

		REDEBUG("Received %zu bytes of response data: %s", t, escaped);
		ctx->code = -1;
	}

	return (t - s);
}

/** Processes incoming HTTP body data from libcurl.
 *
 * Writes incoming body data to an intermediary buffer for later parsing by
 * one of the decode functions.
 *
 * @param[in] ptr Char buffer where inbound header data is written
 * @param[in] size Multiply by nmemb to get the length of ptr.
 * @param[in] nmemb Multiply by size to get the length of ptr.
 * @param[in] userdata rlm_rest_response_t to keep parsing state between calls.
 * @return
 *	- Length of data processed.
 *	- 0 on error.
 */
static size_t rest_response_body(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	rlm_rest_response_t *ctx = userdata;
	REQUEST *request = ctx->request; /* Used by RDEBUG */

	char const *p = ptr, *q;
	char *tmp;

	size_t const t = (size * nmemb);
	size_t needed;

	if (t == 0) return 0;

	/*
	 *  Any post processing of headers should go here...
	 */
	if (ctx->state == WRITE_STATE_PARSE_HEADERS) {
		ctx->state = WRITE_STATE_PARSE_CONTENT;
	}

	switch (ctx->type) {
	case HTTP_BODY_UNSUPPORTED:
	case HTTP_BODY_UNAVAILABLE:
	case HTTP_BODY_INVALID:
		while ((q = memchr(p, '\n', t - (p - (char *)ptr)))) {
			REDEBUG("%.*s", (int) (q - p), p);
			p = q + 1;
		}

		if (*p != '\0') REDEBUG("%.*s", (int)(t - (p - (char *)ptr)), p);

		return t;

	case HTTP_BODY_NONE:
		while ((q = memchr(p, '\n', t - (p - (char *)ptr)))) {
			RDEBUG3("%.*s", (int) (q - p), p);
			p = q + 1;
		}

		if (*p != '\0') RDEBUG3("%.*s", (int)(t - (p - (char *)ptr)), p);

		return t;

	default:
		needed = ctx->used + t + 1;
		if (needed < REST_BODY_INIT) needed = REST_BODY_INIT;

		if (needed > ctx->alloc) {
			ctx->alloc = needed;

			tmp = ctx->buffer;
			ctx->buffer = talloc_array(NULL, char, ctx->alloc);
			/* If data has been written previously */
			if (tmp) {
				memcpy(ctx->buffer, tmp, ctx->used);
				talloc_free(tmp);
			}
		}
		strlcpy(ctx->buffer + ctx->used, p, t + 1);
		ctx->used += t;	/* don't include the trailing zero */

		break;
	}

	return t;
}

/** Print out the response text as error lines
 *
 * @param request The Current request.
 * @param handle rlm_rest_handle_t used to execute the previous request.
 */
void rest_response_error(REQUEST *request, rlm_rest_handle_t *handle)
{
	char const *p, *q;
	size_t len;

	len = rest_get_handle_data(&p, handle);
	if (len == 0) {
		RERROR("Server returned no data");
		return;
	}

	RERROR("Server returned:");
	while ((q = strchr(p, '\n'))) {
		RERROR("%.*s", (int) (q - p), p);
		p = q + 1;
	}
	if (*p != '\0') RERROR("%s", p);
}

/** (Re-)Initialises the data in a rlm_rest_response_t.
 *
 * This resets the values of the a rlm_rest_response_t to their defaults.
 * Must be called between encoding sessions.
 *
 * @see rest_response_body
 * @see rest_response_header
 *
 * @param[in] request Current request.
 * @param[in] ctx data to initialise.
 * @param[in] type Default http_body_type to use when decoding raw data, may be
 * overwritten by rest_response_header.
 */
static void rest_response_init(REQUEST *request, rlm_rest_response_t *ctx, http_body_type_t type)
{
	ctx->request = request;
	ctx->type = type;
	ctx->state = WRITE_STATE_INIT;
	ctx->alloc = 0;
	ctx->used = 0;
	ctx->buffer = NULL;
}

/** Extracts pointer to buffer containing response data
 *
 * @param[out] out Where to write the pointer to the buffer.
 * @param[in] handle used for the last request.
 * @return > 0 if data is available.
 */
size_t rest_get_handle_data(char const **out, rlm_rest_handle_t *handle)
{
	rlm_rest_curl_context_t *ctx = handle->ctx;

	rad_assert(ctx->response.buffer || (!ctx->response.buffer && !ctx->response.used));

	*out = ctx->response.buffer;
	return ctx->response.used;
}

/** Configures body specific curlopts.
 *
 * Configures libcurl handle to use either chunked mode, where the request
 * data will be sent using multiple HTTP requests, or contiguous mode where
 * the request data will be sent in a single HTTP request.
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in] request Current request.
 * @param[in] handle rlm_rest_handle_t to configure.
 * @param[in] func to pass to libcurl for chunked.
 *	      transfers (NULL if not using chunked mode).
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
static int rest_request_config_body(rlm_rest_t const *instance, rlm_rest_section_t const *section,
				    REQUEST *request, rlm_rest_handle_t *handle, rest_read_t func)
{
	rlm_rest_curl_context_t *ctx = handle->ctx;
	CURL			*candle = handle->candle;

	CURLcode ret = CURLE_OK;
	char const *option = "unknown";

	ssize_t len;

	/*
	 *  We were provided with no read function, assume this means
	 *  no body should be sent.
	 */
	if (!func) {
		SET_OPTION(CURLOPT_POSTFIELDSIZE, 0);
		return 0;
	}

	/*
	 *  Chunked transfer encoding means the body will be sent in
	 *  multiple parts.
	 */
	if (section->chunk > 0) {
		SET_OPTION(CURLOPT_READDATA, &ctx->request);
		SET_OPTION(CURLOPT_READFUNCTION, func);

		return 0;
	}

	/*
	 *  If were not doing chunked encoding then we read the entire
	 *  body into a buffer, and send it in one go.
	 */
	len = rest_request_encode_wrapper(&ctx->body, instance, func, REST_BODY_MAX_LEN, &ctx->request);
	if (len <= 0) {
		REDEBUG("Failed creating HTTP body content");
		return -1;
	}
	RDEBUG2("Content-Length will be %zu bytes", len);

	rad_assert((len == 0) || (talloc_array_length(ctx->body) >= (size_t)len));
	SET_OPTION(CURLOPT_POSTFIELDS, ctx->body);
	SET_OPTION(CURLOPT_POSTFIELDSIZE, len);

	return 0;

error:
	REDEBUG("Failed setting curl option %s: %s (%i)", option, curl_easy_strerror(ret), ret);

	return -1;
}

/** Configures request curlopts.
 *
 * Configures libcurl handle setting various curlopts for things like local
 * client time, Content-Type, and other FreeRADIUS custom headers.
 *
 * Current FreeRADIUS custom headers are:
 *  - X-FreeRADIUS-Section	The module section being processed.
 *  - X-FreeRADIUS-Server	The current virtual server the REQUEST is
 *				passing through.
 *
 * Sets up callbacks for all response processing (buffers and body data).
 *
 * @param[in] inst		configuration data.
 * @param[in] t			Thread specific instance data.
 * @param[in] section		configuration data.
 * @param[in] handle		to configure.
 * @param[in] request		Current request.
 * @param[in] method		to use (HTTP verbs PUT, POST, DELETE etc...).
 * @param[in] type		Content-Type for request encoding, also sets
 *				the default for decoding.
 * @param[in] username		to use for HTTP authentication, may be NULL in
 *				which case configured defaults will be used.
 * @param[in] password		to use for HTTP authentication, may be NULL in
 *				which case configured defaults will be used.
 * @param[in] uri		buffer containing the expanded URI to send the request to.
 * @return
 *	- 0 on success (all opts configured).
 *	- -1 on failure.
 */
int rest_request_config(rlm_rest_t const *inst, rlm_rest_thread_t *t, rlm_rest_section_t const *section,
			REQUEST *request, void *handle, http_method_t method,
			http_body_type_t type,
			char const *uri, char const *username, char const *password)
{
	rlm_rest_handle_t	*randle	= handle;
	rlm_rest_curl_context_t	*ctx = randle->ctx;
	CURL			*candle = randle->candle;
	struct timeval		timeout;

	http_auth_type_t	auth = section->auth;

	CURLcode	ret = CURLE_OK;
	char const	*option = "unknown";
	char const	*content_type;

	VALUE_PAIR 	*header;
	fr_cursor_t	headers;

	char buffer[512];

	rad_assert(candle);
	rad_assert((!username && !password) || (username && password));

	buffer[(sizeof(buffer) - 1)] = '\0';

	/*
	 *	Setup any header options and generic headers.
	 */
	SET_OPTION(CURLOPT_URL, uri);
	if (section->proxy) SET_OPTION(CURLOPT_PROXY, section->proxy);
	SET_OPTION(CURLOPT_NOSIGNAL, 1);
	SET_OPTION(CURLOPT_USERAGENT, "FreeRADIUS " RADIUSD_VERSION_STRING);

	/*
	 *	HTTP/1.1 doesn't require a content type, so only set it
	 *	if we were provided with one explicitly.
	 */
	if (type != HTTP_BODY_NONE) {
		content_type = fr_int2str(http_content_type_table, type, section->body_str);
		snprintf(buffer, sizeof(buffer), "Content-Type: %s", content_type);
		ctx->headers = curl_slist_append(ctx->headers, buffer);
		if (!ctx->headers) goto error_header;
	}

	timeout = fr_pool_timeout(t->pool);
	DEBUG3("CONNECT TIMEOUT IS %" PRIu64", REQUEST TIMEOUT IS %" PRIu64,
	       FR_TIMEVAL_TO_MS(&timeout), FR_TIMEVAL_TO_MS(&section->timeout_tv));
	SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, FR_TIMEVAL_TO_MS(&timeout));
	SET_OPTION(CURLOPT_TIMEOUT_MS, FR_TIMEVAL_TO_MS(&section->timeout_tv));

#ifdef CURLOPT_PROTOCOLS
	SET_OPTION(CURLOPT_PROTOCOLS, (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

	/*
	 *	FreeRADIUS custom headers
	 */
	RDEBUG3("Adding custom headers:");
	RINDENT();
	snprintf(buffer, sizeof(buffer), "X-FreeRADIUS-Section: %s", section->name);
	RDEBUG3("%s", buffer);
	ctx->headers = curl_slist_append(ctx->headers, buffer);
	if (!ctx->headers) goto error_header;

	snprintf(buffer, sizeof(buffer), "X-FreeRADIUS-Server: %s", cf_section_name2(request->server_cs));
	RDEBUG3("%s", buffer);
	ctx->headers = curl_slist_append(ctx->headers, buffer);
	if (!ctx->headers) goto error_header;

	for (header =  fr_cursor_iter_by_da_init(&headers, &request->control, attr_rest_http_header);
	     header;
	     header = fr_cursor_next(&headers)) {
		header = fr_cursor_remove(&headers);
		if (!strchr(header->vp_strvalue, ':')) {
			RWDEBUG("Invalid HTTP header \"%s\" must be in format '<attribute>: <value>'.  Skipping...",
				header->vp_strvalue);
			talloc_free(header);
			continue;
		}
		RDEBUG3("%s", header->vp_strvalue);
		ctx->headers = curl_slist_append(ctx->headers, header->vp_strvalue);
		talloc_free(header);
	}
	REXDENT();

	/*
	 *	Configure HTTP verb (GET, POST, PUT, PATCH, DELETE, other...)
	 */
	switch (method) {
	case HTTP_METHOD_GET:
		SET_OPTION(CURLOPT_HTTPGET, 1L);
		break;

	case HTTP_METHOD_POST:
		SET_OPTION(CURLOPT_POST, 1L);
		break;

	case HTTP_METHOD_PUT:
		/*
		 *	Do not set CURLOPT_PUT, this will cause libcurl
		 *	to ignore CURLOPT_POSTFIELDs and attempt to read
		 *	whatever was set with CURLOPT_READDATA, which by
		 *	default is stdin.
		 *
		 *	This is many cases will cause the server to block,
		 *	indefinitely.
		 */
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "PUT");
		break;

	case HTTP_METHOD_PATCH:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "PATCH");
		break;

	case HTTP_METHOD_DELETE:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "DELETE");
		break;

	case HTTP_METHOD_CUSTOM:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, section->method_str);
		break;

	default:
		rad_assert(0);
		break;
	};

	/*
	 *	Set user based authentication parameters
	 */
	if (auth) {
		if ((auth >= HTTP_AUTH_BASIC) &&
		    (auth <= HTTP_AUTH_ANY_SAFE)) {
			SET_OPTION(CURLOPT_HTTPAUTH, http_curl_auth[auth]);

			if (username) {
				SET_OPTION(CURLOPT_USERNAME, username);
			} else if (section->username) {
				if (xlat_eval(buffer, sizeof(buffer), request, section->username, NULL, NULL) < 0) {
					option = STRINGIFY(CURLOPT_USERNAME);
					goto error;
				}
				SET_OPTION(CURLOPT_USERNAME, buffer);
			}

			if (password) {
				SET_OPTION(CURLOPT_PASSWORD, password);
			} else if (section->password) {
				if (xlat_eval(buffer, sizeof(buffer), request, section->password, NULL, NULL) < 0) {
					option = STRINGIFY(CURLOPT_PASSWORD);
					goto error;
				}
				SET_OPTION(CURLOPT_PASSWORD, buffer);
			}
#ifdef CURLOPT_TLSAUTH_USERNAME
		} else if (auth == HTTP_AUTH_TLS_SRP) {
			SET_OPTION(CURLOPT_TLSAUTH_TYPE, http_curl_auth[auth]);

			if (username) {
				SET_OPTION(CURLOPT_TLSAUTH_USERNAME, username);
			} else if (section->username) {
				if (xlat_eval(buffer, sizeof(buffer), request, section->username, NULL, NULL) < 0) {
					option = STRINGIFY(CURLOPT_TLSAUTH_USERNAME);
					goto error;
				}
				SET_OPTION(CURLOPT_TLSAUTH_USERNAME, buffer);
			}

			if (password) {
				SET_OPTION(CURLOPT_TLSAUTH_PASSWORD, password);
			} else if (section->password) {
				if (xlat_eval(buffer, sizeof(buffer), request, section->password, NULL, NULL) < 0) {
					option = STRINGIFY(CURLOPT_TLSAUTH_PASSWORD);
					goto error;
				}
				SET_OPTION(CURLOPT_TLSAUTH_PASSWORD, buffer);
			}
#endif
		}
	}

	/*
	 *	Set SSL/TLS authentication parameters
	 */
	if (section->tls_certificate_file) {
		SET_OPTION(CURLOPT_SSLCERT, section->tls_certificate_file);
	}

	if (section->tls_private_key_file) {
		SET_OPTION(CURLOPT_SSLKEY, section->tls_private_key_file);
	}

	if (section->tls_private_key_password) {
		SET_OPTION(CURLOPT_KEYPASSWD, section->tls_private_key_password);
	}

	if (section->tls_ca_file) {
		SET_OPTION(CURLOPT_ISSUERCERT, section->tls_ca_file);
	}

	if (section->tls_ca_path) {
		SET_OPTION(CURLOPT_CAPATH, section->tls_ca_path);
	}

	if (section->tls_random_file) {
		SET_OPTION(CURLOPT_RANDOM_FILE, section->tls_random_file);
	}

	SET_OPTION(CURLOPT_SSL_VERIFYPEER, (section->tls_check_cert == true) ? 1 : 0);
	SET_OPTION(CURLOPT_SSL_VERIFYHOST, (section->tls_check_cert_cn == true) ? 2 : 0);
	if (section->tls_extract_cert_attrs) SET_OPTION(CURLOPT_CERTINFO, 1);

	/*
	 *	Tell CURL how to get HTTP body content, and how to process incoming data.
	 */
	rest_response_init(request, &ctx->response, type);

	SET_OPTION(CURLOPT_HEADERFUNCTION, rest_response_header);
	SET_OPTION(CURLOPT_HEADERDATA, &ctx->response);
	SET_OPTION(CURLOPT_WRITEFUNCTION, rest_response_body);
	SET_OPTION(CURLOPT_WRITEDATA, &ctx->response);

	/*
	 *  Force parsing the body text as a particular encoding.
	 */
	ctx->response.force_to = section->force_to;

	switch (method) {
	case HTTP_METHOD_GET:
	case HTTP_METHOD_DELETE:
		RDEBUG3("Using a HTTP method which does not require a body.  Forcing request body type to \"none\"");
		goto finish;

	case HTTP_METHOD_POST:
	case HTTP_METHOD_PUT:
	case HTTP_METHOD_PATCH:
	case HTTP_METHOD_CUSTOM:
		if (section->chunk > 0) {
			ctx->request.chunk = section->chunk;

			ctx->headers = curl_slist_append(ctx->headers, "Expect:");
			if (!ctx->headers) goto error_header;

			ctx->headers = curl_slist_append(ctx->headers, "Transfer-Encoding: chunked");
			if (!ctx->headers) goto error_header;
		}

		RDEBUG3("Request body content-type will be \"%s\"",
			fr_int2str(http_content_type_table, type, section->body_str));
		break;

	default:
		rad_assert(0);
	};

	/*
	 *  Setup encoder specific options
	 */
	switch (type) {
	case HTTP_BODY_NONE:
		if (rest_request_config_body(inst, section, request, handle, NULL) < 0) return -1;

		break;

	case HTTP_BODY_CUSTOM_XLAT:
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
		if (rest_request_config_body(inst, section, request, handle,
					     rest_encode_custom) < 0) {
			TALLOC_FREE(ctx->request.encoder);
			return -1;
		}

		break;
	}

	case HTTP_BODY_CUSTOM_LITERAL:
	{
		rest_custom_data_t *data;

		data = talloc_zero(request, rest_custom_data_t);
		data->p = section->data;
		data->start = section->data;
		data->len = strlen(section->data);

		/* Use the encoder specific pointer to store the data we need to encode */
		ctx->request.encoder = data;
		if (rest_request_config_body(inst, section, request, handle, rest_encode_custom) < 0) {
			TALLOC_FREE(ctx->request.encoder);
			return -1;
		}
	}
		break;

#ifdef HAVE_JSON
	case HTTP_BODY_JSON:
	{
		rest_custom_data_t *data;

		data = talloc_zero(request, rest_custom_data_t);
		ctx->request.encoder = data;

		rest_request_init(request, &ctx->request);

		if (rest_request_config_body(inst, section, request, handle,
					     rest_encode_json) < 0) {
			return -1;
		}
	}

		break;
#endif

	case HTTP_BODY_POST:
		rest_request_init(request, &ctx->request);
		fr_cursor_init(&(ctx->request.cursor), &request->packet->vps);

		if (rest_request_config_body(inst, section, request, handle,
					     rest_encode_post) < 0) {
			return -1;
		}

		break;

	default:
		rad_assert(0);
	}


finish:
	SET_OPTION(CURLOPT_HTTPHEADER, ctx->headers);

	return 0;

error:
	REDEBUG("Failed setting curl option %s: %s (%i)", option, curl_easy_strerror(ret), ret);
	return -1;

error_header:
	REDEBUG("Failed creating header");
	REXDENT();
	return -1;
}

int rest_response_certinfo(rlm_rest_t const *inst, UNUSED rlm_rest_section_t const *section,
			   REQUEST *request, void *handle)
{
	rlm_rest_handle_t	*randle = handle;
	CURL			*candle = randle->candle;
	CURLcode		ret;
	int			i;
	char		 	buffer[265];
	char			*p , *q, *attr = buffer;
	fr_cursor_t		cursor, list;
	VALUE_PAIR		*cert_vps = NULL;

	/*
	 *	Examples and documentation show cert_info being
	 *	a struct curl_certinfo *, but CPP checks require
	 *	it to be a struct curl_slist *.
	 *
	 *	https://curl.haxx.se/libcurl/c/certinfo.html
	 */
	union {
		struct curl_slist    *to_info;
		struct curl_certinfo *to_certinfo;
	} ptr;
	ptr.to_info = NULL;

	fr_cursor_init(&list, &request->packet->vps);

	ret = curl_easy_getinfo(candle, CURLINFO_CERTINFO, &ptr.to_info);
	if (ret != CURLE_OK) {
		REDEBUG("Getting certificate info failed: %i - %s", ret, curl_easy_strerror(ret));

		return -1;
	}

	attr += strlcpy(attr, "TLS-Cert-", sizeof(buffer));

	RDEBUG2("Chain has %i certificate(s)", ptr.to_certinfo->num_of_certs);
	for (i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
		struct curl_slist *cert_attrs;

		RDEBUG2("Processing certificate %i",i);
		fr_cursor_init(&cursor, &cert_vps);

		for (cert_attrs = ptr.to_certinfo->certinfo[i];
		     cert_attrs;
		     cert_attrs = cert_attrs->next) {
		     	VALUE_PAIR		*vp;
		     	fr_dict_attr_t const	*da;

		     	q = strchr(cert_attrs->data, ':');
			if (!q) {
				RWDEBUG("Malformed certinfo from libcurl: %s", cert_attrs->data);
				continue;
			}

			strlcpy(attr, cert_attrs->data, (q - cert_attrs->data) + 1);
			for (p = attr; *p != '\0'; p++) if (*p == ' ') *p = '-';

			da = fr_dict_attr_by_name(dict_freeradius, buffer);
			if (!da) {
				RDEBUG3("Skipping %s += '%s'", buffer, q + 1);
				RDEBUG3("If this value is required, define attribute \"%s\"", buffer);
				continue;
			}
			MEM(vp = fr_pair_afrom_da(request->packet, da));
			fr_pair_value_from_str(vp, q + 1, -1, '\0', true);

			fr_cursor_append(&cursor, vp);
		}

		/*
		 *	Add a copy of the cert_vps to session state.
		 *
		 *	Both PVS studio and Coverity detect the condition
		 *	below as logically dead code unless we explicitly
		 *	set cert_vps.  This is because they're too dumb
		 *	to realise that the cursor argument passed to
		 *	tls_session_pairs_from_x509_cert contains a
		 *	reference to cert_vps.
		 */
		cert_vps = fr_cursor_current(&cursor);
		if (cert_vps) {
			/*
			 *	Print out all the pairs we have so far
			 */
			log_request_pair_list(L_DBG_LVL_2, request, cert_vps, NULL);
			fr_cursor_merge(&list, &cursor);
			cert_vps = NULL;
		}
	}

	return 0;
}

/** Sends the response to the correct decode function.
 *
 * Uses the Content-Type information written in rest_response_header to
 * determine the correct decode function to use. The decode function will
 * then convert the raw received data into VALUE_PAIRs.
 *
 * @param[in] instance configuration data.
 * @param[in] section configuration data.
 * @param[in] request Current request.
 * @param[in] handle to use.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int rest_response_decode(rlm_rest_t const *instance, rlm_rest_section_t const *section,
			 REQUEST *request, void *handle)
{
	rlm_rest_handle_t	*randle = handle;
	rlm_rest_curl_context_t	*ctx = randle->ctx;

	int ret = -1;	/* -Wsometimes-uninitialized */

	if (!ctx->response.buffer) {
		RDEBUG2("Skipping attribute processing, no valid body data received");
		return 0;
	}

	switch (ctx->response.type) {
	case HTTP_BODY_NONE:
		return 0;

	case HTTP_BODY_PLAIN:
		ret = rest_decode_plain(instance, section, request, handle, ctx->response.buffer, ctx->response.used);
		break;

	case HTTP_BODY_POST:
		ret = rest_decode_post(instance, section, request, handle, ctx->response.buffer, ctx->response.used);
		break;

#ifdef HAVE_JSON
	case HTTP_BODY_JSON:
		ret = rest_decode_json(instance, section, request, handle, ctx->response.buffer, ctx->response.used);
		break;
#endif

	case HTTP_BODY_UNSUPPORTED:
	case HTTP_BODY_UNAVAILABLE:
	case HTTP_BODY_INVALID:
		return -1;

	default:
		rad_assert(0);
	}

	return ret;
}

/** Cleans up after a REST request.
 *
 * Resets all options associated with a CURL handle, and frees any headers
 * associated with it.
 *
 * Calls rest_read_ctx_free and rest_response_free to free any memory used by
 * context data.
 *
 * @param[in] instance configuration data.
 * @param[in] handle to cleanup.
 */
void rest_request_cleanup(UNUSED rlm_rest_t const *instance, void *handle)
{
	rlm_rest_handle_t	*randle = handle;
	rlm_rest_curl_context_t	*ctx = randle->ctx;
	CURL			*candle = randle->candle;

	/*
	 *  Clear any previously configured options
	 */
	curl_easy_reset(candle);

	/*
	 *  Free header list
	 */
	if (ctx->headers != NULL) {
		curl_slist_free_all(ctx->headers);
		ctx->headers = NULL;
	}

	/*
	 *  Free body data (only used if chunking is disabled)
	 */


	/*
	 *  Free response data
	 */
	TALLOC_FREE(ctx->body);
	TALLOC_FREE(ctx->response.buffer);
	TALLOC_FREE(ctx->request.encoder);
	TALLOC_FREE(ctx->response.decoder);
}

/** URL encodes a string.
 *
 * Encode special chars as per RFC 3986 section 4.
 *
 * @param[in] request Current request.
 * @param[out] out Where to write escaped string.
 * @param[in] outlen Size of out buffer.
 * @param[in] raw string to be urlencoded.
 * @param[in] arg pointer, gives context for escaping.
 * @return length of data written to out (excluding NULL).
 */
size_t rest_uri_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *raw, UNUSED void *arg)
{
	char *escaped;

	escaped = curl_escape(raw, strlen(raw));
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
 * @param[out] out Where to write the pointer to the new buffer containing the escaped URI.
 * @param[in] inst of rlm_rest.
 * @param[in] uri configuration data.
 * @param[in] request Current request
 * @return
 *	- Length of data written to buffer (excluding NULL).
 *	- < 0 if an error occurred.
 */
ssize_t rest_uri_build(char **out, rlm_rest_t const *inst, REQUEST *request, char const *uri)
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
 * @param[out] out Where to write the pointer to the new buffer containing the escaped URI.
 * @param[in] inst of rlm_rest.
 * @param[in] request Current request
 * @param[in] handle to use.
 * @param[in] uri configuration data.
 * @return
 *	- Length of data written to buffer (excluding NULL).
 *	- < 0 if an error occurred.
 */
ssize_t rest_uri_host_unescape(char **out, rlm_rest_t const *inst, REQUEST *request,
			       void *handle, char const *uri)
{
	rlm_rest_handle_t	*randle = handle;
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
