#pragma once
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
 * @brief Function prototypes and datatypes for the REST (HTTP) transport.
 * @file rest.h
 *
 * @copyright 2012-2016 Arran Cudbard-Bell (a.cudbardb@freeradius.org)
 */
RCSIDH(other_h, "$Id$")

#include <freeradius-devel/server/pairmove.h>
#include <freeradius-devel/server/pool.h>
#include "config.h"

#define CURL_NO_OLDIES 1

/*
 *	We have to use this as curl uses lots of enums
 */
#ifndef CURL_AT_LEAST_VERSION
#  define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | z)
#  define CURL_AT_LEAST_VERSION(x, y, z) (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS(x, y, z))
#endif

#include <curl/curl.h>

/*
 *	The common JSON library (also tells us if we have json-c)
 */
#include <freeradius-devel/json/base.h>

#define REST_URI_MAX_LEN		2048
#define REST_BODY_MAX_LEN		8192
#define REST_BODY_ALLOC_CHUNK		1024
#define REST_BODY_MAX_ATTRS		256

typedef enum {
	REST_HTTP_METHOD_UNKNOWN = 0,
	REST_HTTP_METHOD_GET,
	REST_HTTP_METHOD_POST,
	REST_HTTP_METHOD_PUT,
	REST_HTTP_METHOD_PATCH,
	REST_HTTP_METHOD_DELETE,
	REST_HTTP_METHOD_CUSTOM		//!< Must always come last, should not be in method table
} http_method_t;

typedef enum {
	REST_HTTP_BODY_UNKNOWN = 0,
	REST_HTTP_BODY_UNSUPPORTED,
	REST_HTTP_BODY_UNAVAILABLE,
	REST_HTTP_BODY_INVALID,
	REST_HTTP_BODY_NONE,
	REST_HTTP_BODY_CUSTOM_XLAT,
	REST_HTTP_BODY_CUSTOM_LITERAL,
	REST_HTTP_BODY_POST,
	REST_HTTP_BODY_JSON,
	REST_HTTP_BODY_XML,
	REST_HTTP_BODY_YAML,
	REST_HTTP_BODY_HTML,
	REST_HTTP_BODY_PLAIN,
	REST_HTTP_BODY_NUM_ENTRIES
} http_body_type_t;

typedef enum {
	REST_HTTP_AUTH_UNKNOWN = 0,
	REST_HTTP_AUTH_NONE,
	REST_HTTP_AUTH_TLS_SRP,
	REST_HTTP_AUTH_BASIC,
	REST_HTTP_AUTH_DIGEST,
	REST_HTTP_AUTH_DIGEST_IE,
	REST_HTTP_AUTH_GSSNEGOTIATE,
	REST_HTTP_AUTH_NTLM,
	REST_HTTP_AUTH_NTLM_WB,
	REST_HTTP_AUTH_ANY,
	REST_HTTP_AUTH_ANY_SAFE,
	REST_HTTP_AUTH_NUM_ENTRIES
} http_auth_type_t;

/*
 *	Must be updated (in rest.c) if additional values are added to
 *	http_body_type_t
 */
extern const http_body_type_t http_body_type_supported[REST_HTTP_BODY_NUM_ENTRIES];

extern const unsigned long http_curl_auth[REST_HTTP_AUTH_NUM_ENTRIES];

extern fr_table_num_sorted_t const http_auth_table[];
extern size_t http_auth_table_len;

extern fr_table_num_sorted_t const http_method_table[];
extern size_t http_method_table_len;

extern fr_table_num_sorted_t const http_body_type_table[];
extern size_t http_body_type_table_len;

extern fr_table_num_sorted_t const http_content_type_table[];
extern size_t http_content_type_table_len;

/*
 *	Structure for section configuration
 */
typedef struct {
	char const		*name;		//!< Section name.
	char const		*uri;		//!< URI to send HTTP request to.

	char const		*proxy;		//!< Send request via this proxy.

	char const		*method_str;	//!< The string version of the HTTP method.
	http_method_t		method;		//!< What HTTP method should be used, GET, POST etc...

	char const		*body_str;	//!< The string version of the encoding/content type.
	http_body_type_t	body;		//!< What encoding type should be used.

	char const		*force_to_str;	//!< Force decoding with this decoder.
	http_body_type_t	force_to;	//!< Override the Content-Type header in the response
						//!< to force decoding as a particular type.

	char const		*data;		//!< Custom body data (optional).

	bool			auth_is_set;	//!< Whether a value was provided for auth_str.

	http_auth_type_t	auth;		//!< HTTP auth type.

	bool			require_auth;	//!< Whether HTTP-Auth is required or not.
	char const		*username;	//!< Username used for HTTP-Auth
	char const		*password;	//!< Password used for HTTP-Auth

	char const		*tls_certificate_file;
	char const		*tls_private_key_file;
	char const		*tls_private_key_password;
	char const		*tls_ca_file;
	char const		*tls_ca_path;
	char const		*tls_random_file;
	bool			tls_check_cert;
	bool			tls_check_cert_cn;
	bool			tls_extract_cert_attrs;

	fr_time_delta_t		timeout;	//!< Timeout timeval.
	uint32_t		chunk;		//!< Max chunk-size (mainly for testing the encoders)
	size_t			max_body_in;	//!< Maximum size of incoming data.
} rlm_rest_section_t;

/*
 *	Structure for module configuration
 */
typedef struct {
	char const		*xlat_name;	//!< Instance name.

	char const		*connect_proxy;	//!< Send request via this proxy.

	int			http_negotiation; //!< What HTTP version to negotiate, and how to
						///< negotiate it.  One or the CURL_HTTP_VERSION_ macros.

	bool			multiplex;	//!< Whether to perform multiple requests using a single
						///< connection.

	fr_pool_t		*pool;		//!< Pointer to the connection pool.

	rlm_rest_section_t	xlat;		//!< Configuration specific to xlat.
	rlm_rest_section_t	authorize;	//!< Configuration specific to authorisation.
	rlm_rest_section_t	authenticate;	//!< Configuration specific to authentication.
	rlm_rest_section_t	accounting;	//!< Configuration specific to accounting.
	rlm_rest_section_t	post_auth;	//!< Configuration specific to Post-auth

#ifndef NDEBUG
	bool			fail_header_decode;	//!< Force header decoding to fail for debugging purposes.
	bool			fail_body_decode;	//!< Force body decoding to fail for debugging purposes.
#endif
} rlm_rest_t;

/** Thread specific rlm_rest instance data
 *
 */
typedef struct {
	rlm_rest_t const	*inst;		//!< Instance of rlm_rest.
	fr_pool_t		*pool;		//!< Thread specific connection pool.
	CURLM			*mandle;	//!< Thread specific multi handle.  Serves as the dispatch
						//!< and coralling structure for REST requests.
	fr_event_list_t		*el;		//!< This thread's event list.
	fr_event_timer_t const	*ev;		//!< Used to manage IO timers for libcurl.
	unsigned int		transfers;	//!< Keep track of how many outstanding transfers
						//!< we think there are.
} rlm_rest_thread_t;

/** Wrapper around the module thread stuct for individual xlats
 *
 */
typedef struct {
	rlm_rest_t		*inst;		//!< Instance of rlm_rest.
	rlm_rest_thread_t	*t;		//!< rlm_rest thread instance.
} rest_xlat_thread_inst_t;

/*
 *	States for stream based attribute encoders
 */
typedef enum {
	READ_STATE_INIT	= 0,
	READ_STATE_ATTR_BEGIN,
	READ_STATE_ATTR_CONT,
	READ_STATE_END,
} read_state_t;

/*
 *	States for the response parser
 */
typedef enum {
	WRITE_STATE_INIT = 0,
	WRITE_STATE_PARSE_HEADERS,
	WRITE_STATE_PARSE_CONTENT,
	WRITE_STATE_DISCARD,
} write_state_t;

/*
 *	Outbound data context (passed to CURLOPT_READFUNCTION as CURLOPT_READDATA)
 */
typedef struct {
	rlm_rest_t const	*instance;	//!< This instance of rlm_rest.
	rlm_rest_section_t const *section;	//!< Section configuration.

	REQUEST			*request;	//!< Current request.
	read_state_t		state;		//!< Encoder state

	fr_cursor_t		cursor;		//!< Cursor pointing to the start of the list to encode.

	size_t			chunk;		//!< Chunk size

	void			*encoder;	//!< Encoder specific data.
} rlm_rest_request_t;

/*
 *	Curl inbound data context (passed to CURLOPT_WRITEFUNCTION and
 *	CURLOPT_HEADERFUNCTION as CURLOPT_WRITEDATA and CURLOPT_HEADERDATA)
 */
typedef struct {
	rlm_rest_t const	*instance;	//!< This instance of rlm_rest.
	rlm_rest_section_t const *section;	//!< Section configuration.

	REQUEST			*request;	//!< Current request.
	write_state_t		state;		//!< Decoder state.

	char 			*buffer;	//!< Raw incoming HTTP data.
	size_t		 	alloc;		//!< Space allocated for buffer.
	size_t		 	used;		//!< Space used in buffer.

	int		 	code;		//!< HTTP Status Code.
	http_body_type_t	type;		//!< HTTP Content Type.
	http_body_type_t	force_to;	//!< Force decoding the body type as a particular encoding.

	void			*decoder;	//!< Decoder specific data.
} rlm_rest_response_t;

/*
 *	Curl context data
 */
typedef struct {
	struct curl_slist	*headers;	//!< Any HTTP headers which will be sent with the
						//!< request.

	char			*body;		//!< Pointer to the buffer which contains body data/
						//!< Only used when not performing chunked encoding.

	rlm_rest_request_t	request;	//!< Request context data.
	rlm_rest_response_t	response;	//!< Response context data.
} rlm_rest_curl_context_t;

/*
 *	Connection API handle
 */
typedef struct {
	CURL			*candle;	//!< Libcurl easy handle
	rlm_rest_curl_context_t	*ctx;		//!< Context, re-initialised after each request.
} rlm_rest_handle_t;

/** Stores the state of a yielded xlat
 *
 */
typedef struct {
	rlm_rest_section_t	section;	//!< Our mutated section config.
	rlm_rest_handle_t	*handle;	//!< curl easy handle servicing our request.
} rlm_rest_xlat_rctx_t;

extern fr_dict_t *dict_freeradius;

extern fr_dict_attr_t const *attr_rest_http_body;
extern fr_dict_attr_t const *attr_rest_http_header;
extern fr_dict_attr_t const *attr_rest_http_status_code;

/*
 *	Function prototype for rest_read_wrapper. Matches CURL's
 *	CURLOPT_READFUNCTION prototype.
 */
typedef size_t (*rest_read_t)(void *ptr, size_t size, size_t nmemb,
			      void *userdata);


void *mod_conn_create(TALLOC_CTX *ctx, void *instance, fr_time_delta_t timeout);

/*
 *	Request processing API
 */
int rest_request_config(rlm_rest_t const *instance, rlm_rest_thread_t *thread,
			rlm_rest_section_t const *section, REQUEST *request,
			void *handle, http_method_t method,
			http_body_type_t type, char const *uri,
			char const *username, char const *password) CC_HINT(nonnull (1,2,3,4,5,8));

int rest_response_certinfo(UNUSED rlm_rest_t const *instance, rlm_rest_section_t const *section,
			   REQUEST *request, void *handle);

int rest_response_decode(rlm_rest_t const *instance,
			UNUSED rlm_rest_section_t const *section, REQUEST *request,
			void *handle);

void rest_response_error(REQUEST *request, rlm_rest_handle_t *handle);
void rest_response_debug(REQUEST *request, rlm_rest_handle_t *handle);

void rest_request_cleanup(rlm_rest_t const *instance, void *handle);

#define rest_get_handle_code(_handle)(((rlm_rest_curl_context_t*)((rlm_rest_handle_t*)_handle)->ctx)->response.code)

#define rest_get_handle_type(_handle)(((rlm_rest_curl_context_t*)((rlm_rest_handle_t*)_handle)->ctx)->response.type)

size_t rest_get_handle_data(char const **out, rlm_rest_handle_t *handle);

/*
 *	Helper functions
 */
size_t rest_uri_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *raw, UNUSED void *arg);
ssize_t rest_uri_build(char **out, rlm_rest_t const *instance, REQUEST *request, char const *uri);
ssize_t rest_uri_host_unescape(char **out, UNUSED rlm_rest_t const *mod_inst, REQUEST *request,
			       void *handle, char const *uri);

/*
 *	Async IO helpers
 */
void rest_io_module_action(void *instance, void *thread, REQUEST *request, void *rctx, fr_state_signal_t action);
void rest_io_xlat_action(REQUEST *request, void *xlat_inst, void *xlat_thread_inst, void *rctx, fr_state_signal_t action);
int rest_io_request_enqueue(rlm_rest_thread_t *thread, REQUEST *request, void *handle);
int rest_io_init(rlm_rest_thread_t *thread, bool multiplex);

