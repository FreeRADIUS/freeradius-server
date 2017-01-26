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
 * @copyright 2012-2014  Arran Cudbard-Bell <a.cudbard-bell@freeradius.org>
 */

RCSIDH(other_h, "$Id$")

#include <freeradius-devel/connection.h>
#include "config.h"

#define CURL_NO_OLDIES 1
#include <curl/curl.h>

#ifdef HAVE_JSON
#  if defined(HAVE_JSONMC_JSON_H)
#    include <json-c/json.h>
#  elif defined(HAVE_JSON_JSON_H)
#    include <json/json.h>
#  endif
#endif

#define REST_URI_MAX_LEN		2048
#define REST_BODY_MAX_LEN		8192
#define REST_BODY_INIT			1024
#define REST_BODY_MAX_ATTRS		256

typedef enum {
	HTTP_METHOD_UNKNOWN = 0,
	HTTP_METHOD_GET,
	HTTP_METHOD_POST,
	HTTP_METHOD_PUT,
	HTTP_METHOD_PATCH,
	HTTP_METHOD_DELETE,
	HTTP_METHOD_CUSTOM		//!< Must always come last, should not be in method table
} http_method_t;

typedef enum {
	HTTP_BODY_UNKNOWN = 0,
	HTTP_BODY_UNSUPPORTED,
	HTTP_BODY_UNAVAILABLE,
	HTTP_BODY_INVALID,
	HTTP_BODY_NONE,
	HTTP_BODY_CUSTOM_XLAT,
	HTTP_BODY_CUSTOM_LITERAL,
	HTTP_BODY_POST,
	HTTP_BODY_JSON,
	HTTP_BODY_XML,
	HTTP_BODY_YAML,
	HTTP_BODY_HTML,
	HTTP_BODY_PLAIN,
	HTTP_BODY_NUM_ENTRIES
} http_body_type_t;

typedef enum {
	HTTP_AUTH_UNKNOWN = 0,
	HTTP_AUTH_NONE,
	HTTP_AUTH_TLS_SRP,
	HTTP_AUTH_BASIC,
	HTTP_AUTH_DIGEST,
	HTTP_AUTH_DIGEST_IE,
	HTTP_AUTH_GSSNEGOTIATE,
	HTTP_AUTH_NTLM,
	HTTP_AUTH_NTLM_WB,
	HTTP_AUTH_ANY,
	HTTP_AUTH_ANY_SAFE,
	HTTP_AUTH_NUM_ENTRIES
} http_auth_type_t;

/*
 *	Must be updated (in rest.c) if additional values are added to
 *	http_body_type_t
 */
extern const http_body_type_t http_body_type_supported[HTTP_BODY_NUM_ENTRIES];

extern const unsigned long http_curl_auth[HTTP_AUTH_NUM_ENTRIES];

extern const FR_NAME_NUMBER http_auth_table[];

extern const FR_NAME_NUMBER http_method_table[];

extern const FR_NAME_NUMBER http_body_type_table[];

extern const FR_NAME_NUMBER http_content_type_table[];

/*
 *	Structure for section configuration
 */
typedef struct rlm_rest_section_t {
	char const		*name;		//!< Section name.
	char const		*uri;		//!< URI to send HTTP request to.

	char const		*method_str;	//!< The string version of the HTTP method.
	http_method_t		method;		//!< What HTTP method should be used, GET, POST etc...

	char const		*body_str;	//!< The string version of the encoding/content type.
	http_body_type_t	body;		//!< What encoding type should be used.

	char const		*force_to_str;	//!< Force decoding with this decoder.
	http_body_type_t	force_to;	//!< Override the Content-Type header in the response
						//!< to force decoding as a particular type.

	char const		*data;		//!< Custom body data (optional).

	char const		*auth_str;	//!< The string version of the Auth-Type.
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

	struct timeval		timeout_tv;	//!< Timeout timeval.
	long			timeout;	//!< Timeout in ms.
	uint32_t		chunk;		//!< Max chunk-size (mainly for testing the encoders)
} rlm_rest_section_t;

/*
 *	Structure for module configuration
 */
typedef struct rlm_rest_t {
	char const		*xlat_name;	//!< Instance name.

	char const		*connect_uri;	//!< URI we attempt to connect to, to pre-establish
						//!< TCP connections.

	struct timeval		connect_timeout_tv;	//!< Connection timeout timeval.
	long			connect_timeout;	//!< Connection timeout ms.

	fr_connection_pool_t	*pool;		//!< Pointer to the connection pool.

	rlm_rest_section_t	authorize;	//!< Configuration specific to authorisation.
	rlm_rest_section_t	authenticate;	//!< Configuration specific to authentication.
	rlm_rest_section_t	accounting;	//!< Configuration specific to accounting.
	rlm_rest_section_t	checksimul;	//!< Configuration specific to simultaneous session
						//!< checking.
	rlm_rest_section_t	post_auth;	//!< Configuration specific to Post-auth
#ifdef WITH_COA
	rlm_rest_section_t	recv_coa;		//!< Configuration specific to recv-coa
#endif
} rlm_rest_t;

/*
 *	States for stream based attribute encoders
 */
typedef enum {
	READ_STATE_INIT	= 0,
	READ_STATE_ATTR_BEGIN,
	READ_STATE_ATTR_CONT,
	READ_STATE_ATTR_END,
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
typedef struct rlm_rest_request_t {
	rlm_rest_t		*instance;	//!< This instance of rlm_rest.
	REQUEST			*request;	//!< Current request.
	read_state_t		state;		//!< Encoder state

	vp_cursor_t		cursor;		//!< Cursor pointing to the start of the list to encode.

	size_t			chunk;		//!< Chunk size

	void			*encoder;	//!< Encoder specific data.
} rlm_rest_request_t;

/*
 *	Curl inbound data context (passed to CURLOPT_WRITEFUNCTION and
 *	CURLOPT_HEADERFUNCTION as CURLOPT_WRITEDATA and CURLOPT_HEADERDATA)
 */
typedef struct rlm_rest_response_t {
	rlm_rest_t		*instance;	//!< This instance of rlm_rest.
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
typedef struct rlm_rest_curl_context_t {
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
typedef struct rlm_rest_handle_t {
	void			*handle;	//!< Real Handle.
	rlm_rest_curl_context_t	*ctx;		//!< Context.
} rlm_rest_handle_t;

/*
 *	Function prototype for rest_read_wrapper. Matches CURL's
 *	CURLOPT_READFUNCTION prototype.
 */
typedef size_t (*rest_read_t)(void *ptr, size_t size, size_t nmemb,
			      void *userdata);

/*
 *	Connection API callbacks
 */
int rest_init(rlm_rest_t *instance);

void rest_cleanup(void);

void *mod_conn_create(TALLOC_CTX *ctx, void *instance);

int mod_conn_alive(void *instance, void *handle);

/*
 *	Request processing API
 */
int rest_request_config(rlm_rest_t *instance,
			rlm_rest_section_t *section, REQUEST *request,
			void *handle, http_method_t method,
			http_body_type_t type, char const *uri,
			char const *username, char const *password) CC_HINT(nonnull (1,2,3,4,7));

int rest_request_perform(rlm_rest_t *instance,
			 rlm_rest_section_t *section, REQUEST *request,
			 void *handle);

int rest_response_decode(rlm_rest_t *instance,
			UNUSED rlm_rest_section_t *section, REQUEST *request,
			void *handle);

void rest_response_error(REQUEST *request, rlm_rest_handle_t *handle);

void rest_request_cleanup(rlm_rest_t *instance, rlm_rest_section_t *section,
			  void *handle);

#define rest_get_handle_code(handle)(((rlm_rest_curl_context_t*)((rlm_rest_handle_t*)handle)->ctx)->response.code)

#define rest_get_handle_type(handle)(((rlm_rest_curl_context_t*)((rlm_rest_handle_t*)handle)->ctx)->response.type)

size_t rest_get_handle_data(char const **out, rlm_rest_handle_t *handle);

/*
 *	Helper functions
 */
size_t rest_uri_escape(UNUSED REQUEST *request, char *out, size_t outlen, char const *raw, UNUSED void *arg);
ssize_t rest_uri_build(char **out, rlm_rest_t *instance, REQUEST *request, char const *uri);
ssize_t rest_uri_host_unescape(char **out, UNUSED rlm_rest_t *instance, REQUEST *request,
			       void *handle, char const *uri);
