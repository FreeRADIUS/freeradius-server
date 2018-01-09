#ifndef _UTIL_CURL_H_
#define _UTIL_CURL_H_

#include <curl/curl.h>

#include "buffer.h"

/**
 * Struct to hold response [meta]data.
 */
typedef struct
{
	int code;
	dynamic_buffer_t buffer;
} curl_response_context_t;

/**
 * Synchronous request/response exchange utility method.
 */
CURLcode do_curl_exchange(CURL *curl, const char *url, const char *body,
						  curl_response_context_t *response_context);

#endif // _UTIL_CURL_H_
