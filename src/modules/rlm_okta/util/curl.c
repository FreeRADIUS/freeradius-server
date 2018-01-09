#include "curl.h"

static const long CONNECT_TIMEOUT_SECS		= 1;
static const long REQUEST_TIMEOUT_SECS		= 3;

static const char *USER_AGENT				= "FreeRADIUS Okta Client/1.0";
static const char *CONTENT_TYPE_HEADER		= "Content-Type: application/json";

/**
 * Write callback for the CURL response.
 * A dynamic_buffer_t instance is configured to be passed as userdata.
 */
static size_t receive_bytes(void *response_data, size_t size, size_t nmemb, void *userdata)
{
	size_t total_bytes_to_write = size * nmemb;
	dynamic_buffer_t *response_buffer = userdata;
	dynamic_buffer_write(response_buffer, response_data, total_bytes_to_write);
	return total_bytes_to_write;
}

/**
 * Synchronous request/response exchange utility method.
 */
CURLcode do_curl_exchange(CURL *curl, const char *url, const char *body,
						  curl_response_context_t *response_context)
{
	CURLcode ret;
	struct curl_slist *headers = NULL;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_SECS);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECS);

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_bytes);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&(response_context->buffer));

	headers = curl_slist_append(headers, CONTENT_TYPE_HEADER);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	ret = curl_easy_perform(curl);

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &(response_context->code));

	curl_slist_free_all(headers);
	return ret;
}
