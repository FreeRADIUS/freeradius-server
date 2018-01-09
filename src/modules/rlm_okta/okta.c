#include <freeradius-devel/radiusd.h>

#include <json/json.h>

#include "okta.h"
#include "util/curl.h"

#define BASE_URL			 "https://cadre.okta.com"
#define AUTHORIZE_URL_FORMAT "/api/v1/authn"
#define VERIFY_URL_FORMAT	 "/api/v1/authn/factors/%s/verify"

#define AUTHORIZE_BODY_FORMAT "{ \"username\": \"%s\",	 \"password\": \"%s\" }"
#define VERIFY_BODY_FORMAT	  "{ \"stateToken\": \"%s\", \"passCode\": \"%s\" }"

static const int	HTTP_OK			= 200;
static const size_t TOTP_LENGTH		= 6;
static const size_t MAX_URL_LENGTH	= 512;
static const size_t MAX_BODY_LENGTH = 2048;

/**
 * Retrieves stateToken and _embedded->factors[0]->id from the response JSON.
 * Caller now owns the memory pointed to by state_token_out and factor_id_out.
 */
static bool grab_verify_parameters(void *response_buffer,
								   char **state_token_out, char **factor_id_out)
{
	json_object *json_response = NULL, *state_token = NULL, *embedded = NULL,
				*factors = NULL, *first_factor = NULL, *factor_id = NULL;

	json_response = json_tokener_parse(response_buffer);
	if (json_response == NULL)
	{
		ERROR("Malformed JSON response");
		return false;
	}

	if (json_object_object_get_ex(json_response, "stateToken", &state_token) &&
		json_object_object_get_ex(json_response, "_embedded", &embedded) &&
		json_object_object_get_ex(embedded, "factors", &factors))
	{
		first_factor = json_object_array_get_idx(factors, 0);
		json_object_object_get_ex(first_factor, "id", &factor_id);
	}

	if (state_token == NULL || factor_id == NULL)
	{
		json_object_put(json_response);
		return false;
	}

	/**
	 * Allocate new buffers for these strings since json-c owns them
	 * and they will dangle after dropping the ref at the end of the func.
	 */
	*state_token_out = strdup(json_object_get_string(state_token));
	*factor_id_out	 = strdup(json_object_get_string(factor_id));
	json_object_put(json_response);
	return true;
}

/**
 * Performs the Okta first factor auth.
 * Sends the username and password to the first authorization endpoint,
 * returning a state token and factor ID for use in the subsequent
 * verification step.
 */
bool authorize_user(CURL *curl, const char *username, const char *password,
					char **state_token, char **factor_id)
{
	CURLcode ret;
	bool authorized = false;
	char url[MAX_URL_LENGTH];
	char request_body[MAX_BODY_LENGTH];
	curl_response_context_t response_context;

	snprintf(url, MAX_URL_LENGTH, "%s/%s", BASE_URL, AUTHORIZE_URL_FORMAT);
	snprintf(request_body, MAX_BODY_LENGTH, AUTHORIZE_BODY_FORMAT, username, password);

	dynamic_buffer_init(&(response_context.buffer));

	ret = do_curl_exchange(curl, url, request_body, &response_context);
	if (ret != CURLE_OK)
	{
		ERROR("Authorize request failed (%d): %s", ret, curl_easy_strerror(ret));
	}

	if (response_context.code == HTTP_OK)
	{
		DEBUG("Okta authorize succeeded");
		authorized = grab_verify_parameters(response_context.buffer.buffer, state_token, factor_id);
	} else
	{
		ERROR("Okta responded with non-200 authorize response (%d)", response_context.code);
	}

	dynamic_buffer_destroy(&(response_context.buffer));
	return authorized;
}

/**
 * Performs the Okta second factor auth.
 * Utilizing the state token and factor ID from the first step, this function
 * verfies the second factor TOTP code contained at the end of password.
 */
bool verify_challenge_response(CURL *curl, const char *password,
							   const char *state_token, const char *factor_id)
{
	CURLcode ret;
	bool verified = false;
	const char *passcode;
	char url[MAX_URL_LENGTH], path[MAX_URL_LENGTH];
	char request_body[MAX_BODY_LENGTH];
	curl_response_context_t response_context;

	/**
	 * The XAuth protocol allows for multiple authentication rounds, with each
	 * one appending the user's input to the User-Password field. Our TOTP
	 * code is at the very end.
	 */
	passcode = password + strlen(password) - TOTP_LENGTH;
	snprintf(request_body, MAX_BODY_LENGTH, VERIFY_BODY_FORMAT, state_token, passcode);

	snprintf(path, MAX_URL_LENGTH, VERIFY_URL_FORMAT, factor_id);
	snprintf(url, MAX_URL_LENGTH, "%s/%s", BASE_URL, path);

	dynamic_buffer_init(&(response_context.buffer));

	ret = do_curl_exchange(curl, url, request_body, &response_context);
	if (ret != CURLE_OK)
	{
		ERROR("Verify request failed (%d): %s", ret, curl_easy_strerror(ret));
	}

	if (response_context.code == HTTP_OK)
	{
		DEBUG("Okta verify succeeded");
		verified = true;
	} else if (ret == CURLE_OK)
	{
		ERROR("Okta responded with non-200 verify response: %d", response_context.code);
	}

	dynamic_buffer_destroy(&(response_context.buffer));
	return verified;
}
