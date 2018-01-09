#ifndef _OKTA_H_
#define _OKTA_H_

#include <stdbool.h>
#include <curl/curl.h>

/**
 * Performs the Okta first factor auth.
 * Sends the username and password to the first authorization endpoint,
 * returning a state token and factor ID for use in the subsequent
 * verification step.
 */
bool authorize_user(CURL *curl, const char *username, const char *password,
					char **state_token, char **factor_id);

/**
 * Performs the Okta second factor auth.
 * Utilizing the state token and factor ID from the first step, this function
 * verfies the second factor TOTP code contained at the end of password.
 */
bool verify_challenge_response(CURL *curl, const char *password,
							   const char *state_token, const char *factor_id);

#endif // _OKTA_H_
