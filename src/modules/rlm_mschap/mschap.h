#pragma once

/* @copyright 2006 The FreeRADIUS server project */

RCSIDH(mschap_h, "$Id$")

#define NT_DIGEST_LENGTH 16
#define LM_DIGEST_LENGTH 16

int mschap_nt_password_hash(uint8_t *out, char const *password);
void mschap_challenge_hash(uint8_t const *peer_challenge,
			    uint8_t const *auth_challenge,
			    char const *user_name, uint8_t *challenge );

void mschap_auth_response(char const *username,
			  uint8_t const *nt_hash_hash,
			  uint8_t const *ntresponse,
			  uint8_t const *peer_challenge, uint8_t const *auth_challenge,
			  char *response);
void mschap_add_reply(REQUEST *request, unsigned char ident,
		      fr_dict_attr_t const *da, char const *value, size_t len);
