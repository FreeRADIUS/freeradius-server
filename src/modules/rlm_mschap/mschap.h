/* Copyright 2006 The FreeRADIUS server project */

#ifndef _MSCHAP_H
#define _MSCHAP_H

#include <freeradius-devel/ident.h>
RCSIDH(mschap_h, "$Id$")

void mschap_ntpwdhash (uint8_t *szHash, const char *szPassword);
void mschap_challenge_hash( const uint8_t *peer_challenge,
			    const uint8_t *auth_challenge,
			    const char *user_name, uint8_t *challenge );

void mschap_auth_response(const char *username,
			  const uint8_t *nt_hash_hash,
			  uint8_t *ntresponse,
			  uint8_t *peer_challenge, uint8_t *auth_challenge,
			  char *response);


#endif /*_MSCHAP_H*/
