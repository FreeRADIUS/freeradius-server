/* Copyright 2015 The FreeRADIUS server project */

#ifndef _AUTH_WBCLIENT_H
#define _AUTH_WBCLIENT_H

RCSIDH(auth_wbclient_h, "$Id$")

int do_auth_wbclient(rlm_mschap_t *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH]);

#endif /*_AUTH_WBCLIENT_H*/
