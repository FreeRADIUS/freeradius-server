/* Copyright 2015 The FreeRADIUS server project */

#ifndef _AUTH_WBCLIENT_H
#define _AUTH_WBCLIENT_H

RCSIDH(auth_wbclient_h, "$Id$")

#include <wbclient.h>

/* Samba does not export this constant yet */
#ifndef WBC_MSV1_0_ALLOW_MSVCHAPV2
#define WBC_MSV1_0_ALLOW_MSVCHAPV2 0x00010000
#endif

int do_auth_wbclient(rlm_mschap_t *inst, REQUEST *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH]);

#endif /*_AUTH_WBCLIENT_H*/
