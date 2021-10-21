#pragma once
/* @copyright 2015 The FreeRADIUS server project */
RCSIDH(auth_wbclient_h, "$Id$")

int do_auth_wbclient(rlm_mschap_t const *inst, request_t *request,
		     uint8_t const *challenge, uint8_t const *response,
		     uint8_t nthashhash[NT_DIGEST_LENGTH]);
