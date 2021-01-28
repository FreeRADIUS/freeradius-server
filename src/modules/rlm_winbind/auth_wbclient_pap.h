#pragma once
/* @copyright 2016 The FreeRADIUS server project */


RCSIDH(auth_wbclient_h, "$Id$")

int do_auth_wbclient_pap(rlm_winbind_t const *inst, request_t *request, fr_pair_t *password);
