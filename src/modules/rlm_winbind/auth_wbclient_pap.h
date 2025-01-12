#pragma once
/* @copyright 2016 The FreeRADIUS server project */


RCSIDH(auth_wbclient_h, "$Id$")

int do_auth_wbclient_pap(request_t *request, winbind_auth_call_env_t *env, rlm_winbind_thread_t *t);
