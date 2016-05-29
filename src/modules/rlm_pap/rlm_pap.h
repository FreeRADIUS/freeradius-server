/* Copyright 2016 The FreeRADIUS server project */

#ifndef _RLM_PAP_H
#define _RLM_PAP_H

#include "config.h"

#ifdef WITH_AUTH_WINBIND
#  include <wbclient.h>
#  include <freeradius-devel/connection.h>
#endif

/*
 *      Structure for the module configuration.
 */
typedef struct rlm_pap_t {
	char const		*name;
	int			auth_type;
	bool			normify;
	vp_tmpl_t		*wb_username;
	vp_tmpl_t		*wb_domain;
#ifdef WITH_AUTH_WINBIND
	fr_connection_pool_t    *wb_pool;
#endif
} rlm_pap_t;

#endif

