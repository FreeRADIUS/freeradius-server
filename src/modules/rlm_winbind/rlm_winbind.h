/* Copyright 2016 The FreeRADIUS server project */

#ifndef _RLM_WBCLIENT_H
#define _RLM_WBCLIENT_H

#include "config.h"
#include <wbclient.h>
#include <freeradius-devel/connection.h>

/*
 *      Structure for the module configuration.
 */
typedef struct rlm_winbind_t {
	vp_tmpl_t		*wb_username;
	vp_tmpl_t		*wb_domain;
	fr_connection_pool_t    *wb_pool;
} rlm_winbind_t;

#endif

