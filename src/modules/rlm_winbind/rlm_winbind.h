#pragma once
/* @copyright 2016 The FreeRADIUS server project */

#include "config.h"
#include <wbclient.h>
#include <freeradius-devel/server/pool.h>

/*
 *      Structure for the module configuration.
 */
typedef struct {
	fr_pool_t		*wb_pool;
	fr_dict_enum_value_t		*auth_type;

	/* main config */
	tmpl_t		*wb_domain;

	/* group config */
	tmpl_t		*group_username;
	bool			group_add_domain;
} rlm_winbind_t;

typedef struct {
	fr_value_box_t	username;
	fr_value_box_t	domain;
	fr_value_box_t	password;
} winbind_auth_call_env_t;
