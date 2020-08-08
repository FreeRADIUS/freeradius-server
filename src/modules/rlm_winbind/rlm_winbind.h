#pragma once
/* @copyright 2016 The FreeRADIUS server project */

#include "config.h"
#include <wbclient.h>
#include <freeradius-devel/server/pool.h>

/*
 *      Structure for the module configuration.
 */
typedef struct {
	char const		*name;
	fr_pool_t		*wb_pool;
	fr_dict_enum_t		*auth_type;

	/* main config */
	tmpl_t		*wb_username;
	tmpl_t		*wb_domain;

	/* group config */
	tmpl_t		*group_username;
	bool			group_add_domain;
	char const		*group_attribute;
} rlm_winbind_t;
