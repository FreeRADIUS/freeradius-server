#pragma once
/* @copyright 2016 The FreeRADIUS server project */

#include "config.h"
#include <wbclient.h>
#include <freeradius-devel/util/slab.h>

/*
 *      Structure for the module configuration.
 */
typedef struct {
	fr_dict_enum_value_t	*auth_type;

	/* group config */
	bool			group_add_domain;
	fr_slab_config_t	reuse;
} rlm_winbind_t;

typedef struct {
	struct wbcContext	*ctx;
} winbind_ctx_t;

FR_SLAB_TYPES(winbind, winbind_ctx_t)
FR_SLAB_FUNCS(winbind, winbind_ctx_t)

typedef struct {
	rlm_winbind_t const	*inst;		//!< Instance of rlm_winbind
	winbind_slab_list_t	*slab;		//!< Slab list for winbind handles.
} rlm_winbind_thread_t;

typedef struct {
	fr_value_box_t	username;
	fr_value_box_t	domain;
	fr_value_box_t	password;
} winbind_auth_call_env_t;
