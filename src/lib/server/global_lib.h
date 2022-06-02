#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/**
 * $Id$
 *
 * @file lib/server/global_lib.h
 * @brief API for initialising and freeing libraries.
 *
 * @copyright 2022 The FreeRADIUS server project
 */
RCSIDH(lib_h, "$Id$")

#include <freeradius-devel/server/cf_parse.h>
#include <freeradius-devel/util/dl.h>

typedef int (*lib_init_t)(void);

typedef void (*lib_free_t)(void);

/** Structure to define how to initialise libraries with global configuration
 *
 */
typedef struct {
	char const 		*name;			//!<  Name of library and section within global config
	CONF_PARSER const	*config;		//!<  Config parser for this library's global options
	void			*inst;			//!<  Module data to parse global config into
	lib_init_t		init;			//!<  Callback to initialise library
	lib_free_t		free;			//!<  Callback to free library
} global_lib_autoinst_t;

extern const global_lib_autoinst_t global_lib_terminator;

/*
 *	To be used as terminator in an array of global_lib_autoinst_t
 */
#define GLOBAL_LIB_TERMINATOR &global_lib_terminator

int global_lib_auto_instantiate(dl_t const *module, void *symbol, void *user_ctx);

void global_lib_autofree(dl_t const *module, void *symbol, void *user_ctx);

int global_lib_init(void);

int global_lib_instantiate(void);
