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
 * @file lib/server/trigger.h
 * @brief Execute scripts when a server event occurs.
 *
 * @copyright 2015 The FreeRADIUS server project
 */
RCSIDH(trigger_h, "$Id$")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/module.h>
#include <freeradius-devel/server/request.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/util/pair.h>
#include <freeradius-devel/util/talloc.h>

/** Common values used by modules when building trigger args
 *
 */
typedef struct {
	char const	*module;	//!< Module name
	char const	*name;		//!< Instance name
	char const	*server;	//!< Server name / IP
	uint16_t	port;		//!< Server port
} module_trigger_args_t;

int		trigger_init(CONF_SECTION const *cs);

int		trigger(unlang_interpret_t *intp, CONF_SECTION const *cs, CONF_PAIR **trigger_cp,
			char const *name, bool rate_limit, fr_pair_list_t *args) CC_HINT(nonnull(4));

bool		trigger_enabled(void);

void		trigger_args_afrom_server(TALLOC_CTX *ctx, fr_pair_list_t *list, char const *server, uint16_t port);

int		module_trigger_args_build(TALLOC_CTX *ctx, fr_pair_list_t *list, CONF_SECTION *cs,
					  module_trigger_args_t *args) CC_HINT(nonnull(1,2,4));

typedef int (*fr_trigger_worker_t)(request_t *request, module_method_t process, void *ctx);

#ifdef __cplusplus
}
#endif
