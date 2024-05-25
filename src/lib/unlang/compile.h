#pragma once
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/**
 * $Id$
 *
 * @file unlang/compile.h
 * @brief Declarations for the unlang interpreter.
 *
 * @copyright 2019 The FreeRADIUS server project
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/server/cf_util.h>
#include <freeradius-devel/server/tmpl.h>
#include <freeradius-devel/server/virtual_servers.h>
#include <freeradius-devel/util/retry.h>
#include <freeradius-devel/unlang/mod_action.h>

void		unlang_compile_init(TALLOC_CTX *ctx);

int 		unlang_compile(virtual_server_t const *vs,
			       CONF_SECTION *cs, unlang_mod_actions_t const *actions, tmpl_rules_t const *rules, void **instruction);

bool		unlang_compile_is_keyword(const char *name);

bool		unlang_compile_actions(unlang_mod_actions_t *actions, CONF_SECTION *parent, bool module_retry);

#ifdef __cplusplus
}
#endif
