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
#include <freeradius-devel/server/components.h>
#include <freeradius-devel/server/tmpl.h>

typedef struct unlang_s unlang_t;

typedef int const unlang_action_table_t[RLM_MODULE_NUMCODES];

typedef struct {
	rlm_components_t	component;
	char const		*section_name1;
	char const		*section_name2;
	unlang_action_table_t	*actions;
	vp_tmpl_rules_t const	*rules;
} unlang_compile_ctx_t;

typedef unlang_t *(*unlang_op_compile_t)(unlang_t *parent, unlang_compile_ctx_t *unlang_ctx, CONF_SECTION *cs);

int		unlang_compile(CONF_SECTION *cs, rlm_components_t component, vp_tmpl_rules_t const *rules);

bool		unlang_compile_is_keyword(const char *name);

#ifdef __cplusplus
}
#endif
