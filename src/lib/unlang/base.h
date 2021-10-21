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
 * @file unlang/base.h
 * @brief Public interface to the unlang interpreter
 *
 * @copyright 2016-2019 The FreeRADIUS server project
 */
#include <freeradius-devel/unlang/call.h>
#include <freeradius-devel/unlang/compile.h>
#include <freeradius-devel/unlang/function.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/subrequest.h>

#ifdef __cplusplus
extern "C" {
#endif

bool			unlang_section(CONF_SECTION *cs);

int			unlang_init_global(void);

void			unlang_free_global(void);

int			unlang_thread_instantiate(TALLOC_CTX *ctx) CC_HINT(nonnull);

#ifdef WITH_PERF
void			unlang_perf_virtual_server(fr_log_t *log, char const *name);
#endif

#ifdef __cplusplus
}
#endif
