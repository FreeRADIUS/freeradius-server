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
#include <freeradius-devel/unlang/compile.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>
#include <freeradius-devel/unlang/subrequest.h>

#ifdef __cplusplus
extern "C" {
#endif

bool		unlang_section(CONF_SECTION *cs);

void		unlang_register(int type, unlang_op_t *op);

int		unlang_init(void);

void		unlang_free(void);

#ifdef __cplusplus
}
#endif
