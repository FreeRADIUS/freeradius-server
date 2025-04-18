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
 * @file unlang/interpret_priv.h
 * @brief Private declarations for the unlang interpreter.
 *
 * @copyright 2021 The FreeRADIUS server project
 */

#include <freeradius-devel/util/event.h>
#include <freeradius-devel/unlang/interpret.h>
#include "interpret_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct unlang_interpret_s {
	fr_event_list_t		*el;
	unlang_request_func_t	funcs;
	void			*uctx;
};

static inline void interpret_child_init(request_t *request)
{
	unlang_interpret_t *intp = unlang_interpret_get(request);

	intp->funcs.init_internal(request, intp->uctx);
}

#ifdef __cplusplus
}
#endif
